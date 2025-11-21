package impl

import (
	"errors"
	"math/rand"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// Comments were AI generated.

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	// Initialize the node with its configuration.
	n := &node{
		conf:    conf,
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
		routing: map[string]string{},
	}
	// Configure logger: disabled if GLOG=="no", else enabled at info level to console
	level := zerolog.InfoLevel
	if os.Getenv("GLOG") == "no" {
		level = zerolog.Disabled
	}
	writer := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	n.log = zerolog.New(writer).Level(level).With().Timestamp().Logger().
		With().Str("role", "peer").Logger()
	addr := ""
	if conf.Socket != nil {
		addr = conf.Socket.GetAddress()
	}
	if addr != "" {
		n.routing[addr] = addr // self-entry
	}

	// initialize internal maps
	n.lastRecv = make(map[string]uint)
	n.rumorStore = make(map[string]map[uint]transport.Message)
	n.ackWaiter = make(map[string]*ackWait)

	if conf.MessageRegistry != nil {
		conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, n.execChatMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, n.execRumorsMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, n.execAckMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, n.execStatusMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, n.execPrivateMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, n.execEmptyMessage)
	}

	return n
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	peer.Peer
	// You probably want to keep the peer.Configuration on this struct:
	conf peer.Configuration

	// zerolog logger, configured via GLOG env var
	log zerolog.Logger

	// goroutine management
	stopCh  chan struct{}  // closed to request the listener to stop
	stopped chan struct{}  // closed when the listener goroutine exits
	wg      sync.WaitGroup // wait for background goroutines
	startMu sync.Mutex     // protects started flag
	started bool

	//  routing table + its lock. Only self entry needed for Start/Stop.
	routingMu sync.RWMutex
	routing   map[string]string // origin -> next hop (relay). self maps to self

	// sequence number for rumors, protected by sequenceMu
	sequenceMu sync.Mutex
	sequence   uint

	// last received sequence per origin
	recvMu   sync.RWMutex
	lastRecv map[string]uint

	// store rumors content per origin and sequence for catch-up
	storeMu    sync.RWMutex
	rumorStore map[string]map[uint]transport.Message

	// ack waiters by PacketID
	ackMu     sync.Mutex
	ackWaiter map[string]*ackWait
}

// ackWait tracks pending acks for a sent rumor
type ackWait struct {
	rumorMsg transport.Message
	tried    map[string]struct{}
	stopCh   chan struct{}
}

// Start implements peer.Service
func (n *node) Start() error {
	// Ensure calling Start multiple times does nothing after first. With basic lock + flag.
	n.startMu.Lock()
	if n.started {
		n.startMu.Unlock()
		return nil
	}
	n.started = true
	n.startMu.Unlock()

	// Launch the listening loop in a background goroutine so Start returns quickly.
	n.wg.Add(1)
	go n.listenLoop()

	// Start anti-entropy loop if configured
	if n.conf.AntiEntropyInterval > 0 {
		n.wg.Add(1)
		go n.runAntiEntropy()
	}

	// Start heartbeat loop if configured
	if n.conf.HeartbeatInterval > 0 {
		n.wg.Add(1)
		go n.runHeartbeat()

		// Send an initial heartbeat rumor at startup
		if n.conf.MessageRegistry != nil {
			empty := types.EmptyMessage{}
			if msg, err := n.conf.MessageRegistry.MarshalMessage(&empty); err == nil {
				_ = n.Broadcast(msg)
			}
		}
	}

	return nil
}

// listenLoop receives packets from the socket and dispatches them.
func (n *node) listenLoop() {
	defer n.wg.Done()
	defer close(n.stopped)

	for {
		select {
		case <-n.stopCh:
			return
		default:
		}

		if n.conf.Socket == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		pkt, err := n.conf.Socket.Recv(1000 * time.Millisecond)
		if errors.Is(err, transport.TimeoutError(0)) {
			continue
		}
		if err != nil {
			continue
		}

		n.handlePacket(pkt)
	}
}

// handlePacket processes a single received packet.
func (n *node) handlePacket(pkt transport.Packet) {
	if pkt.Header == nil {
		return
	}

	myAddr := n.conf.Socket.GetAddress()
	if pkt.Header.Destination == "" || pkt.Header.Destination == myAddr {
		if n.conf.MessageRegistry != nil {
			_ = n.conf.MessageRegistry.ProcessPacket(pkt)
		}
		return
	}

	// relay
	n.routingMu.RLock()
	nextHop, ok := n.routing[pkt.Header.Destination]
	n.routingMu.RUnlock()
	if !ok {
		return
	}

	pkt.Header.RelayedBy = myAddr
	_ = n.conf.Socket.Send(nextHop, pkt, 2*time.Second)
}

// Stop implements peer.Service
func (n *node) Stop() error {
	// Signal the listener to stop exactly once.
	select {
	case <-n.stopCh: // already closed
	default:
		close(n.stopCh)
	}

	// Wait for background goroutines.
	n.wg.Wait()
	return nil
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	if n.conf.Socket == nil {
		return errors.New("socket not initialized")
	}

	n.routingMu.RLock()
	nextHop, ok := n.routing[dest]
	n.routingMu.RUnlock()
	if !ok {
		return errors.New("destination not in routing table")
	}

	myAddr := n.conf.Socket.GetAddress()
	header := transport.NewHeader(myAddr, myAddr, dest)
	pkt := transport.Packet{Header: &header, Msg: &msg}
	return n.conf.Socket.Send(nextHop, pkt, 2*time.Second)
}

func (n *node) Broadcast(msg transport.Message) error {
	if n.conf.Socket == nil {
		return errors.New("socket not initialized")
	}
	myAddr := n.conf.Socket.GetAddress()

	// Get and increment sequence number, store self rumor content
	n.sequenceMu.Lock()
	n.sequence++
	seq := n.sequence
	n.sequenceMu.Unlock()

	// Create a rumor that embeds the provided message
	rumor := types.Rumor{
		Origin:   myAddr,
		Sequence: seq,
		Msg:      &msg,
	}

	// persist our own rumor for catch-up
	n.storeMu.Lock()
	if n.rumorStore == nil {
		n.rumorStore = make(map[string]map[uint]transport.Message)
	}
	if _, ok := n.rumorStore[myAddr]; !ok {
		n.rumorStore[myAddr] = make(map[uint]transport.Message)
	}
	n.rumorStore[myAddr][seq] = msg
	n.storeMu.Unlock()

	// Create RumorsMessage with the single rumor
	rumorsMsg := types.RumorsMessage{Rumors: []types.Rumor{rumor}}

	// Convert to transport.Message
	rumorTransportMsg, err := n.conf.MessageRegistry.MarshalMessage(&rumorsMsg)
	if err != nil {
		return err
	}

	// Process locally the rumor message (which will execute embedded message)
	localHeader := transport.NewHeader(myAddr, myAddr, myAddr)
	localPkt := transport.Packet{Header: &localHeader, Msg: &rumorTransportMsg}
	_ = n.conf.MessageRegistry.ProcessPacket(localPkt)

	// pick one random neighbor
	neighbor, ok := n.pickRandomNeighbor(nil)
	if !ok {
		return nil
	}

	// send rumor to the selected neighbor and possibly wait for ack
	pktHeader := transport.NewHeader(myAddr, myAddr, neighbor)
	pkt := transport.Packet{Header: &pktHeader, Msg: &rumorTransportMsg}

	// register ack waiter if timeout > 0
	if n.conf.AckTimeout > 0 {
		n.ackMu.Lock()
		if n.ackWaiter == nil {
			n.ackWaiter = make(map[string]*ackWait)
		}
		w := &ackWait{rumorMsg: rumorTransportMsg, tried: map[string]struct{}{neighbor: {}}, stopCh: make(chan struct{})}
		n.ackWaiter[pktHeader.PacketID] = w
		n.ackMu.Unlock()

		go n.waitAck(pktHeader.PacketID)
	}

	return n.conf.Socket.Send(neighbor, pkt, 2*time.Second)

}

// pickRandomNeighbor returns a random neighbor (direct connection) excluding provided addresses.
// The bool indicates whether a neighbor was found.
func (n *node) pickRandomNeighbor(exclude map[string]struct{}) (string, bool) {
	n.routingMu.RLock()
	defer n.routingMu.RUnlock()

	myAddr := ""
	if n.conf.Socket != nil {
		myAddr = n.conf.Socket.GetAddress()
	}

	candidates := make([]string, 0)
	for origin, relay := range n.routing {
		if origin == myAddr {
			continue
		}
		// neighbor if relay == origin
		if relay != origin {
			continue
		}
		if exclude != nil {
			if _, found := exclude[origin]; found {
				continue
			}
		}
		candidates = append(candidates, origin)
	}

	if len(candidates) == 0 {
		return "", false
	}

	idx := rand.Intn(len(candidates))
	return candidates[idx], true
}

// runAntiEntropy periodically sends a StatusMessage to a random neighbor.
func (n *node) runAntiEntropy() {
	defer n.wg.Done()
	ticker := time.NewTicker(n.conf.AntiEntropyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			neighbor, ok := n.pickRandomNeighbor(nil)
			if !ok {
				continue
			}
			status := n.buildStatus()
			msg, err := n.conf.MessageRegistry.MarshalMessage(&status)
			if err != nil {
				continue
			}
			myAddr := n.conf.Socket.GetAddress()
			header := transport.NewHeader(myAddr, myAddr, neighbor)
			pkt := transport.Packet{Header: &header, Msg: &msg}
			_ = n.conf.Socket.Send(neighbor, pkt, 2*time.Second)
		}
	}
}

// runHeartbeat periodically sends an EmptyMessage embedded in a rumor.
func (n *node) runHeartbeat() {
	defer n.wg.Done()
	ticker := time.NewTicker(n.conf.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			empty := types.EmptyMessage{}
			msg, err := n.conf.MessageRegistry.MarshalMessage(&empty)
			if err != nil {
				continue
			}
			// Reuse the Broadcast path to do local processing and ack wait
			_ = n.Broadcast(msg)
		}
	}
}

// buildStatus builds the local status message including self last sent seq.
func (n *node) buildStatus() types.StatusMessage {
	status := make(types.StatusMessage)

	n.recvMu.RLock()
	for origin, seq := range n.lastRecv {
		status[origin] = seq
	}
	n.recvMu.RUnlock()

	// add self entry only if we have sent at least one rumor
	myAddr := ""
	if n.conf.Socket != nil {
		myAddr = n.conf.Socket.GetAddress()
	}
	n.sequenceMu.Lock()
	if n.sequence > 0 {
		status[myAddr] = n.sequence
	}
	n.sequenceMu.Unlock()
	return status
}

// waitAck waits for an ack for a given packet id and if timeout occurs, forwards to another neighbor.
func (n *node) waitAck(packetID string) {
	timeout := n.conf.AckTimeout
	if timeout <= 0 {
		return
	}

	n.ackMu.Lock()
	w, ok := n.ackWaiter[packetID]
	n.ackMu.Unlock()
	if !ok {
		return
	}

	select {
	case <-w.stopCh:
		return
	case <-time.After(timeout):
		// pick a new neighbor different from tried ones
		neighbor, ok := n.pickRandomNeighbor(w.tried)
		if !ok {
			// nothing to do, cleanup
			n.ackMu.Lock()
			delete(n.ackWaiter, packetID)
			n.ackMu.Unlock()
			return
		}
		myAddr := n.conf.Socket.GetAddress()
		header := transport.NewHeader(myAddr, myAddr, neighbor)
		// reuse same packet id for correlation
		header.PacketID = packetID
		pkt := transport.Packet{Header: &header, Msg: &w.rumorMsg}
		_ = n.conf.Socket.Send(neighbor, pkt, 2*time.Second)
		// cleanup waiter after one retry
		n.ackMu.Lock()
		delete(n.ackWaiter, packetID)
		n.ackMu.Unlock()
		return
	}
}

// execRumorsMessage handles incoming rumors: process expected, ack back, and forward if any expected.
func (n *node) execRumorsMessage(m types.Message, pkt transport.Packet) error {
	rumors, ok := m.(*types.RumorsMessage)
	if !ok {
		return errors.New("rumors message callback error")
	}
	myAddr := n.conf.Socket.GetAddress()
	anyExpected := n.applyExpectedRumors(rumors.Rumors, pkt)

	// Local rumors processed via Broadcast shouldn't trigger ack/forward.
	if pkt.Header != nil && pkt.Header.Source == myAddr {
		return nil
	}

	n.sendAckWithStatus(pkt)

	if anyExpected {
		n.forwardRumors(pkt)
	}

	return nil
}

// applyExpectedRumors processes in-order rumors, updates state, and returns true if any were applied.
func (n *node) applyExpectedRumors(items []types.Rumor, pkt transport.Packet) bool {
	myAddr := n.conf.Socket.GetAddress()
	applied := false
	for _, r := range items {
		n.recvMu.RLock()
		last := n.lastRecv[r.Origin]
		n.recvMu.RUnlock()

		if r.Sequence != last+1 {
			continue
		}

		newPkt := transport.Packet{Header: pkt.Header, Msg: r.Msg}
		_ = n.conf.MessageRegistry.ProcessPacket(newPkt)

		n.recvMu.Lock()
		n.lastRecv[r.Origin] = r.Sequence
		n.recvMu.Unlock()

		n.storeMu.Lock()
		if _, ok := n.rumorStore[r.Origin]; !ok {
			n.rumorStore[r.Origin] = make(map[uint]transport.Message)
		}
		n.rumorStore[r.Origin][r.Sequence] = *r.Msg
		n.storeMu.Unlock()

		// update routing if origin isn't a direct neighbor
		n.routingMu.RLock()
		relay, exists := n.routing[r.Origin]
		n.routingMu.RUnlock()
		if !exists || relay != r.Origin {
			if pkt.Header != nil && pkt.Header.RelayedBy != "" && pkt.Header.RelayedBy != myAddr {
				n.SetRoutingEntry(r.Origin, pkt.Header.RelayedBy)
			}
		}

		applied = true
	}
	return applied
}

// sendAckWithStatus replies to the source with our current status.
func (n *node) sendAckWithStatus(pkt transport.Packet) {
	myAddr := n.conf.Socket.GetAddress()
	status := n.buildStatus()
	ack := types.AckMessage{AckedPacketID: pkt.Header.PacketID, Status: status}
	ackMsg, err := n.conf.MessageRegistry.MarshalMessage(&ack)
	if err != nil {
		return
	}
	header := transport.NewHeader(myAddr, myAddr, pkt.Header.Source)
	out := transport.Packet{Header: &header, Msg: &ackMsg}
	_ = n.conf.Socket.Send(pkt.Header.Source, out, 2*time.Second)
}

// forwardRumors forwards the current rumor message to a random neighbor, excluding the source.
func (n *node) forwardRumors(pkt transport.Packet) {
	myAddr := n.conf.Socket.GetAddress()
	exclude := map[string]struct{}{pkt.Header.Source: {}}
	if neighbor, ok := n.pickRandomNeighbor(exclude); ok {
		header := transport.NewHeader(pkt.Header.Source, myAddr, neighbor)
		out := transport.Packet{Header: &header, Msg: pkt.Msg}
		_ = n.conf.Socket.Send(neighbor, out, 2*time.Second)
	}
}

// execAckMessage handles an ack: stop waiter and process embedded status.
func (n *node) execAckMessage(m types.Message, pkt transport.Packet) error {
	ack, ok := m.(*types.AckMessage)
	if !ok {
		return errors.New("ack message callback error")
	}

	// stop waiting for this ack
	n.ackMu.Lock()
	if w, found := n.ackWaiter[ack.AckedPacketID]; found {
		select {
		case <-w.stopCh:
		default:
			close(w.stopCh)
		}
		delete(n.ackWaiter, ack.AckedPacketID)
	}
	n.ackMu.Unlock()

	// process embedded status
	status := ack.Status
	msg, err := n.conf.MessageRegistry.MarshalMessage(&status)
	if err != nil {
		return err
	}
	newPkt := transport.Packet{Header: pkt.Header, Msg: &msg}
	_ = n.conf.MessageRegistry.ProcessPacket(newPkt)
	return nil
}

// execStatusMessage sync views and continue mongering when equal.
func (n *node) execStatusMessage(m types.Message, pkt transport.Packet) error {
	remote, ok := m.(*types.StatusMessage)
	if !ok {
		return errors.New("status message callback error")
	}
	local := n.buildStatus()

	missing, hasRemoteNew := n.computeStatusDiff(local, *remote)

	if len(missing) > 0 {
		n.sendMissingRumors(pkt.Header.Source, missing)
	}

	if hasRemoteNew {
		n.sendStatusTo(pkt.Header.Source)
		return nil
	}

	if len(missing) == 0 && n.conf.ContinueMongering > 0 {
		// equal views, maybe continue mongering to a different neighbor
		if rand.Float64() < n.conf.ContinueMongering {
			exclude := map[string]struct{}{pkt.Header.Source: {}}
			if neighbor, ok := n.pickRandomNeighbor(exclude); ok {
				n.sendStatusTo(neighbor)
			}
		}
	}
	return nil
}

type rumorRef struct {
	origin string
	seq    uint
}

// computeStatusDiff compares local and remote status and returns the missing rumors to send
// along with whether the remote has any newer sequence numbers.
func (n *node) computeStatusDiff(localStatus, remoteStatus types.StatusMessage) ([]rumorRef, bool) {
	remoteHasNew := false
	missingRefs := make([]rumorRef, 0)

	allOrigins := make(map[string]struct{})
	for origin := range localStatus {
		allOrigins[origin] = struct{}{}
	}
	for origin := range remoteStatus {
		allOrigins[origin] = struct{}{}
	}

	for origin := range allOrigins {
		localSeq := localStatus[origin]
		remoteSeq := remoteStatus[origin]
		switch {
		case remoteSeq > localSeq:
			remoteHasNew = true
		case localSeq > remoteSeq:
			for seq := remoteSeq + 1; seq <= localSeq; seq++ {
				missingRefs = append(missingRefs, rumorRef{origin: origin, seq: seq})
			}
		}
	}

	return missingRefs, remoteHasNew
}

// sendMissingRumors packs and sends the requested rumors to the destination.
func (n *node) sendMissingRumors(dest string, items []rumorRef) {
	if len(items) == 0 {
		return
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].origin == items[j].origin {
			return items[i].seq < items[j].seq
		}
		return items[i].origin < items[j].origin
	})

	rumors := make([]types.Rumor, 0, len(items))
	n.storeMu.RLock()
	for _, p := range items {
		if mset, ok := n.rumorStore[p.origin]; ok {
			if tm, ok2 := mset[p.seq]; ok2 {
				m := tm
				rumors = append(rumors, types.Rumor{Origin: p.origin, Sequence: p.seq, Msg: &m})
			}
		}
	}
	n.storeMu.RUnlock()
	if len(rumors) == 0 {
		return
	}

	out := types.RumorsMessage{Rumors: rumors}
	msg, err := n.conf.MessageRegistry.MarshalMessage(&out)
	if err != nil {
		return
	}
	myAddr := n.conf.Socket.GetAddress()
	header := transport.NewHeader(myAddr, myAddr, dest)
	pktOut := transport.Packet{Header: &header, Msg: &msg}
	_ = n.conf.Socket.Send(dest, pktOut, 2*time.Second)
}

// sendStatusTo sends the current status to the given destination.
func (n *node) sendStatusTo(dest string) {
	status := n.buildStatus()
	msg, err := n.conf.MessageRegistry.MarshalMessage(&status)
	if err != nil {
		return
	}
	myAddr := n.conf.Socket.GetAddress()
	header := transport.NewHeader(myAddr, myAddr, dest)
	out := transport.Packet{Header: &header, Msg: &msg}
	_ = n.conf.Socket.Send(dest, out, 2*time.Second)
}

// execPrivateMessage executes the embedded message only if the local address is a recipient.
func (n *node) execPrivateMessage(m types.Message, pkt transport.Packet) error {
	pm, ok := m.(*types.PrivateMessage)
	if !ok {
		return errors.New("private message callback error")
	}
	myAddr := n.conf.Socket.GetAddress()
	if _, ok := pm.Recipients[myAddr]; !ok {
		return nil
	}
	newPkt := transport.Packet{Header: pkt.Header, Msg: pm.Msg}
	_ = n.conf.MessageRegistry.ProcessPacket(newPkt)
	return nil
}

// execEmptyMessage is a no-op for heartbeat embedded messages.
func (n *node) execEmptyMessage(m types.Message, pkt transport.Packet) error {
	return nil
}
func (n *node) AddPeer(addr ...string) {
	if len(addr) == 0 { // If no addresses, nothing to do.
		return
	}

	self := ""
	if n.conf.Socket != nil {
		self = n.conf.Socket.GetAddress()
	}

	n.routingMu.Lock()
	for _, address := range addr { //_ is the index, we don't need it
		if address == "" {
			continue // skip empty addresses
		}
		if address == self {
			continue // skip self address
		}
		// Add direct neighbor: next hop is the peer itself.
		n.routing[address] = address
	}
	n.routingMu.Unlock()
}

// GetRoutingTable implements peer.Messaging
func (n *node) GetRoutingTable() peer.RoutingTable {
	n.routingMu.RLock()
	routingTable := make(peer.RoutingTable, len(n.routing)) // Allocate memory for the routing table
	for origin, relay := range n.routing {                  // Manually fill it
		routingTable[origin] = relay
	}
	n.routingMu.RUnlock()
	return routingTable
}

// SetRoutingEntry implements peer.Messaging
func (n *node) SetRoutingEntry(origin, relayAddr string) {
	if origin == "" { // If no origin, nothing to do.
		return
	}

	self := ""
	if n.conf.Socket != nil {
		self = n.conf.Socket.GetAddress()
	}
	if origin == self { // Ignore attempts to change self-entry.
		return
	}

	n.routingMu.Lock()
	if relayAddr == "" {
		// Delete entry if relayAddr is empty.
		delete(n.routing, origin)
	} else {
		// Set or overwrite entry.
		n.routing[origin] = relayAddr
	}
	n.routingMu.Unlock()
}

// ChatMessage callback – logs message
func (n *node) execChatMessage(msg types.Message, pkt transport.Packet) error {
	chatMsg, ok := msg.(*types.ChatMessage)
	if !ok {
		return errors.New("chat message callback error")
	}
	// Log the chat message; the logger is disabled if GLOG=="no"
	if pkt.Header != nil {
		n.log.Info().
			Str("type", chatMsg.Name()).
			Str("source", pkt.Header.Source).
			Str("destination", pkt.Header.Destination).
			Str("relayedBy", pkt.Header.RelayedBy).
			Msg(chatMsg.Message)
	} else {
		n.log.Info().
			Str("type", chatMsg.Name()).
			Msg(chatMsg.Message)
	}
	return nil
}
