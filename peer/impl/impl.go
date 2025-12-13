package impl

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
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
		conf:              conf,
		stopCh:            make(chan struct{}),
		stopped:           make(chan struct{}),
		routing:           map[string]string{},
		congestionControl: true,
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
	n.circuits = make(map[circuitKey]*Circuit)
	n.clientCircuits = make(map[uint16]*ClientCircuit)
	n.streamTables = make(map[uint16]*CircuitStreams)
	n.congestionControl = true

	// Initialize crypto state
	n.peerOnionKeys = make(map[string]*rsa.PublicKey)
	n.diffieHellmanHandshakePairs = make(map[uint16]*DiffieHellmanHandshakePairs)
	n.circuitCryptoStates = make(map[uint16][]*CircuitCryptoState)

	// Generate onion keypair for this node
	// Note: In production, this should be loaded from persistent storage
	// For now, we generate a new keypair each time
	var err error
	n.onionKey, err = GenerateOnionKeyPair()
	if err != nil {
		// Log error but don't fail initialization
		// The node can still function without crypto features
		n.log.Error().Err(err).Msg("Failed to generate onion keypair")
	}

	if conf.MessageRegistry != nil {
		conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, n.execChatMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, n.execRumorsMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, n.execAckMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, n.execStatusMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, n.execPrivateMessage)
		conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, n.execEmptyMessage)

		conf.MessageRegistry.RegisterMessageCallback(TorCellMessage{}, n.ExecTorCell)
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

	// Tor circuits (relay side)
	circuitsMu sync.RWMutex
	circuits   map[circuitKey]*Circuit

	// Tor client circuits (OP side)
	clientCircuitsMu sync.RWMutex
	clientCircuits   map[uint16]*ClientCircuit

	// streamTables[circID] = CircuitStreams
	streamsMu    sync.RWMutex
	streamTables map[uint16]*CircuitStreams

	// Congestion control toggle
	congestionControl bool

	// Cryptography for Tor-like onion routing
	onionKey      *OnionKeyPair             // This node's long-term onion keypair
	peerOnionKeys map[string]*rsa.PublicKey // Cached onion public keys for peers
	peerKeysMu    sync.RWMutex              // Protects peerOnionKeys

	// NOTE: Maybe they can be added to the Circuit struct
	diffieHellmanHandshakePairs map[uint16]*DiffieHellmanHandshakePairs // Pending handshakes by circuit ID
	// Crypto states per circuit ID. Each Circuit ID has multiple Crypto States, one per hop
	circuitCryptoStates map[uint16][]*CircuitCryptoState
	cryptoStatesMu      sync.Mutex // Protects circuitCryptoStates

	circuitIDMu sync.Mutex // Protects circuit ID generation
	circuitIDs  []uint16   // Allocated circuit IDs

	// Rate limiting
	writeBucket *TokenBucket // Token bucket for outgoing data
	readBucket  *TokenBucket // Token bucket for incoming data
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
		// Rate limiting
		if n.congestionControl {
			size := CellSize
			wait := n.readBucket.Consume(float64(size))
			if wait > 0 {
				n.log.Info().
					Int("size", size).
					Dur("wait", wait).
					Msg("Rate limiting: waiting to receive cell")
				time.Sleep(wait)
			}
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
	//Rate limiting
	if n.congestionControl {
		size := CellSize

		//Check bucket
		wait := n.writeBucket.Consume(float64(size))
		if wait > 0 {
			n.log.Info().
				Str("dest", dest).
				Int("size", size).
				Dur("wait", wait).
				Msg("Rate limiting: waiting to send cell")
			time.Sleep(wait)
		}
	}
	return n.conf.Socket.Send(nextHop, pkt, 2*time.Second)
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

func (n *node) ExecTorCell(m types.Message, pkt transport.Packet) error {
	cellMsg, ok := m.(*TorCellMessage)
	if !ok {
		return errors.New("tor cell callback error")
	}

	cell, err := n.DecodeCell(cellMsg.Raw)
	if err != nil {
		return err
	}

	src := pkt.Header.Source

	switch cell.Command {
	case Create:
		return n.HandleCreate(cell, src)
	case Created:
		return n.HandleCreated(cell, src)
	case Relay:
		return n.HandleRelay(cell, src)
	case Destroy:
		return n.HandleDestroy(cell, src)
	case Padding:
		return nil
	}

	// Unknown command
	return fmt.Errorf("unknown cell command %d", cell.Command)
}

// Get onion public key
func (n *node) GetOnionPublicKey() interface{} {
	if n.onionKey == nil {
		return nil
	}
	return n.onionKey.Public
}

// AddPeerOnionKey stores a remote onion public key in the cache
// This function is used to populate a map of IP addresses to onion public keys
// In the future, this should be replaced with a persistent storage mechanism
func (n *node) AddPeerOnionKey(peerAddr string, pubKey interface{}) {
	n.peerKeysMu.Lock()
	defer n.peerKeysMu.Unlock()
	if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
		n.peerOnionKeys[peerAddr] = rsaKey
	}
}

// Retrieves a remote onion public key from the cache
func (n *node) GetPeerPublicOnionKey(peerAddr string) (*rsa.PublicKey, error) {
	n.peerKeysMu.RLock()
	defer n.peerKeysMu.RUnlock()
	pubKey, ok := n.peerOnionKeys[peerAddr]
	if !ok {
		return nil, fmt.Errorf("onion public key for peer %s not found", peerAddr)
	}
	return pubKey, nil
}

// AddStream adds a stream to the circuit's stream table'
func (n *node) AddStream(circID uint16, stream *Stream) {
	table := n.GetCircuitStreams(circID)

	n.streamsMu.Lock()
	table.Streams[stream.ID] = stream
	n.streamsMu.Unlock()
}

// DeleteStream deletes a stream to the circuit's stream table
func (n *node) DeleteStream(circID uint16, stream *Stream) {
	table := n.GetCircuitStreams(circID)

	n.streamsMu.Lock()
	delete(table.Streams, stream.ID)
	n.streamsMu.Unlock()
}

// GetStream returns a stream from the circuit's stream table
func (n *node) GetStream(circID uint16, streamID uint16) *Stream {
	n.streamsMu.RLock()
	table, ok := n.streamTables[circID]
	if !ok {
		n.streamsMu.RUnlock()
		return nil
	}
	stream := table.Streams[streamID]
	n.streamsMu.RUnlock()
	return stream
}

// GetCircuitStreams returns the streams table for a given circuit ID
func (n *node) GetCircuitStreams(circID uint16) *CircuitStreams {
	n.streamsMu.Lock()
	defer n.streamsMu.Unlock()

	// If no table exists yet, create it
	table, ok := n.streamTables[circID]
	if !ok {
		table = &CircuitStreams{
			Streams: make(map[uint16]*Stream),
		}
		n.streamTables[circID] = table
	}
	return table
}

// CleanupStreams removes the streams table when a circuit is destroyed
func (n *node) CleanupStreams(circID uint16) {
	n.streamsMu.Lock()
	delete(n.streamTables, circID)
	n.streamsMu.Unlock()
}
