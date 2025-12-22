package impl

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/udp"
)

// PacketQueueItem holds a cell waiting to be sent
type PacketQueueItem struct {
	Dest string
	Cell Cell
}

// Circuit represents a relay-side circuit state
type Circuit struct {
	InCircID  uint16
	PrevHop   string
	OutCircID uint16
	NextHop   string
	State     string // "pending", "established"

	// Hop-by-hop circuit-level flow control - separate windows for each direction
	// This applies at every relay: Guard↔Middle, Middle↔Exit, etc.
	// Forward direction (PrevHop -> this node -> NextHop)
	ForwardPackageWindow int        // Cells we can send to NextHop
	ForwardDeliverWindow int        // Cells we can accept from PrevHop
	ForwardWindowCond    *sync.Cond // To block when ForwardPackageWindow is 0

	// Backward direction (NextHop -> this node -> PrevHop)
	BackwardPackageWindow int        // Cells we can send to PrevHop
	BackwardDeliverWindow int        // Cells we can accept from NextHop
	BackwardWindowCond    *sync.Cond // To block when BackwardPackageWindow is 0

	// Queues for non-blocking flow control
	ForwardQueue  []PacketQueueItem // Packets waiting for ForwardPackageWindow
	BackwardQueue []PacketQueueItem // Packets waiting for BackwardPackageWindow

	// Legacy fields (kept for backward compatibility with endpoint flow control)
	PackageWindow int // Number of cells that can be sent (used by exit node)
	DeliverWindow int // Number of cells that can be received (used by exit node)
	WindowCond    *sync.Cond

	// Crypto synchronization
	CryptoMu sync.Mutex // Protects access to circuitCryptoStates for this circuit

	// Fairness / Prioritization
	CellCount float64 // EWMA of cells sent
	IsBulk    bool    // True if CellCount > Threshold
}

// Stream definition
type StreamState int

const (
	StreamInit StreamState = iota
	StreamWaitingForConnected
	StreamOpen

	StreamHalfClosedLocal // for two-way-handshake
	StreamHalfClosedRemote
	StreamFullyClosed
)

type Stream struct {
	mu         sync.RWMutex // protects State field
	ID         uint16
	CircID     uint16
	State      StreamState
	TargetAddr string // UDP connection (assumed for streams)
	Sock       transport.ClosableSocket

	// Stores the data that was sent by the client over this stream
	// This variable is used for testing purposes to verify data transmission
	// It is populated only for Client and Exit nodes
	SentData [][]byte

	// Buffer for data received from the remote target
	// This variable is used for testing purposes to verify data transmission
	// It is populated only for Client and Exit nodes
	ReceivedData [][]byte

	// Flow control
	PackageWindow int        // Number of cells that can be sent
	DeliverWindow int        // Number of cells that can be received
	WindowCond    *sync.Cond // To block when PackageWindow is 0

	// Fairness / Prioritization
	CellCount float64 // EWMA of cells sent
	IsBulk    bool    // True if CellCount > Threshold

	// TODO: In real implementation, there would be a server node sending data back, not exit
}

type CircuitStreams struct {
	Streams map[uint16]*Stream // streamID -> Stream
}

var udpFac transport.Factory = udp.NewUDP

// SetUDPFactory allows tests to override the UDP factory and emulate a SOCK creation failure when UDP is failing
func SetUDPFactory(factory transport.Factory) {
	udpFac = factory
}

type circuitKey struct {
	PrevHop  string
	InCircID uint16
}

const (
	// Flow control constants
	DefaultWindowSize = 500 // Unit is cells
	WindowIncrement   = 50

	// Stream flow control constants
	DefaultStreamWindowSize = 500
	StreamWindowIncrement   = 50
)

// ClientCircuitState represents the state of a client-initiated circuit
type ClientCircuitState int

const (
	CircuitStateCreating   ClientCircuitState = iota // Waiting for Created from first hop
	CircuitStateExtending1                           // Waiting for Extended from hop 2
	CircuitStateExtending2                           // Waiting for Extended from hop 3
	CircuitStateReady                                // Circuit fully established
	CircuitStateFailed                               // Circuit creation failed
)

// ClientCircuit represents an OP-initiated circuit through 3 hops
type ClientCircuit struct {
	CircID    uint16             // Circuit ID used on the first hop
	Hops      [3]string          // The 3 relay addresses: Guard, Middle, Exit
	State     ClientCircuitState // Current state machine state
	ReadyChan chan struct{}      // Closed when circuit is ready
	Error     error              // Set if circuit creation fails

	// Stream-level flow control (end-to-end with Exit)
	PackageWindow int // Number of cells that can be sent (stream level)
	DeliverWindow int // Number of cells that can be received (stream level)
	WindowCond    *sync.Cond

	// Hop-by-hop circuit-level flow control (with adjacent hop - Guard)
	// Note: This mechanism applies at every node pair in the circuit
	ForwardPackageWindow  int // Cells we can send to next hop (Guard)
	BackwardDeliverWindow int // Cells we can receive from next hop (Guard)

	// Fairness / Prioritization
	StatsMu   sync.Mutex // Protects CellCount and IsBulk
	CellCount float64    // EWMA of cells sent
	IsBulk    bool       // True if CellCount > Threshold

	// Crypto synchronization
	CryptoMu sync.Mutex // Protects access to circuitCryptoStates for this circuit

	// Hidden service support
	IsRendezvous bool // True if this is a rendezvous circuit
}

// -----------------------------------------------------------------------------
// Tor Circuit Handlers

// HandleCreate handles a Create cell
func (n *node) HandleCreate(cell Cell, src string) error {
	n.circuitsMu.Lock()
	defer n.circuitsMu.Unlock()

	key := circuitKey{PrevHop: src, InCircID: cell.CircID}
	_, exists := n.circuits[key]
	if exists {
		return nil
	}

	// Create new circuit
	circ := &Circuit{
		InCircID:              cell.CircID,
		PrevHop:               src,
		State:                 "established",
		PackageWindow:         DefaultWindowSize,
		DeliverWindow:         DefaultWindowSize,
		ForwardPackageWindow:  DefaultWindowSize,
		ForwardDeliverWindow:  DefaultWindowSize,
		BackwardPackageWindow: DefaultWindowSize,
		BackwardDeliverWindow: DefaultWindowSize,
	}
	circ.WindowCond = sync.NewCond(&n.circuitsMu)
	circ.ForwardWindowCond = sync.NewCond(&n.circuitsMu)
	circ.BackwardWindowCond = sync.NewCond(&n.circuitsMu)
	n.circuits[key] = circ

	// Track this circuit ID
	n.addCircuitID(cell.CircID)

	n.log.Info().Str("src", src).Uint16("circID", cell.CircID).Msg("Handling Create cell")

	// Perform handshake and derive keys using CompleteHandshakeAsResponder
	// Then reply with the appropriate payload'
	n.log.Info().Str("src", src).Uint16("circID", cell.CircID).Msg("Completing handshake as responder")
	payloadBytes, crypto, err := n.CompleteHandshakeAsResponder(n.onionKey, cell.Payload[:])
	if err != nil {
		return fmt.Errorf("handshake failed for circuit %d from %s: %w", cell.CircID, src, err)
	}

	// Store the crypto state for this circuit, for this hop
	n.circuitCryptoStates[cell.CircID] = []*CircuitCryptoState{crypto}

	// Prepare the payload for Created
	var payload [CellPayloadLen]byte
	copy(payload[:], payloadBytes)

	// Send Created
	reply := Cell{
		CircID:  cell.CircID,
		Command: Created,
		Payload: payload,
	}

	n.log.Info().Str("src", src).Uint16("circID", cell.CircID).Msg("Sending Created")

	return n.SendCell(src, reply)
}

// HandleCreated handles a Created cell
func (n *node) HandleCreated(cell Cell, src string) error {
	// First, check if this is for a client circuit (OP case)
	n.clientCircuitsMu.RLock()
	_, isClientCircuit := n.clientCircuits[cell.CircID]
	n.clientCircuitsMu.RUnlock()

	n.log.Info().Str("src", src).Uint16("circID", cell.CircID).Msg("Handling Created cell")

	if isClientCircuit {
		return n.HandleCreatedAsOP(cell, src)
	}

	// Otherwise, it's a relay circuit
	n.circuitsMu.Lock()
	defer n.circuitsMu.Unlock()

	var targetCirc *Circuit
	for _, circ := range n.circuits {
		if circ.NextHop == src && circ.OutCircID == cell.CircID {
			targetCirc = circ
			break
		}
	}

	if targetCirc == nil {
		return fmt.Errorf("received Created from %s for unknown circuit %d", src, cell.CircID)
	}

	targetCirc.State = "established"
	n.log.Info().Str("peer", src).Uint16("circID", cell.CircID).Msg("Circuit established")

	// Forward the payload of CREATED back to PrevHop after encrypting it with the shared key
	// NOTE: In reality, the cell payload is of Relay Cell sized. So we need to truncate it accordingly
	cryptoStates := n.circuitCryptoStates[targetCirc.InCircID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto state found for circuit %d", targetCirc.InCircID)
	}
	targetCirc.CryptoMu.Lock()
	relayPayloadCipherText, digest, err := EncryptRelayPayload(
		cryptoStates[0],
		DirectionBackward,
		cell.Payload[:RelayPayloadLen],
	)
	targetCirc.CryptoMu.Unlock()

	if err != nil {
		return err
	}

	if targetCirc.PrevHop != "" {
		relayPayload := RelayCell{
			CircID:   targetCirc.InCircID,
			StreamID: 0,
			Command:  RelayExtended,
			Digest:   digest,
			Length:   uint16(len(relayPayloadCipherText)),
			Data:     relayPayloadCipherText,
		}

		cellToSend, err := n.EncodeRelayCell(relayPayload)
		if err != nil {
			return err
		}
		return n.SendCell(targetCirc.PrevHop, cellToSend, targetCirc)
	}

	return nil
}

// HandleRelay handles a Relay cell
// TODO: All the relay cells need to have the command encrypted as well
func (n *node) HandleRelay(cell Cell, src string) error {
	// First, check if this is for a rendezvous circuit
	//n.rendezvousAssocMu.Lock()
	peerCircID, isRendezvous := n.rendezvousAssoc[cell.CircID]
	//n.rendezvousAssocMu.Unlock()
	n.log.Debug().Msgf("Handling relay cell with CircID %d from %s", cell.CircID, src)
	if isRendezvous {
		// CRITICAL FIX FOR RENDEZVOUS CIRCUITS (debugged using copilot):
		// The RP must decrypt its layer before blind forwarding, just like any other relay node.
		// Without this, Bob would receive data still encrypted with Alice's RP layer, which Bob
		// cannot decrypt as Alice and Bob have different RP crypto states.
		// Flow: Alice encrypts [SharedSecret, RP, Middle, Guard] -> Guard decrypts -> Middle decrypts
		//       -> RP decrypts RP layer -> forwards SharedSecret-encrypted data to Bob's circuit
		//       -> Bob's Middle encrypts backward -> Bob's Guard encrypts backward -> Bob receives
		//       -> Bob decrypts [Guard bwd, Middle bwd, SharedSecret fwd]
		n.log.Debug().Msg("Will forward relay cell at rendezvous point")

		// Look up the incoming circuit to decrypt the RP layer
		n.circuitsMu.RLock()
		var incomingCirc *Circuit
		for k, c := range n.circuits {
			if k.InCircID == cell.CircID {
				incomingCirc = c
				break
			}
		}
		n.circuitsMu.RUnlock()

		if incomingCirc == nil {
			return fmt.Errorf("rendezvous incoming circuit %d not found", cell.CircID)
		}

		// Decrypt the relay cell data with RP's crypto state before forwarding
		relayCell, err := n.DecodeRelayCell(cell)
		if err != nil {
			return err
		}

		cryptoStates := n.circuitCryptoStates[incomingCirc.InCircID]
		if len(cryptoStates) > 0 {
			incomingCirc.CryptoMu.Lock()
			decryptedData, _ := DecryptRelayCellAtHop(cryptoStates[0], DirectionForward, relayCell.Data, relayCell.Digest)
			incomingCirc.CryptoMu.Unlock()
			n.log.Debug().Msg("[RP] Decrypted RP layer before blind forwarding (critical for rendezvous)")
			relayCell.Data = decryptedData
			relayCell.Length = uint16(len(decryptedData))
		}

		// Look up the peer circuit
		n.circuitsMu.RLock()
		var peerKey *circuitKey
		for k := range n.circuits {
			if k.InCircID == peerCircID {
				keyCopy := k // avoid loop variable capture
				peerKey = &keyCopy
				break
			}
		}
		n.circuitsMu.RUnlock()

		if peerKey == nil {
			return fmt.Errorf("rendezvous peer circuit %d not found", peerCircID)
		}

		n.log.Debug().
			Uint16("fromCircID", cell.CircID).
			Uint16("toCircID", peerCircID).
			Str("toHop", peerKey.PrevHop).
			Msg("Forwarding relay cell at rendezvous point after decrypting RP layer")

		// Rewrite circuit ID for the receiving side and encode
		relayCell.CircID = peerKey.InCircID
		forwardCell, err := n.EncodeRelayCell(relayCell)
		if err != nil {
			return err
		}

		// Forward to the other circuit's previous hop
		return n.SendCell(peerKey.PrevHop, forwardCell)
	}

	// Check if this is for a client circuit (OP receiving relay cells)
	n.clientCircuitsMu.RLock()
	cc, isClientCircuit := n.clientCircuits[cell.CircID]
	n.clientCircuitsMu.RUnlock()

	if isClientCircuit {
		return n.HandleRelayAsOP(cell, src, cc)
	}

	return n.HandleRelayForwarding(cell, src)
}

// HandleRelayAsOP handles a relay cell when acting as OP
func (n *node) HandleRelayAsOP(cell Cell, src string, cc *ClientCircuit) error {
	// OP receiving a relay cell back from the circuit
	relayCell, err := n.DecodeRelayCell(cell)
	if err != nil {
		return err
	}

	// Verify it came from our guard
	if src != cc.Hops[0] {
		return fmt.Errorf("relay cell from unexpected source %s (expected %s)", src, cc.Hops[0])
	}

	switch relayCell.Command {
	case RelayExtended:
		return n.HandleRelayExtendedAsOP(relayCell)
	case RelayConnected:
		return n.HandleRelayConnectedAsOP(relayCell, cc)
	case RelayEnd:
		return n.HandleRelayEndAsOP(relayCell, cc)
	case RelayData:
		return n.HandleRelayDataAsOP(relayCell, cc)
	case RelaySendme:
		return n.HandleRelaySendmeAsOP(relayCell, cc)
	case RelayIntroEstablished:
		return n.HandleRelayIntroEstablished(relayCell)
	case RelayHSDirReply:
		return n.HandleRelayHSDirReply(relayCell)
	case RelayRPEstablished:
		return n.HandleRelayRPEstablished(relayCell)
	case RelayIntroduceACK:
		return n.HandleRelayIntroduceACK(relayCell)
	case RelayIntroduce2:
		return n.HandleRelayIntroduce2(relayCell)
	case RelayRendezvous2:
		return n.HandleRelayRendezvous2(relayCell)
	case RelayBegin:
		// Hidden service (Bob) receiving RELAY_BEGIN from client (Alice) over rendezvous circuit
		return n.HandleRelayBeginAsOP(relayCell, cc)
	default:
		n.log.Error().
			Int("command", int(relayCell.Command)).
			Msg("unexpected relay command for client circuit") // This is the only thing that helped in debugging a big issue in Hidden Service
		return fmt.Errorf("unexpected relay command %d for client circuit", relayCell.Command)
	}
}

// HandleRelaySendmeAsOP handles a RelaySendme command when acting as OP
func (n *node) HandleRelaySendmeAsOP(relayCell RelayCell, cc *ClientCircuit) error {
	if !n.congestionControl.Load() {
		return nil
	}

	if relayCell.StreamID != 0 {
		// Stream-level flow control
		stream, err := n.validateStreamForData(cc.CircID, relayCell.StreamID)
		if err != nil {
			return err
		}

		stream.mu.Lock()
		stream.PackageWindow += StreamWindowIncrement
		stream.WindowCond.Broadcast()
		newWindow := stream.PackageWindow
		stream.mu.Unlock()

		n.log.Info().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relayCell.StreamID).
			Int("newPackageWindow", newWindow).
			Msg("Received stream SENDME (OP), window updated")
		return nil
	}

	n.clientCircuitsMu.Lock()
	defer n.clientCircuitsMu.Unlock()

	cc.PackageWindow += WindowIncrement
	cc.WindowCond.Broadcast()
	n.log.Info().Uint16("circID", cc.CircID).Int("newWindow", cc.PackageWindow).Msg("Received SENDME (OP), window updated")
	return nil
}

func (n *node) sendRelaySendmeStreamAsOP(cc *ClientCircuit, streamID uint16) error {
	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", streamID).
		Msg("Sending stream RELAY_SENDME as OP")

	cryptoStates := n.circuitCryptoStates[cc.CircID]
	cc.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, []byte{})
	cc.CryptoMu.Unlock()

	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", cc.CircID).
			Msg("Failed to encrypt stream RELAY_SENDME payload")
		return err
	}

	relayCell := RelayCell{
		CircID:   cc.CircID,
		StreamID: streamID,
		Command:  RelaySendme,
		Digest:   digest,
		Data:     encrypted,
		Length:   uint16(len(encrypted)),
	}

	cell, _ := n.EncodeRelayCell(relayCell)
	n.log.Info().
		Uint16("circID", cc.CircID).
		Str("guard", cc.Hops[0]).
		Msg("Sending stream RELAY_SENDME to guard")
	return n.SendCell(cc.Hops[0], cell)
}

// HandleRelayForwarding handles a relay cell when acting as a relay
func (n *node) HandleRelayForwarding(cell Cell, src string) error {
	n.circuitsMu.RLock()
	key := circuitKey{PrevHop: src, InCircID: cell.CircID}
	circ, exists := n.circuits[key]

	// If not found, try to find circuit where src is NextHop (cell coming back)
	if !exists {
		for _, c := range n.circuits {
			if c.NextHop == src && c.OutCircID == cell.CircID {
				circ = c
				exists = true
				break
			}
		}
	}
	n.circuitsMu.RUnlock()

	if !exists {
		return fmt.Errorf("received Relay cell for unknown circuit %d from %s", cell.CircID, src)
	}

	// Determine direction: is this coming from PrevHop or NextHop?
	switch src {
	case circ.PrevHop:
		return n.HandleForwardRelay(cell, circ)
	case circ.NextHop:
		return n.HandleBackwardRelay(cell, circ)
	}

	return fmt.Errorf("relay cell from unexpected source %s", src)
}

// HandleForwardRelay handles a relay cell going forward (PrevHop -> NextHop)
func (n *node) HandleForwardRelay(cell Cell, circ *Circuit) error {
	// Decode the relay cell
	relayCell, err := n.DecodeRelayCell(cell)
	if err != nil {
		return err
	}

	// Get crypto state for this circuit
	cryptoStates := n.circuitCryptoStates[circ.InCircID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto state found for circuit %d", circ.InCircID)
	}

	// Handle circuit-level SENDME from PrevHop
	if n.processCircuitSendmeFromPrevHop(relayCell, circ) {
		return nil
	}

	// Try to decrypt and check if this cell is for this node
	circ.CryptoMu.Lock()
	decryptedData, isForUs := DecryptRelayCellAtHop(cryptoStates[0], DirectionForward, relayCell.Data, relayCell.Digest)
	circ.CryptoMu.Unlock()

	if isForUs {
		n.log.Info().
			Uint16("circID", circ.InCircID).
			Uint8("command", relayCell.Command).
			Msg("Digest matched and processing relay command")

		if circ.NextHop == "" {
			relayCell.Data = decryptedData
			return n.HandleRelayAtEndpoint(relayCell, circ)
		}
		return nil
	}

	// Digest didn't match - forward the cell
	n.SecurityStats.mu.Lock()
	n.SecurityStats.DigestMismatches++
	n.SecurityStats.RelayDigestMismatches++
	n.SecurityStats.mu.Unlock()

	n.log.Info().
		Uint16("circID", circ.InCircID).
		Str("nextHop", circ.NextHop).
		Msg("Digest mismatch; forwarding relay cell to next hop")

	if circ.NextHop == "" {
		n.SecurityStats.mu.Lock()
		n.SecurityStats.DroppedCells++
		n.SecurityStats.DroppedDigestMismatch++
		n.SecurityStats.DroppedNoNextHop++
		n.SecurityStats.mu.Unlock()
		return fmt.Errorf("digest mismatch but no next hop to forward to")
	}

	// Handle flow control
	n.handleForwardFlowControl(relayCell, circ)

	// Forward the decrypted data to NextHop
	relayCell.Data = decryptedData
	relayCell.Length = uint16(len(decryptedData))
	relayCell.CircID = circ.OutCircID
	forwardCell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}

	isDataCell := relayCell.Command == RelayData
	return n.queueOrSendForward(circ, forwardCell, isDataCell)
}

// HandleRelayAtEndpoint is the switch case of HandleForwardRelay
func (n *node) HandleRelayAtEndpoint(relayCell RelayCell, circ *Circuit) error {
	switch relayCell.Command {
	case RelayBegin:
		return n.HandleRelayBegin(relayCell, circ)
	case RelayEnd:
		return n.HandleRelayEnd(relayCell, circ)
	case RelayExtend:
		return n.HandleRelayExtend(relayCell, circ)
	case RelayExtended:
		return n.HandleRelayExtended(relayCell, circ)
	case RelayData:
		return n.HandleRelayData(relayCell, circ)
	case RelaySendme:
		return n.HandleRelaySendme(relayCell, circ)
	case RelayIntroduce1:
		return n.HandleRelayIntroduce1(relayCell, circ)
	case RelayEstablishIntro:
		return n.HandleRelayEstablishIntro(relayCell, circ)
	case RelayRendezvous1:
		return n.HandleRelayRendezvous1(relayCell, circ)
	case RelayHSDirPublish:
		return n.HandleRelayHSDirPublish(relayCell, circ)
	case RelayHSDirLookup:
		return n.HandleRelayHSDirLookup(relayCell, circ)
	case RelayHSDirDelete:
		return n.HandleRelayHSDirDelete(relayCell, circ)
	case RelayEstablishRP:
		return n.HandleRelayEstablishRP(relayCell, circ)
	default:
		return fmt.Errorf("unknown relay command %d", relayCell.Command)
	}
}

// HandleBackwardRelay handles a relay cell going backward (NextHop -> PrevHop)
func (n *node) HandleBackwardRelay(cell Cell, circ *Circuit) error {
	n.log.Info().
		Uint16("circID", circ.InCircID).
		Str("prevHop", circ.PrevHop).
		Msg("Encrypting and forwarding relay cell to previous hop")

	// Decode the relay cell
	relayCell, err := n.DecodeRelayCell(cell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circ.InCircID).
			Msg("Failed to decode relay cell in backward direction")
		return err
	}

	// Get crypto state for this circuit
	cryptoStates := n.circuitCryptoStates[circ.InCircID]
	if len(cryptoStates) == 0 {
		n.log.Error().
			Uint16("circID", circ.InCircID).
			Msg("No crypto state found for backward relay")
		return fmt.Errorf("no crypto state found for circuit %d", circ.InCircID)
	}

	// Handle circuit-level SENDME from NextHop
	if n.processCircuitSendmeFromNextHop(relayCell, circ) {
		return nil
	}

	// Handle flow control
	n.handleBackwardFlowControl(relayCell, circ)

	// Encrypt one layer using our crypto state
	circ.CryptoMu.Lock()
	encryptedData, digest, err := EncryptRelayPayload(
		cryptoStates[0],
		DirectionBackward,
		relayCell.Data,
	)
	circ.CryptoMu.Unlock()
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circ.InCircID).
			Msg("Failed to encrypt relay cell data in backward direction")
		return fmt.Errorf("failed to encrypt relay cell data: %w", err)
	}

	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", relayCell.StreamID).
		Int("command", int(relayCell.Command)).
		Msg("Encrypted relay cell, forwarding to previous hop")

	// Build the encrypted relay cell
	encryptedRelayCell := RelayCell{
		CircID:   circ.InCircID,
		StreamID: relayCell.StreamID,
		Command:  relayCell.Command,
		Digest:   digest,
		Length:   uint16(len(encryptedData)),
		Data:     encryptedData,
	}

	// Encode cell
	cellToSend, err := n.EncodeRelayCell(encryptedRelayCell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circ.InCircID).
			Msg("Failed to encode encrypted relay cell")
		return err
	}

	isDataCell := relayCell.Command == RelayData
	return n.queueOrSendBackward(circ, cellToSend, isDataCell)
}

// HandleRelayBegin opens a stream on a circuit (as an Exit node)
func (n *node) HandleRelayBegin(relay RelayCell, circ *Circuit) error {
	// Open a brand new UDP socket using your transport layer
	transportSocket := udpFac()
	socket, err := transportSocket.CreateSocket(":0")
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circ.InCircID).
			Uint16("streamID", relay.StreamID).
			Msg("Server failed to open socket. Sending RelayEnd") // TODO: Should send Relay Truncate
		return n.SendRelayEnd(circ, relay.StreamID)
	}

	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", relay.StreamID).
		Str("targetAddr", string(relay.Data)).
		Msg("Handling RelayBegin - opening stream as Exit node")

	stream := &Stream{
		ID:            relay.StreamID,
		CircID:        circ.InCircID,
		State:         StreamWaitingForConnected,
		TargetAddr:    string(relay.Data),
		Sock:          socket,
		PackageWindow: DefaultStreamWindowSize,
		DeliverWindow: DefaultStreamWindowSize,
	}
	stream.WindowCond = sync.NewCond(&stream.mu)

	n.AddStream(circ.InCircID, stream)
	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", relay.StreamID).
		Msg("Added stream to circuit")

	// Respond with RELAY_CONNECTED
	stream.mu.Lock()
	stream.State = StreamOpen
	stream.mu.Unlock()
	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", relay.StreamID).
		Msg("Stream state set to Open, sending RelayConnected")
	return n.SendRelayConnected(circ, relay.StreamID)
}

// sendRelayControlCell is a helper function to send RELAY_CONNECTED or RELAY_END
func (n *node) sendRelayControlCell(circ *Circuit, streamID uint16, command uint8, msgType string) error {
	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", streamID).
		Str("prevHop", circ.PrevHop).
		Msgf("Sending %s to previous hop", msgType)

	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	crypto := n.circuitCryptoStates[circ.InCircID][exitIdx]

	circ.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayPayload(
		crypto,
		DirectionBackward,
		[]byte{},
	)
	circ.CryptoMu.Unlock()

	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circ.InCircID).
			Uint16("streamID", streamID).
			Msgf("Failed to encrypt %s payload", msgType)
		return err
	}

	relayCell := RelayCell{
		CircID:   circ.InCircID,
		StreamID: streamID,
		Command:  command,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}

	cell, _ := n.EncodeRelayCell(relayCell)
	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", streamID).
		Msgf("%s sent successfully", msgType)
	return n.SendCell(circ.PrevHop, cell, circ)
}

// SendRelayConnected sends RELAY_CONNECTED after receiving RELAY_BEGIN
func (n *node) SendRelayConnected(circ *Circuit, streamID uint16) error {
	return n.sendRelayControlCell(circ, streamID, RelayConnected, "RelayConnected")
}

// HandleRelayEnd closes a stream on a circuit
func (n *node) HandleRelayEnd(relay RelayCell, circ *Circuit) error {
	streams := n.GetCircuitStreams(circ.InCircID)
	stream := streams.Streams[relay.StreamID]
	if stream == nil {
		return nil
	}

	// Peer asked to close
	stream.mu.Lock()
	currentState := stream.State
	stream.mu.Unlock()

	if currentState == StreamOpen {
		n.log.Info().
			Uint16("circID", circ.InCircID).
			Uint16("streamID", relay.StreamID).
			Msg("Stream was Open, sending RelayEnd and closing immediately (relay circuit)")

		// Send acknowledgment
		err := n.SendRelayEnd(circ, relay.StreamID)

		// Close the stream immediately since we're the endpoint
		stream.mu.Lock()
		stream.State = StreamFullyClosed
		stream.mu.Unlock()
		n.DeleteStream(circ.InCircID, stream)

		n.log.Info().
			Uint16("circID", circ.InCircID).
			Uint16("streamID", relay.StreamID).
			Msg("Stream fully closed and deleted (relay circuit)")

		return err
	}

	// Peer’s acknowledgment
	if currentState == StreamHalfClosedLocal {
		stream.mu.Lock()
		stream.State = StreamFullyClosed
		stream.mu.Unlock()
		err := stream.Sock.Close()
		if err != nil {
			return err
		}
		n.DeleteStream(circ.InCircID, stream)
		return nil
	}

	if currentState == StreamHalfClosedRemote {
		stream.mu.Lock()
		stream.State = StreamFullyClosed
		stream.mu.Unlock()
		if stream.Sock != nil {
			err := stream.Sock.Close()
			if err != nil {
				return err
			}
		}
		n.DeleteStream(circ.InCircID, stream)
		return nil
	}

	return nil
}

// SendRelayEnd sends RELAY_END for closing a stream on a circuit
func (n *node) SendRelayEnd(circ *Circuit, streamID uint16) error {
	return n.sendRelayControlCell(circ, streamID, RelayEnd, "RelayEnd")
}

// HandleRelayExtend handles a RelayExtend command
func (n *node) HandleRelayExtend(relayCell RelayCell, circ *Circuit) error {
	// The relay cell Data has already been decrypted by HandleForwardRelay
	plaintext := relayCell.Data

	// Extract the handshake data from the plaintext
	// Format: [addrLen(2)][address][encryptedHandshake]
	if len(plaintext) < 2 {
		return errors.New("invalid RelayExtend payload")
	}

	// Parse the target address from the plaintext
	targetLen := (uint16(plaintext[0]) << 8) | uint16(plaintext[1])
	if targetLen == 0 || int(targetLen)+2 > len(plaintext) {
		n.log.Error().Str("targetLen", fmt.Sprintf("%d", targetLen)).Msg("Invalid target length in RelayExtend")
		return errors.New("invalid target length in RelayExtend")
	}

	// Extract the encrypted handshake data after the address
	handshakePayload := plaintext[2+targetLen:]

	target := string(plaintext[2 : 2+targetLen])
	if target == "" {
		return errors.New("empty target in RelayExtend")
	}

	n.circuitsMu.Lock()
	defer n.circuitsMu.Unlock()

	var newID uint16
	for {
		newID = uint16(rand.Intn(65535) + 1) // Generate new circuit ID
		collision := false
		for _, c := range n.circuits {
			if c.NextHop == target && c.OutCircID == newID {
				collision = true
				break
			}
		}
		if !collision {
			break
		}
	}

	circ.NextHop = target
	circ.OutCircID = newID
	circ.State = "extending"

	// Track the new outgoing circuit ID
	n.addCircuitID(newID)

	n.log.Info().Str("target", target).Uint16("newCircID", newID).Msg("Extending circuit")

	var payload [CellPayloadLen]byte
	copy(payload[:], handshakePayload)

	createCell := Cell{
		CircID:  newID,
		Command: Create,
		Payload: payload,
	}
	return n.SendCell(target, createCell)
}

// HandleRelayExtended handles a RelayExtended command
func (n *node) HandleRelayExtended(_ RelayCell, _ *Circuit) error {
	n.log.Info().Msg("Circuit extension confirmed (RelayExtended)")
	return nil
}

// SendCell sends a cell to a destination
// Optional: pass the circuit associated with this cell for fairness accounting
// circ can be *Circuit, *ClientCircuit, or *Stream
func (n *node) SendCell(dest string, cell Cell, circ ...interface{}) error {
	// Calling the hook
	n.TestInterceptorMu.RLock()
	if n.TestCellInterceptor != nil {
		n.TestCellInterceptor(&cell)
	}
	n.TestInterceptorMu.RUnlock()

	encoded, err := n.EncodeCell(cell)
	if err != nil {
		return err
	}

	msg := TorCellMessage{Raw: encoded}
	if n.conf.MessageRegistry == nil {
		return errors.New("message registry not initialized")
	}

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		return err
	}

	// If congestion control is enabled, use the scheduler
	if n.congestionControl.Load() && n.scheduler != nil {
		isBulk := false
		if len(circ) > 0 && circ[0] != nil {
			switch c := circ[0].(type) {
			case *Circuit:
				c.CryptoMu.Lock()
				c.updatePriority()
				isBulk = c.IsBulk
				c.CryptoMu.Unlock()
			case *ClientCircuit:
				c.StatsMu.Lock()
				c.updatePriority()
				isBulk = c.IsBulk
				c.StatsMu.Unlock()
			case *Stream:
				c.mu.Lock()
				c.updatePriority()
				isBulk = c.IsBulk
				c.mu.Unlock()
			}
		}

		n.scheduler.Schedule(transportMsg, dest, isBulk)
		return nil
	}

	return n.Unicast(dest, transportMsg)
}

// -----------------------------------------------------------------------------
// Client-side (OP) Circuit Building

// BuildCircuit creates a 3-hop circuit through the specified nodes.
// hops must contain exactly 3 addresses: [Guard, Middle, Exit].
// Blocks until the circuit is ready or timeout.
func (n *node) BuildCircuit(hops [3]string, timeout time.Duration) (uint16, error) {
	if n.conf.Socket == nil {
		return 0, errors.New("socket not initialized")
	}

	// Generate a unique circuit ID for the first hop
	circID := n.GenerateClientCircuitID()

	// Create the client circuit state
	cc := &ClientCircuit{
		CircID:                circID,
		Hops:                  hops,
		State:                 CircuitStateCreating,
		ReadyChan:             make(chan struct{}),
		PackageWindow:         DefaultWindowSize,
		DeliverWindow:         DefaultWindowSize,
		ForwardPackageWindow:  DefaultWindowSize,
		BackwardDeliverWindow: DefaultWindowSize,
	}
	cc.WindowCond = sync.NewCond(&n.clientCircuitsMu)

	n.clientCircuitsMu.Lock()
	n.clientCircuits[circID] = cc
	n.clientCircuitsMu.Unlock()

	// Track this circuit ID
	n.addCircuitID(circID)

	n.log.Info().
		Uint16("circID", circID).
		Str("guard", hops[0]).
		Str("middle", hops[1]).
		Str("exit", hops[2]).
		Msg("Building 3-hop circuit")

	// Obtain the next hop's public key for encryption
	// ASSUMPTION: The public onion key is already available in the map
	// It is necessary to populate the public key map before calling BuildCircuit
	nextHopPublicOnionKey, err := n.GetPeerPublicOnionKey(hops[0])
	n.log.Info().Str("guard", hops[0]).Msg("Obtained guard's public onion key")
	if err != nil {
		n.CleanupClientCircuit(circID)
		return 0, fmt.Errorf("failed to get onion key for guard %s: %w", hops[0], err)
	}

	// Call BeginHandshake to prepare the payload and get the handshake state for the current circuit
	n.log.Info().Str("guard", hops[0]).Msg("Beginning handshake with guard")
	handshakePayload, diffieHellmanHandshakePair, err := n.BeginHandshake(nextHopPublicOnionKey)
	if err != nil {
		n.CleanupClientCircuit(circID)
		return 0, fmt.Errorf("failed to begin handshake with guard %s: %w", hops[0], err)
	}

	// Store the handshake state for later use when processing the CREATED cell
	n.diffieHellmanHandshakePairs[circID] = diffieHellmanHandshakePair

	// Create the payload by copying handshake data
	var payload [CellPayloadLen]byte
	copy(payload[:], handshakePayload)

	createCell := Cell{
		CircID:  circID,
		Command: Create,
		Payload: payload,
	}

	// Send Create to the Guard node
	n.log.Info().Str("guard", hops[0]).Msg("Sending Create to guard")
	err = n.SendCell(hops[0], createCell)
	if err != nil {
		n.CleanupClientCircuit(circID)
		return 0, fmt.Errorf("failed to send Create to guard: %w", err)
	}

	// Wait for the circuit to be ready or timeout
	select {
	case <-cc.ReadyChan:
		if cc.Error != nil {
			return 0, cc.Error
		}
		return circID, nil
	case <-time.After(timeout):
		n.CleanupClientCircuit(circID)
		return 0, errors.New("circuit creation timed out")
	case <-n.stopCh:
		n.CleanupClientCircuit(circID)
		return 0, errors.New("node stopped during circuit creation")
	}
}

// GenerateClientCircuitID generates a unique circuit ID for client circuits
func (n *node) GenerateClientCircuitID() uint16 {
	n.clientCircuitsMu.RLock()
	defer n.clientCircuitsMu.RUnlock()

	for {
		id := uint16(rand.Intn(65535) + 1)
		exists := false
		_, exists = n.clientCircuits[id]
		if !exists {
			return id
		}
	}
}

// CleanupClientCircuit removes a client circuit from the map
func (n *node) CleanupClientCircuit(circID uint16) {
	n.clientCircuitsMu.Lock()
	delete(n.clientCircuits, circID)
	n.clientCircuitsMu.Unlock()

	// Clean up the handshake state to avoid memory leaks
	n.cryptoStatesMu.Lock()
	delete(n.diffieHellmanHandshakePairs, circID)
	n.cryptoStatesMu.Unlock()
}

// HandleCreatedAsOP handles a Created cell when this node is the OP
func (n *node) HandleCreatedAsOP(cell Cell, src string) error {
	n.clientCircuitsMu.Lock()
	defer n.clientCircuitsMu.Unlock()

	// Complete the handshake as the initiator
	n.log.Info().Str("src", src).Uint16("circID", cell.CircID).Msg("Completing handshake as initiator")
	circuitCryptoState, err := n.FinishHandshakeAsInitiator(n.diffieHellmanHandshakePairs[cell.CircID], cell.Payload[:])
	if err != nil {
		return fmt.Errorf("failed to complete handshake for circuit %d from %s: %w", cell.CircID, src, err)
	}

	// Store the crypto state for this circuit
	n.circuitCryptoStates[cell.CircID] = []*CircuitCryptoState{circuitCryptoState}
	// At this point the handshake is complete and keys are derived

	cc, exists := n.clientCircuits[cell.CircID]
	if !exists {
		return fmt.Errorf("received Created for unknown client circuit %d", cell.CircID)
	}

	n.log.Info().Str("peer", src).Uint16("circID", cell.CircID).Msg("Circuit established")

	// Verify it came from the expected hop
	if cc.State == CircuitStateCreating && src == cc.Hops[0] {
		// Guard responded, now extend to Middle
		cc.State = CircuitStateExtending1
		n.log.Info().Uint16("circID", cell.CircID).Msg("Guard connected, extending to Middle")

		return n.SendExtendToHop(cc, cc.Hops[1])
	}

	return fmt.Errorf("unexpected Created in state %d from %s", cc.State, src)
}

// HandleRelayExtendedAsOP handles a RelayExtended cell when this node is the OP
func (n *node) HandleRelayExtendedAsOP(relayCell RelayCell) error {
	n.clientCircuitsMu.Lock()
	defer n.clientCircuitsMu.Unlock()

	circID := relayCell.CircID
	cc, exists := n.clientCircuits[circID]
	if !exists {
		return fmt.Errorf("received RelayExtended for unknown client circuit %d", circID)
	}

	n.log.Info().Uint16("circID", circID).Msg("Handling RelayExtended in OP")

	switch cc.State {
	case CircuitStateExtending1:
		// Middle responded, now extend to Exit
		return n.handleMiddleExtended(circID, cc, relayCell)

	case CircuitStateExtending2:
		// Exit responded, complete the handshake and circuit is ready!
		return n.handleExitExtended(circID, cc, relayCell)

	case CircuitStateCreating, CircuitStateReady, CircuitStateFailed:
		return fmt.Errorf("unexpected RelayExtended in state %d", cc.State)

	default:
		return fmt.Errorf("unexpected RelayExtended in state %d", cc.State)
	}
}

// HandleRelayBeginAsOP handles a RELAY_BEGIN when acting as Bob in hidden services
// RelayBegin is reaching Bob .
// But Bob is a client node and does not expect to receive RelayBegin messages.
// It only expects RelayConnected messages.
// But with hidden services, Bob is technically a Server (Exit) node.
// So there should be a way to process RelayBegin at Clients and send back RelayConnected back to Alice.
func (n *node) HandleRelayBeginAsOP(relay RelayCell, cc *ClientCircuit) error {
	n.log.Warn().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Bool("isRendezvous", cc.IsRendezvous).
		Int("numCryptoStates", len(n.circuitCryptoStates[cc.CircID])).
		Str("targetAddr", string(relay.Data)).
		Msg("[DEBUG] HandleRelayBeginAsOP called")

	// Decrypt the relay cell data through crypto layers
	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[cc.CircID]
	n.cryptoStatesMu.Unlock()

	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", cc.CircID)
	}

	// Decrypt through crypto layers
	var plaintext []byte
	if cc.IsRendezvous {
		// For rendezvous: RP decrypts its layer before forwarding, so Bob only needs to
		// decrypt Guard backward, Middle backward, and SharedSecret forward
		n.log.Debug().Msg("[BOB] Decrypting rendezvous RELAY_BEGIN: Guard bwd, Middle bwd, SharedSecret fwd (RP already decrypted)")
		plaintext = relay.Data
		plaintext, _ = DecryptRelayCellAtHop(cryptoStates[0], DirectionBackward, plaintext, [6]byte{})
		plaintext, _ = DecryptRelayCellAtHop(cryptoStates[1], DirectionBackward, plaintext, [6]byte{})
		plaintext, _ = DecryptRelayCellAtHop(cryptoStates[3], DirectionForward, plaintext, [6]byte{})
	} else {
		// Regular circuit: decrypt through all crypto states
		plaintext = decryptRelayDataAtClient(cryptoStates, relay.Data)
	}

	// Open a brand new UDP socket using your transport layer
	transportSocket := udpFac()
	socket, err := transportSocket.CreateSocket(":0")
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Hidden service failed to open socket. Sending RelayEnd")
		return n.SendRelayEndAsOP(cc.CircID, relay.StreamID)
	}

	stream := &Stream{
		ID:            relay.StreamID,
		CircID:        cc.CircID,
		State:         StreamOpen,
		TargetAddr:    string(plaintext),
		Sock:          socket,
		PackageWindow: DefaultStreamWindowSize,
		DeliverWindow: DefaultStreamWindowSize,
	}
	stream.WindowCond = sync.NewCond(&stream.mu)

	n.AddStream(cc.CircID, stream)
	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Msg("Hidden service added stream to rendezvous circuit")

	// Send RELAY_CONNECTED back to Alice
	return n.SendRelayConnectedAsOP(cc, relay.StreamID)
}

// SendRelayConnectedAsOP sends RELAY_CONNECTED from Bob back to Alice
func (n *node) SendRelayConnectedAsOP(cc *ClientCircuit, streamID uint16) error {
	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", streamID).
		Msg("Sending RelayConnected as Bob")

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[cc.CircID]
	n.cryptoStatesMu.Unlock()

	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", cc.CircID)
	}

	var encrypted []byte
	var digest [6]byte
	var err error

	// Always encrypt through all crypto layers
	// This will be encrypted backward as it travels through Bob's circuit to the RP
	encrypted, digest, err = EncryptRelayCellThroughCircuit(cryptoStates, []byte{})

	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", cc.CircID).
			Uint16("streamID", streamID).
			Msg("Failed to encrypt RelayConnected payload")
		return err
	}

	relayCell := RelayCell{
		CircID:   cc.CircID,
		StreamID: streamID,
		Command:  RelayConnected,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}

	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", streamID).
		Msg("RelayConnected sent successfully from Bob")

	return n.SendCell(cc.Hops[0], cell, cc)
}

// SendRelayEndAsOP sends RELAY_END from Bob
func (n *node) SendRelayEndAsOP(circID, streamID uint16) error {
	n.clientCircuitsMu.RLock()
	cc, ok := n.clientCircuits[circID]
	n.clientCircuitsMu.RUnlock()

	if !ok {
		return fmt.Errorf("circuit %d not found", circID)
	}

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[circID]
	n.cryptoStatesMu.Unlock()

	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", circID)
	}

	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, []byte{})
	if err != nil {
		return err
	}

	relayCell := RelayCell{
		CircID:   circID,
		StreamID: streamID,
		Command:  RelayEnd,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}

	return n.SendCell(cc.Hops[0], cell, cc)
}

// handleMiddleExtended processes RELAY_EXTENDED from the middle hop
func (n *node) handleMiddleExtended(circID uint16, cc *ClientCircuit, relayCell RelayCell) error {
	n.log.Info().Uint16("circID", circID).Msg("Middle Responded, Finishing handshake for Middle")

	// Decrypt the payload through guard layer
	cryptoStates := n.circuitCryptoStates[cc.CircID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states found for circuit %d", circID)
	}

	cc.CryptoMu.Lock()
	relayExtendedPayloadPlainText, _ := DecryptRelayCellAtHop(
		cryptoStates[0],
		DirectionBackward,
		relayCell.Data,
		[6]byte{}, // dummy digest as verification in backward direction is not needed
	)
	cc.CryptoMu.Unlock()

	// Complete the handshake as the initiator for the Middle node
	circuitCryptoState, err := n.FinishHandshakeAsInitiator(
		n.diffieHellmanHandshakePairs[cc.CircID],
		relayExtendedPayloadPlainText,
	)
	if err != nil {
		return fmt.Errorf("failed to complete handshake for circuit %d at Middle: %w", circID, err)
	}

	// Append the middle hop crypto state to the slice
	n.circuitCryptoStates[cc.CircID] = append(n.circuitCryptoStates[cc.CircID], circuitCryptoState)

	cc.State = CircuitStateExtending2
	n.log.Info().Uint16("circID", circID).Msg("Middle connected, extending to Exit")
	return n.SendExtendToHop(cc, cc.Hops[2])
}

// handleExitExtended processes RELAY_EXTENDED from the exit hop
func (n *node) handleExitExtended(circID uint16, cc *ClientCircuit, relayCell RelayCell) error {
	n.log.Info().Uint16("circID", circID).Msg("Exit Responded, Finishing handshake for Exit")

	// Decrypt the RELAY_EXTENDED payload through the already established hops
	cryptoStates := n.circuitCryptoStates[cc.CircID]
	if len(cryptoStates) < 2 {
		return fmt.Errorf("insufficient crypto states (%d) for circuit %d", len(cryptoStates), circID)
	}

	// Decrypt through middle and guard layers to get exit's handshake response
	cc.CryptoMu.Lock()
	relayExtendedPayloadPlainText, _ := DecryptRelayCellAtHop(
		cryptoStates[1],
		DirectionBackward,
		relayCell.Data,
		[6]byte{}, // dummy digest
	)

	relayExtendedPayloadPlainText, _ = DecryptRelayCellAtHop(
		cryptoStates[0],
		DirectionBackward,
		relayExtendedPayloadPlainText,
		[6]byte{}, // dummy digest
	)
	cc.CryptoMu.Unlock()

	// Complete the handshake as the initiator for the Exit node
	circuitCryptoState, err := n.FinishHandshakeAsInitiator(
		n.diffieHellmanHandshakePairs[cc.CircID],
		relayExtendedPayloadPlainText,
	)
	if err != nil {
		return fmt.Errorf("failed to complete handshake for circuit %d at Exit: %w", circID, err)
	}

	// Append the exit hop crypto state to the slice
	n.circuitCryptoStates[cc.CircID] = append(n.circuitCryptoStates[cc.CircID], circuitCryptoState)

	cc.State = CircuitStateReady
	n.log.Info().Uint16("circID", circID).Msg("Circuit fully established!")
	close(cc.ReadyChan)
	return nil
}

// HandleRelayConnectedAsOP sets the stream as open
func (n *node) HandleRelayConnectedAsOP(relay RelayCell, cc *ClientCircuit) error {
	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Bool("isRendezvous", cc.IsRendezvous).
		Msg("Handling RelayConnected as OP")

	// For rendezvous circuits, decrypt through all layers to synchronize cipher state
	if cc.IsRendezvous && len(relay.Data) > 0 {
		n.cryptoStatesMu.Lock()
		cryptoStates := n.circuitCryptoStates[cc.CircID]
		n.cryptoStatesMu.Unlock()

		if len(cryptoStates) > 0 {
			// Decrypt through all layers to keep cipher in sync
			_ = decryptRelayDataAtClient(cryptoStates, relay.Data)
		}
	}

	// First check if this is a pending stream
	pendingStream := n.getPendingStream(cc.CircID, relay.StreamID)
	if pendingStream != nil {
		// Move stream from pending to active
		n.removePendingStream(cc.CircID, relay.StreamID)
		pendingStream.mu.Lock()
		pendingStream.State = StreamOpen
		pendingStream.mu.Unlock()
		n.AddStream(cc.CircID, pendingStream)

		n.log.Info().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Stream moved from pending to active and is now Open")
		return nil
	}

	// Otherwise, check if it's already an active stream (shouldn't normally happen)
	stream := n.GetStream(cc.CircID, relay.StreamID)
	if stream == nil {
		n.log.Error().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Received RelayConnected for unknown stream")
		return fmt.Errorf("unknown stream %d", relay.StreamID)
	}

	stream.mu.RLock()
	prevState := stream.State
	stream.mu.RUnlock()

	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Str("previousState", streamStateToString(prevState)).
		Msg("Stream found, transitioning to Open")

	// receive connected reply, we can now set the stream state as open
	stream.mu.Lock()
	stream.State = StreamOpen
	stream.mu.Unlock()
	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Msg("Stream is now Open and ready for use")
	return nil
}

// HandleRelayEndAsOP sets the stream as closed
func (n *node) HandleRelayEndAsOP(relay RelayCell, cc *ClientCircuit) error {
	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Msg("Handling RelayEnd as OP")

	streams := n.GetCircuitStreams(cc.CircID)
	stream := streams.Streams[relay.StreamID]

	if stream == nil {
		n.log.Error().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Received RelayEnd for unknown stream")
		return fmt.Errorf("unknown stream %d", relay.StreamID)
	}

	stream.mu.RLock()
	currentState := stream.State
	stream.mu.RUnlock()

	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Str("currentState", streamStateToString(currentState)).
		Msg("Stream found, processing RelayEnd")

	// TODO: This should've been a relay teardown message instead of a relay end message
	// Relay teardown is sent if the server failed to open a TCP connection to the target
	// This creates a single-handshake instead of a two-handshake close
	// For now, we handle it as a normal RelayEnd

	// Peer asked to close the stream
	if currentState == StreamWaitingForConnected {
		n.log.Info().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Stream was WaitingForConnected, transitioning to FullyClosed and deleting stream")
		stream.mu.Lock()
		stream.State = StreamFullyClosed
		stream.mu.Unlock()
		n.DeleteStream(cc.CircID, stream)
		n.log.Info().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Stream fully closed and deleted")
		return nil
	}

	if currentState == StreamOpen {
		n.log.Info().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Stream was Open, transitioning to HalfClosedRemote and sending RelayEnd")
		stream.mu.Lock()
		stream.State = StreamHalfClosedRemote
		stream.mu.Unlock()
		return n.SendRelayEndAsClient(cc.CircID, stream.ID)
	}

	if currentState == StreamHalfClosedLocal {
		n.log.Info().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Stream was HalfClosedLocal, transitioning to FullyClosed and closing socket")
		stream.mu.Lock()
		stream.State = StreamFullyClosed
		stream.mu.Unlock()
		if stream.Sock != nil {
			stream.Sock.Close()
		}
		n.DeleteStream(cc.CircID, stream)
		n.log.Info().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("Stream fully closed and deleted")
	}

	return nil
}

// SendRelayEndAsClient sends a RelayEnd cell as a client
func (n *node) SendRelayEndAsClient(circID, streamID uint16) error {
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Sending RelayEnd as client")

	cryptoStates := n.circuitCryptoStates[circID]
	cc := n.clientCircuits[circID]
	cc.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, []byte{})
	cc.CryptoMu.Unlock()

	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encrypt RelayEnd payload")
		return err
	}

	relayCell := RelayCell{
		CircID:   circID,
		StreamID: streamID,
		Command:  RelayEnd,
		Digest:   digest,
		Data:     encrypted,
		Length:   uint16(len(encrypted)),
	}

	cell, _ := n.EncodeRelayCell(relayCell)
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Str("guard", cc.Hops[0]).
		Msg("Sending RelayEnd to guard")
	return n.SendCell(cc.Hops[0], cell)
}

// SendExtendToHop sends a RelayExtend cell to extend the circuit to the next hop
func (n *node) SendExtendToHop(cc *ClientCircuit, nextHop string) error {
	// Flow Control: Check and decrement PackageWindow
	// NOTE: Caller (HandleCreatedAsOP or HandleRelayExtendedAsOP) already holds n.clientCircuitsMu
	if n.congestionControl.Load() {
		for cc.PackageWindow <= 0 {
			cc.WindowCond.Wait()
		}
		cc.PackageWindow--
	}

	// Get the public onion key for the next hop
	nextHopPublicKey, err := n.GetPeerPublicOnionKey(nextHop)
	if err != nil {
		return fmt.Errorf("failed to get onion key for %s: %w", nextHop, err)
	}

	// Create the Diffie-Hellman handshake payload encrypted with next hop's public key
	n.log.Info().Str("nextHop", nextHop).Msg("Beginning handshake with next hop using RelayExtend")
	handshakePayload, handshakeState, err := n.BeginHandshake(nextHopPublicKey)
	if err != nil {
		return fmt.Errorf("failed to begin handshake with %s: %w", nextHop, err)
	}

	// Store the handshake state for later use when processing the EXTENDED cell
	n.cryptoStatesMu.Lock()
	n.diffieHellmanHandshakePairs[cc.CircID] = handshakeState
	n.cryptoStatesMu.Unlock()

	// Build the RELAY EXTEND payload: address length (2 bytes) + address + encrypted handshake
	// Format: [addrLen(2)][address][encryptedHandshake]
	addrBytes := []byte(nextHop)
	addrLen := uint16(len(addrBytes))

	payloadBuf := make([]byte, 2+len(addrBytes)+len(handshakePayload))
	payloadBuf[0] = byte(addrLen >> 8)
	payloadBuf[1] = byte(addrLen)
	copy(payloadBuf[2:], addrBytes)
	copy(payloadBuf[2+len(addrBytes):], handshakePayload)

	// Encrypt the relay cell payload with onion encryption (all hops so far)
	cryptoStates := n.circuitCryptoStates[cc.CircID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states found for circuit %d", cc.CircID)
	}

	// Apply onion encryption: encrypt with each hop's key in reverse order
	cc.CryptoMu.Lock()
	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, payloadBuf)
	cc.CryptoMu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to encrypt relay cell: %w", err)
	}

	// Build the relay cell with the complete payload
	relayCell := RelayCell{
		CircID:   cc.CircID,
		StreamID: 0,
		Command:  RelayExtend,
		Digest:   digest,
		Data:     encryptedPayload,
		Length:   uint16(len(encryptedPayload)),
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}

	// Send to the Guard (first hop) - it will forward through the circuit
	return n.SendCell(cc.Hops[0], cell)
}

// DestroyCircuit starts circuit teardown from the client side
func (n *node) DestroyCircuit(circID uint16) error {
	n.clientCircuitsMu.RLock()
	_, isClientCircuit := n.clientCircuits[circID]
	n.clientCircuitsMu.RUnlock()

	if isClientCircuit {
		return destroyCircuitAsClient(n, true, circID)
	}
	return errors.New("DestroyCircuit called for unknown circuit")
}

// RelayDestroyCircuit starts circuit teardown from the relay side with source address
func (n *node) RelayDestroyCircuit(circID uint16, src string) error {
	if src == "" {
		return errors.New("source address required for relay circuit destruction")
	}
	return destroyCircuitAsRelay(n, true, circID, src)
}

// CleanupAllCircuits destroys all circuits (client and relay) managed by this node
func (n *node) CleanupAllCircuits() {
	var circID []uint16
	n.clientCircuitsMu.RLock()
	for id := range n.clientCircuits {
		circID = append(circID, id)
	}
	n.clientCircuitsMu.RUnlock()

	// Destroy all client circuits
	for _, id := range circID {
		_ = destroyCircuitAsClient(n, true, id)
	}

	var circuitKeys []circuitKey
	n.circuitsMu.RLock()
	for key := range n.circuits {
		circuitKeys = append(circuitKeys, key)
	}
	n.circuitsMu.RUnlock()

	// Destroy all relay circuits
	for _, key := range circuitKeys {
		_ = destroyCircuitAsRelay(n, true, key.InCircID, key.PrevHop)
	}

	addr := n.conf.Socket.GetAddress()
	n.log.Info().Str("peer", addr).Msg("Cleaned up all circuits")
}

// destroyCircuitAsClient starts or relays circuit teardown as a client node
func destroyCircuitAsClient(n *node, initiator bool, circID uint16) error {
	n.clientCircuitsMu.Lock()
	cc, exists := n.clientCircuits[circID]
	if !exists {
		return fmt.Errorf("cannot destroy unknown client circuit %d", circID)
	}

	if cc.State != CircuitStateReady {
		return nil // For now return if circuit not ready, later we can block (wait for circuit to be created)
	}

	if initiator {
		destroyCell := Cell{
			CircID:  circID,
			Command: Destroy,
		}
		_ = n.SendCell(cc.Hops[0], destroyCell) // Ignore send cell error, destroy circuit resources anyway
	}
	n.clientCircuitsMu.Unlock()

	n.CleanupClientCircuit(circID)
	n.CleanupStreams(circID)

	// Remove circuit ID from tracking
	n.removeCircuitID(circID)

	addr := n.conf.Socket.GetAddress()
	n.log.Info().Str("peer", addr).Uint16("circID", circID).Msg("Destroyed client")
	return nil
}

// destroyCircuitAsRelay starts or relays circuit teardown as a relay node
func destroyCircuitAsRelay(n *node, initiator bool, circID uint16, src string) error {
	n.log.Trace().Msg("destroyCircuitAsRelay: called")
	key := circuitKey{PrevHop: src, InCircID: circID}
	n.circuitsMu.RLock()
	circ, exists := n.circuits[key]
	if !exists { // Try to find circuit where src is NextHop (cell coming back)
		for k, c := range n.circuits {
			if c.NextHop == src && c.OutCircID == circID {
				circ = c
				key = k
				exists = true
				break
			}
		}
	}
	if !exists {
		n.circuitsMu.RUnlock()
		n.log.Trace().Msg("destroyCircuitAsRelay: circuit not found")
		return fmt.Errorf("cannot destroy unknown relay circuit %d from %s", circID, src)
	}

	// Send Destroy to the right direction, or to both if initiator of the teardown
	if src == circ.PrevHop || initiator {
		if circ.NextHop != "" { // If the node is the exit node do not send to NextHop
			destroyCell := Cell{
				CircID:  circ.OutCircID,
				Command: Destroy,
			}
			_ = n.SendCell(circ.NextHop, destroyCell)
		}
	}
	if src == circ.NextHop || initiator {
		destroyCell := Cell{
			CircID:  circ.InCircID,
			Command: Destroy,
		}
		_ = n.SendCell(circ.PrevHop, destroyCell)
	}
	n.circuitsMu.RUnlock()

	n.circuitsMu.Lock()
	delete(n.circuits, key)
	n.circuitsMu.Unlock()

	n.CleanupStreams(circ.InCircID)

	// Remove both InCircID and OutCircID from tracking
	n.removeCircuitID(circ.InCircID)
	if circ.OutCircID != 0 {
		n.removeCircuitID(circ.OutCircID)
	}

	addr := n.conf.Socket.GetAddress()
	n.log.Info().Str("peer", addr).Uint16("circID", circID).Msg("Destroyed relay")
	return nil
}

// HandleDestroy handles a Destroy cell
func (n *node) HandleDestroy(cell Cell, src string) error {
	n.clientCircuitsMu.RLock()
	_, isClientCircuit := n.clientCircuits[cell.CircID]
	n.clientCircuitsMu.RUnlock()

	if isClientCircuit {
		return destroyCircuitAsClient(n, false, cell.CircID)
	}
	return destroyCircuitAsRelay(n, false, cell.CircID, src)
}

// GenerateStreamID allocates a random, unused stream ID for a circuit.
func (n *node) GenerateStreamID(circID uint16) uint16 {
	table := n.GetCircuitStreams(circID)

	for {
		id := uint16(rand.Intn(65535) + 1)
		_, exists := table.Streams[id]
		if !exists {
			n.log.Debug().
				Uint16("circID", circID).
				Uint16("streamID", id).
				Msg("Generated new stream ID")
			return id
		}
	}
}

// OpenStream implements Tor.OpenStream
// opens a new stream over an existing client circuit (OP side).
func (n *node) OpenStream(circID uint16, targetAddr string) (uint16, error) {
	n.log.Info().
		Uint16("circID", circID).
		Str("targetAddr", targetAddr).
		Msg("Opening new stream over client circuit")

	// Validate circuit
	cc, cryptoStates, err := n.validateCircuitForStream(circID)
	if err != nil {
		return 0, err
	}

	// Generate stream ID and create stream object
	streamID := n.GenerateStreamID(circID)
	stream := n.createStreamObject(circID, streamID, targetAddr)

	// Store pending stream temporarily until RELAY_CONNECTED is received
	n.storePendingStream(circID, streamID, stream)

	// Send RELAY_BEGIN cell
	if err := n.sendRelayBegin(circID, streamID, targetAddr, cryptoStates, cc); err != nil {
		n.removePendingStream(circID, streamID)
		return 0, err
	}

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("RELAY_BEGIN sent successfully, stream waiting for connected")

	return streamID, nil
}

// validateCircuitForStream validates the circuit exists and is ready
func (n *node) validateCircuitForStream(circID uint16) (*ClientCircuit, []*CircuitCryptoState, error) {
	n.clientCircuitsMu.RLock()
	cc, exists := n.clientCircuits[circID]
	n.clientCircuitsMu.RUnlock()

	if !exists {
		n.log.Error().
			Uint16("circID", circID).
			Msg("Cannot open stream: unknown client circuit")
		return nil, nil, fmt.Errorf("unknown client circuit %d", circID)
	}

	if cc.State != CircuitStateReady {
		n.log.Error().
			Uint16("circID", circID).
			Int("currentState", int(cc.State)).
			Msg("Cannot open stream: circuit not ready")
		return nil, nil, fmt.Errorf("circuit %d not ready (current state is %d)", circID, cc.State)
	}

	cryptoStates := n.circuitCryptoStates[circID]
	if len(cryptoStates) == 0 {
		n.log.Error().
			Uint16("circID", circID).
			Msg("Cannot open stream: no crypto states found for circuit")
		return nil, nil, fmt.Errorf("no crypto states found for circuit %d", circID)
	}

	return cc, cryptoStates, nil
}

// createStreamObject creates a stream object without adding it to the circuit
func (n *node) createStreamObject(circID, streamID uint16, targetAddr string) *Stream {
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Str("targetAddr", targetAddr).
		Msg("Creating stream object")

	stream := &Stream{
		ID:            streamID,
		CircID:        circID,
		State:         StreamWaitingForConnected,
		TargetAddr:    targetAddr,
		PackageWindow: DefaultStreamWindowSize,
		DeliverWindow: DefaultStreamWindowSize,
	}
	stream.WindowCond = sync.NewCond(&stream.mu)

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Stream object created")

	return stream
}

// sendRelayBegin encrypts and sends a RELAY_BEGIN cell
func (n *node) sendRelayBegin(
	circID, streamID uint16,
	targetAddr string,
	cryptoStates []*CircuitCryptoState,
	cc *ClientCircuit,
) error {
	plainPayload := []byte(targetAddr)
	if cc.IsRendezvous {
		n.log.Debug().
			Uint16("circID", circID).
			Int("numCryptoStates", len(cryptoStates)).
			Msg("[ALICE] Encrypting RELAY_BEGIN for rendezvous: SharedSecret, RP, Middle, Guard (RP will decrypt its layer)")
	}
	cc.CryptoMu.Lock()
	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, plainPayload)
	cc.CryptoMu.Unlock()

	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encrypt RELAY_BEGIN payload")
		return fmt.Errorf("failed to encrypt RELAY_BEGIN payload: %w", err)
	}

	relayCell := RelayCell{
		CircID:   circID,
		StreamID: streamID,
		Command:  RelayBegin,
		Digest:   digest,
		Data:     encryptedPayload,
		Length:   uint16(len(encryptedPayload)),
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encode RELAY_BEGIN cell")
		return fmt.Errorf("failed to encode RELAY_BEGIN cell: %w", err)
	}

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Str("guard", cc.Hops[0]).
		Msg("Sending RELAY_BEGIN to guard")

	err = n.SendCell(cc.Hops[0], cell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Str("guard", cc.Hops[0]).
			Msg("Failed to send RELAY_BEGIN to guard")
		return fmt.Errorf("failed to send RELAY_BEGIN to guard: %w", err)
	}

	return nil
}

// transitionStreamToHalfClosed transitions a stream to HalfClosedLocal state
func (n *node) transitionStreamToHalfClosed(circID, streamID uint16) {
	stream := n.GetStream(circID, streamID)
	if stream != nil {
		stream.mu.RLock()
		prevState := stream.State
		stream.mu.RUnlock()

		n.log.Info().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Str("previousState", streamStateToString(prevState)).
			Msg("Stream found, transitioning to HalfClosedLocal")

		stream.mu.Lock()
		stream.State = StreamHalfClosedLocal
		stream.mu.Unlock()
	} else {
		n.log.Warn().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Stream not found when trying to close")
	}
}

// encryptAndSendRelayEnd creates and sends a RELAY_END cell
func (n *node) encryptAndSendRelayEnd(
	circID, streamID uint16,
	cryptoStates []*CircuitCryptoState,
	cc *ClientCircuit,
) error {
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Encrypting RELAY_END payload")

	// empty payload for now
	cc.CryptoMu.Lock()
	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, []byte{})
	cc.CryptoMu.Unlock()
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encrypt RELAY_END payload")
		return fmt.Errorf("failed to encrypt RELAY_END payload: %w", err)
	}

	relayCell := RelayCell{
		CircID:   circID,
		StreamID: streamID,
		Command:  RelayEnd,
		Digest:   digest,
		Data:     encryptedPayload,
		Length:   uint16(len(encryptedPayload)),
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encode RELAY_END cell")
		return fmt.Errorf("failed to encode RELAY_END cell: %w", err)
	}

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Str("guard", cc.Hops[0]).
		Msg("Sending RELAY_END to guard")

	err = n.SendCell(cc.Hops[0], cell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to send RELAY_END")
		return err
	}

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("RELAY_END sent successfully")
	return nil
}

// CloseStream implements Tor.CloseStream
// closes a stream from the OP side by sending RELAY_END.
func (n *node) CloseStream(circID, streamID uint16) error {
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Closing stream from OP side")

	// Look up the client circuit
	n.clientCircuitsMu.RLock()
	cc, exists := n.clientCircuits[circID]
	n.clientCircuitsMu.RUnlock()
	if !exists {
		n.log.Error().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Cannot close stream: unknown client circuit")
		return fmt.Errorf("unknown client circuit %d", circID)
	}

	// Transition stream state
	n.transitionStreamToHalfClosed(circID, streamID)

	// Get crypto states
	cryptoStates := n.circuitCryptoStates[circID]
	if len(cryptoStates) == 0 {
		n.log.Error().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Cannot close stream: no crypto states found for circuit")
		return fmt.Errorf("no crypto states found for circuit %d", circID)
	}

	// Encrypt and send RELAY_END
	return n.encryptAndSendRelayEnd(circID, streamID, cryptoStates, cc)
}

// GetCircuitsNbr returns the number of relay circuits (for testing)
func (n *node) GetCircuitsNbr() int {
	n.circuitsMu.RLock()
	defer n.circuitsMu.RUnlock()
	return len(n.circuits)
}

// GetClientCircuitsNbr returns the number of client circuits (for testing)
func (n *node) GetClientCircuitsNbr() int {
	n.clientCircuitsMu.RLock()
	defer n.clientCircuitsMu.RUnlock()
	return len(n.clientCircuits)
}

// SetCongestionControl enables or disables congestion control.
func (n *node) SetCongestionControl(enable bool) {
	n.congestionControl.Store(enable)
}

// HasStream reports whether a stream exists for a client circuit
func (n *node) HasStream(circID, streamID uint16) bool {
	n.streamsMu.RLock()
	defer n.streamsMu.RUnlock()

	table, ok := n.streamTables[circID]
	if !ok {
		n.log.Debug().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("HasStream: no stream table for circuit")
		return false
	}
	_, exists := table.Streams[streamID]
	n.log.Debug().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Bool("exists", exists).
		Msg("HasStream check result")
	return exists
}

// ContainsStream reports whether a relay circuit contains a given stream
func (n *node) ContainsStream(circID, streamID uint16) bool {
	n.streamsMu.RLock()
	defer n.streamsMu.RUnlock()

	table, ok := n.streamTables[circID]
	if !ok {
		n.log.Debug().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("ContainsStream: no stream table for circuit")
		return false
	}
	_, exists := table.Streams[streamID]
	n.log.Debug().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Bool("exists", exists).
		Msg("ContainsStream check result")
	return exists
}

// HasStreams returns the number of streams for a client circuit
func (n *node) HasStreams(circID uint16) (uint16, error) {
	n.streamsMu.RLock()
	defer n.streamsMu.RUnlock()

	table, ok := n.streamTables[circID]
	if !ok {
		n.log.Debug().
			Uint16("circID", circID).
			Msg("HasStreams: no stream table for circuit")
		return 0, fmt.Errorf("no stream table for circuit %d", circID)
	}

	hasStreams := len(table.Streams) > 0
	n.log.Debug().
		Uint16("circID", circID).
		Int("streamCount", len(table.Streams)).
		Bool("hasStreams", hasStreams).
		Msg("HasStreams check result")
	return uint16(len(table.Streams)), nil
}

// streamStateToString converts StreamState to a human-readable string
func streamStateToString(state StreamState) string {
	switch state {
	case StreamInit:
		return "Init"
	case StreamWaitingForConnected:
		return "WaitingForConnected"
	case StreamOpen:
		return "Open"
	case StreamHalfClosedLocal:
		return "HalfClosedLocal"
	case StreamHalfClosedRemote:
		return "HalfClosedRemote"
	case StreamFullyClosed:
		return "FullyClosed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

// addCircuitID adds a circuit ID to the tracked list
func (n *node) addCircuitID(circID uint16) {
	n.circuitIDMu.Lock()
	defer n.circuitIDMu.Unlock()

	// Check if already exists
	for _, id := range n.circuitIDs {
		if id == circID {
			return
		}
	}

	n.circuitIDs = append(n.circuitIDs, circID)
	n.log.Debug().Uint16("circID", circID).Msg("Added circuit ID to tracking list")
}

// removeCircuitID removes a circuit ID from the tracked list
func (n *node) removeCircuitID(circID uint16) {
	n.circuitIDMu.Lock()
	defer n.circuitIDMu.Unlock()

	for i, id := range n.circuitIDs {
		if id == circID {
			// Remove by replacing with last element and truncating
			n.circuitIDs[i] = n.circuitIDs[len(n.circuitIDs)-1]
			n.circuitIDs = n.circuitIDs[:len(n.circuitIDs)-1]
			n.log.Debug().Uint16("circID", circID).Msg("Removed circuit ID from tracking list")
			return
		}
	}
}

// GetCircuitIDs returns a copy of all tracked circuit IDs (for testing)
func (n *node) GetCircuitIDs() []uint16 {
	n.circuitIDMu.Lock()
	defer n.circuitIDMu.Unlock()

	// Return a copy to prevent external modification
	ids := make([]uint16, len(n.circuitIDs))
	copy(ids, n.circuitIDs)
	return ids
}

// validateStreamForSending validates that a stream exists and is in open state for sending data
func (n *node) validateStreamForSending(circID, streamID uint16) (*Stream, error) {
	stream := n.GetStream(circID, streamID)
	if stream == nil {
		n.log.Error().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Stream not found")
		return nil, fmt.Errorf("stream %d not found on circuit %d", streamID, circID)
	}

	stream.mu.RLock()
	state := stream.State
	stream.mu.RUnlock()

	if state != StreamOpen {
		n.log.Error().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Int("state", int(state)).
			Msg("Stream not in open state")
		return nil, fmt.Errorf("stream %d on circuit %d not open (state: %d)", streamID, circID, state)
	}

	return stream, nil
}

// encryptAndSendRelayData encrypts data and sends it as a RELAY_DATA cell
func (n *node) encryptAndSendRelayData(
	circID, streamID uint16,
	data []byte,
	cryptoStates []*CircuitCryptoState,
	guardAddr string,
	stream *Stream,
	cc *ClientCircuit,
) error {
	// TODO: We currently assume data always fits in a single relay cell, so
	// encrypt the whole payload at once
	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, data)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encrypt RELAY_DATA payload")
		return fmt.Errorf("failed to encrypt RELAY_DATA payload: %w", err)
	}

	relayCell := RelayCell{
		CircID:   circID,
		StreamID: streamID,
		Command:  RelayData,
		Digest:   digest,
		Data:     encryptedPayload,
		Length:   uint16(len(encryptedPayload)),
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encode RELAY_DATA cell")
		return fmt.Errorf("failed to encode RELAY_DATA cell: %w", err)
	}

	n.log.Debug().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Int("dataLen", len(data)).
		Str("guard", guardAddr).
		Msg("Sending RELAY_DATA to guard")

	// Pass stream if available, otherwise pass circuit
	if stream != nil {
		err = n.SendCell(guardAddr, cell, stream)
	} else {
		err = n.SendCell(guardAddr, cell, cc)
	}

	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Str("guard", guardAddr).
			Msg("Failed to send RELAY_DATA to guard")
		return fmt.Errorf("failed to send RELAY_DATA to guard: %w", err)
	}

	return nil
}

// storeSentData stores the sent data in the stream for testing purposes
func storeSentData(stream *Stream, data []byte) {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	stream.mu.Lock()
	stream.SentData = append(stream.SentData, dataCopy)
	stream.mu.Unlock()
}

// SendStreamData sends data over a stream using RELAY_DATA cells
func (n *node) SendStreamData(circID, streamID uint16, data []byte) error {
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Int("dataLen", len(data)).
		Msg("Sending stream data")

	// Validate stream
	stream, err := n.validateStreamForSending(circID, streamID)
	if err != nil {
		return err
	}

	// Stream-level Flow Control: Wait for PackageWindow before sending
	if n.congestionControl.Load() {
		stream.mu.Lock()
		for stream.PackageWindow <= 0 {
			stream.WindowCond.Wait()
		}
		stream.PackageWindow--
		stream.mu.Unlock()
	}

	// Get client circuit and crypto states
	n.clientCircuitsMu.Lock()
	cc, exists := n.clientCircuits[circID]
	if !exists {
		n.clientCircuitsMu.Unlock()
		return fmt.Errorf("client circuit %d not found", circID)
	}
	cryptoStates := n.circuitCryptoStates[circID]
	n.clientCircuitsMu.Unlock()

	n.log.Warn().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Bool("isRendezvous", cc.IsRendezvous).
		Int("numCryptoStates", len(cryptoStates)).
		Int("dataLen", len(data)).
		Hex("dataFirst20", data[:min(20, len(data))]).
		Msg("[ALICE] About to encrypt and send RELAY_DATA")

	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states found for circuit %d", circID)
	}

	// Encrypt and send data
	cc.CryptoMu.Lock()
	err = n.encryptAndSendRelayData(circID, streamID, data, cryptoStates, cc.Hops[0], stream, cc)
	cc.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	// Store the chunk in SentData for testing
	storeSentData(stream, data)

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Int("totalBytes", len(data)).
		Msg("Stream data sent successfully")

	return nil
}

// GetStreamPackets returns the packets sent over a stream (for testing)
func (n *node) GetStreamPackets(circID, streamID uint16) ([][]byte, error) {
	stream := n.GetStream(circID, streamID)
	if stream == nil {
		return nil, fmt.Errorf("stream %d not found on circuit %d", streamID, circID)
	}

	stream.mu.RLock()
	packets := make([][]byte, len(stream.SentData))
	for i, packet := range stream.SentData {
		packets[i] = make([]byte, len(packet))
		copy(packets[i], packet)
	}
	stream.mu.RUnlock()

	return packets, nil
}

// GetReceivedStreamPackets returns the packets received over a stream (for testing)
func (n *node) GetReceivedStreamPackets(circID, streamID uint16) ([][]byte, error) {
	stream := n.GetStream(circID, streamID)
	if stream == nil {
		return nil, fmt.Errorf("stream %d not found on circuit %d", streamID, circID)
	}

	stream.mu.RLock()
	packets := make([][]byte, len(stream.ReceivedData))
	for i, packet := range stream.ReceivedData {
		packets[i] = make([]byte, len(packet))
		copy(packets[i], packet)
	}
	stream.mu.RUnlock()

	return packets, nil
}

// validateStreamForData validates that a stream exists and is in open state
func (n *node) validateStreamForData(circID, streamID uint16) (*Stream, error) {
	stream := n.GetStream(circID, streamID)
	if stream == nil {
		n.log.Error().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Received RELAY_DATA for unknown stream")
		return nil, fmt.Errorf("unknown stream %d on circuit %d", streamID, circID)
	}

	if stream.State != StreamOpen {
		n.log.Error().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Int("state", int(stream.State)).
			Msg("Stream not in open state")
		return nil, fmt.Errorf("stream %d on circuit %d not open (state: %d)", streamID, circID, stream.State)
	}

	return stream, nil
}

// storeReceivedData stores the received data in a stream for testing purposes
func storeReceivedData(stream *Stream, data []byte) {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	stream.mu.Lock()
	stream.ReceivedData = append(stream.ReceivedData, dataCopy)
	stream.mu.Unlock()
}

// encryptAndSendReply encrypts data with a single crypto state and sends it back
func (n *node) encryptAndSendReply(
	circID, streamID uint16,
	data []byte,
	crypto *CircuitCryptoState,
	destination string,
) error {
	encryptedPayload, digest, err := EncryptRelayPayload(
		crypto,
		DirectionBackward,
		data,
	)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encrypt RELAY_DATA reply payload")
		return fmt.Errorf("failed to encrypt RELAY_DATA reply: %w", err)
	}

	replyCell := RelayCell{
		CircID:   circID,
		StreamID: streamID,
		Command:  RelayData,
		Digest:   digest,
		Data:     encryptedPayload,
		Length:   uint16(len(encryptedPayload)),
	}

	cell, err := n.EncodeRelayCell(replyCell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to encode RELAY_DATA reply cell")
		return fmt.Errorf("failed to encode RELAY_DATA reply: %w", err)
	}

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Str("destination", destination).
		Msg("Sending RELAY_DATA reply")

	err = n.SendCell(destination, cell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Failed to send RELAY_DATA reply")
		return fmt.Errorf("failed to send RELAY_DATA reply: %w", err)
	}

	return nil
}

func (n *node) sendRelaySendmeStream(circ *Circuit, streamID uint16) error {
	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", streamID).
		Msg("Sending stream RELAY_SENDME as relay")

	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	crypto := n.circuitCryptoStates[circ.InCircID][exitIdx]

	circ.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayPayload(
		crypto,
		DirectionBackward,
		[]byte{},
	)
	circ.CryptoMu.Unlock()

	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circ.InCircID).
			Msg("Failed to encrypt stream RELAY_SENDME payload")
		return err
	}

	relayCell := RelayCell{
		CircID:   circ.InCircID,
		StreamID: streamID,
		Command:  RelaySendme,
		Digest:   digest,
		Data:     encrypted,
		Length:   uint16(len(encrypted)),
	}

	cell, _ := n.EncodeRelayCell(relayCell)
	return n.SendCell(circ.PrevHop, cell, circ)
}

// handleCircuitFlowControlAtExit handles circuit-level flow control at exit node
func (n *node) handleCircuitFlowControlAtExit(circ *Circuit) {
	if !n.congestionControl.Load() {
		return
	}

	n.circuitsMu.Lock()
	circ.ForwardDeliverWindow--
	shouldSendCircuitSendme := (DefaultWindowSize - circ.ForwardDeliverWindow) >= WindowIncrement
	if shouldSendCircuitSendme {
		circ.ForwardDeliverWindow += WindowIncrement
	}
	n.circuitsMu.Unlock()

	if shouldSendCircuitSendme {
		if err := n.sendRelaySendmeToHop(circ.PrevHop, circ.InCircID); err != nil {
			n.log.Error().Err(err).Msg("Exit: Failed to send circuit SENDME to PrevHop")
		}
	}
}

// handleStreamFlowControlAtExit handles stream-level flow control at exit node
func (n *node) handleStreamFlowControlAtExit(circ *Circuit, stream *Stream, streamID uint16) {
	if !n.congestionControl.Load() {
		return
	}

	stream.mu.Lock()
	stream.DeliverWindow--
	shouldSendStreamSendme := (DefaultStreamWindowSize - stream.DeliverWindow) >= StreamWindowIncrement
	if shouldSendStreamSendme {
		stream.DeliverWindow += StreamWindowIncrement
	}
	stream.mu.Unlock()

	if shouldSendStreamSendme {
		if err := n.sendRelaySendmeStream(circ, streamID); err != nil {
			n.log.Error().Err(err).Msg("Failed to send stream RELAY_SENDME")
		}
	}
}

// sendReplyAsync sends a reply back to the client asynchronously
func (n *node) sendReplyAsync(circ *Circuit, relay RelayCell, stream *Stream) {
	go func() {
		// Stream-level Flow Control: Wait for PackageWindow before sending reply
		if n.congestionControl.Load() {
			stream.mu.Lock()
			for stream.PackageWindow <= 0 {
				stream.WindowCond.Wait()
			}
			stream.PackageWindow--
			stream.mu.Unlock()
		}

		// Send a reply back to the client with the same payload
		circ.CryptoMu.Lock()
		exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
		crypto := n.circuitCryptoStates[circ.InCircID][exitIdx]

		err := n.encryptAndSendReply(circ.InCircID, relay.StreamID, relay.Data, crypto, circ.PrevHop)
		circ.CryptoMu.Unlock()
		if err != nil {
			n.log.Error().Err(err).Msg("Failed to send reply")
			return
		}

		n.log.Info().
			Uint16("circID", circ.InCircID).
			Uint16("streamID", relay.StreamID).
			Msg("RELAY_DATA handled and reply sent successfully")
	}()
}

// handleCircuitFlowControlAtClient handles circuit-level flow control at client
func (n *node) handleCircuitFlowControlAtClient(cc *ClientCircuit) {
	if !n.congestionControl.Load() {
		return
	}

	n.clientCircuitsMu.Lock()
	cc.BackwardDeliverWindow--
	shouldSendCircuitSendme := (DefaultWindowSize - cc.BackwardDeliverWindow) >= WindowIncrement
	if shouldSendCircuitSendme {
		cc.BackwardDeliverWindow += WindowIncrement
	}
	n.clientCircuitsMu.Unlock()

	if shouldSendCircuitSendme {
		if err := n.sendRelaySendmeToHopAsOP(cc); err != nil {
			n.log.Error().Err(err).Msg("Client: Failed to send circuit SENDME to Guard")
		}
	}
}

// handleStreamFlowControlAtClient handles stream-level flow control at client
func (n *node) handleStreamFlowControlAtClient(cc *ClientCircuit, stream *Stream, streamID uint16) {
	if !n.congestionControl.Load() {
		return
	}

	stream.mu.Lock()
	stream.DeliverWindow--
	shouldSendStreamSendme := (DefaultStreamWindowSize - stream.DeliverWindow) >= StreamWindowIncrement
	if shouldSendStreamSendme {
		stream.DeliverWindow += StreamWindowIncrement
	}
	stream.mu.Unlock()

	if shouldSendStreamSendme {
		if err := n.sendRelaySendmeStreamAsOP(cc, streamID); err != nil {
			n.log.Error().Err(err).Msg("Failed to send stream RELAY_SENDME")
		}
	}
}

// sendRelaySendmeToHop sends a circuit-level RELAY_SENDME to a specific hop (for hop-by-hop flow control)
// This is used by intermediate relays to signal they can receive more cells from that hop
func (n *node) sendRelaySendmeToHop(dest string, circID uint16) error {
	n.log.Info().
		Uint16("circID", circID).
		Str("dest", dest).
		Msg("Sending circuit-level RELAY_SENDME to hop")

	// For hop-by-hop SENDME, we send it unencrypted (the neighboring hop will process it directly)
	// StreamID = 0 means circuit-level SENDME
	relayCell := RelayCell{
		CircID:   circID,
		StreamID: 0,
		Command:  RelaySendme,
		Length:   0,
		Data:     []byte{},
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}
	return n.SendCell(dest, cell)
}

// sendRelaySendmeToHopAsOP sends a circuit-level RELAY_SENDME from Client to Guard
// This is hop-by-hop flow control - the same mechanism used at every node pair
func (n *node) sendRelaySendmeToHopAsOP(cc *ClientCircuit) error {
	n.log.Info().
		Uint16("circID", cc.CircID).
		Str("guard", cc.Hops[0]).
		Msg("Client: Sending circuit-level RELAY_SENDME to Guard")

	// Circuit-level SENDME: streamID = 0, unencrypted (direct to neighbor)
	relayCell := RelayCell{
		CircID:   cc.CircID,
		StreamID: 0,
		Command:  RelaySendme,
		Length:   0,
		Data:     []byte{},
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}
	return n.SendCell(cc.Hops[0], cell)
}

// decryptRelayDataAtClient decrypts RELAY_DATA through all circuit hops
func decryptRelayDataAtClient(cryptoStates []*CircuitCryptoState, encryptedPayload []byte) []byte {
	plainPayload := encryptedPayload
	for i := range cryptoStates {
		// Decrypt one layer at a time without digest verification
		// Only the innermost (original) layer has the meaningful digest
		plainPayload, _ = DecryptRelayCellAtHop(
			cryptoStates[i],
			DirectionBackward,
			plainPayload,
			[6]byte{}, // dummy digest
		)
	}
	return plainPayload
}

// HandleRelayData handles RELAY_DATA cells at the exit node
// It stores the received data and sends a reply back to the client with the same payload
func (n *node) HandleRelayData(relay RelayCell, circ *Circuit) error {
	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", relay.StreamID).
		Int("dataLen", len(relay.Data)).
		Msg("Handling RELAY_DATA at exit node")

	// Validate stream exists and is open
	stream, err := n.validateStreamForData(circ.InCircID, relay.StreamID)
	if err != nil {
		return err
	}

	// Handle flow control
	n.handleCircuitFlowControlAtExit(circ)
	n.handleStreamFlowControlAtExit(circ, stream, relay.StreamID)

	// Store the received data for testing
	storeReceivedData(stream, relay.Data)

	n.log.Info().
		Uint16("circID", circ.InCircID).
		Uint16("streamID", relay.StreamID).
		Int("dataLen", len(relay.Data)).
		Msg("Stored received data, sending reply back to client")

	// Send reply asynchronously
	n.sendReplyAsync(circ, relay, stream)

	return nil
}

// HandleRelayDataAsOP handles RELAY_DATA cells at the client (OP)
// It decrypts and stores the received data without forwarding
func (n *node) HandleRelayDataAsOP(relay RelayCell, cc *ClientCircuit) error {
	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Int("dataLen", len(relay.Data)).
		Hex("encryptedData", relay.Data[:min(20, len(relay.Data))]).
		Msg("*** HandleRelayDataAsOP called - Handling RELAY_DATA as client")

	// Validate stream exists and is open
	stream, err := n.validateStreamForData(cc.CircID, relay.StreamID)
	if err != nil {
		return err
	}

	// Handle flow control
	n.handleCircuitFlowControlAtClient(cc)
	n.handleStreamFlowControlAtClient(cc, stream, relay.StreamID)

	// Get crypto states for decryption
	cryptoStates := n.circuitCryptoStates[cc.CircID]
	if len(cryptoStates) == 0 {
		n.log.Error().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("No crypto states found for circuit")
		return fmt.Errorf("no crypto states found for circuit %d", cc.CircID)
	}
	n.log.Warn().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Int("numCryptoStates", len(cryptoStates)).
		Bool("isRendezvous", cc.IsRendezvous).
		//Hex("encryptedFirst8", relay.Data[:8]).
		Msg("[BOB] About to decrypt RELAY_DATA")

	// Decrypt the payload
	cc.CryptoMu.Lock()
	var plainPayload []byte
	if cc.IsRendezvous {
		// For rendezvous: RP decrypts its layer, so Bob decrypts Guard bwd, Middle bwd, SharedSecret fwd
		n.log.Debug().
			Uint16("circID", cc.CircID).
			Uint16("streamID", relay.StreamID).
			Msg("[BOB] Decrypting rendezvous RELAY_DATA: Guard bwd, Middle bwd, SharedSecret fwd")
		plainPayload = relay.Data
		plainPayload, _ = DecryptRelayCellAtHop(cryptoStates[0], DirectionBackward, plainPayload, [6]byte{})
		plainPayload, _ = DecryptRelayCellAtHop(cryptoStates[1], DirectionBackward, plainPayload, [6]byte{})
		plainPayload, _ = DecryptRelayCellAtHop(cryptoStates[3], DirectionForward, plainPayload, [6]byte{})
	} else {
		// Regular circuit: decrypt through all crypto states
		plainPayload = decryptRelayDataAtClient(cryptoStates, relay.Data)
	}
	cc.CryptoMu.Unlock()

	n.log.Warn().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Int("decryptedLen", len(plainPayload)).
		Hex("decryptedFirst20", plainPayload[:min(20, len(plainPayload))]).
		Msg("[BOB] After decryption")

	// Store the decrypted data for testing
	storeReceivedData(stream, plainPayload)

	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Int("dataLen", len(plainPayload)).
		Msg("*** RELAY_DATA received and stored successfully at client")

	return nil
}

// HandleRelaySendme handles a RelaySendme command
func (n *node) HandleRelaySendme(cell RelayCell, circ *Circuit) error {
	if !n.congestionControl.Load() {
		return nil
	}

	if cell.StreamID != 0 {
		// Stream-level flow control
		stream, err := n.validateStreamForData(circ.InCircID, cell.StreamID)
		if err != nil {
			return err
		}

		stream.mu.Lock()
		stream.PackageWindow += StreamWindowIncrement
		stream.WindowCond.Broadcast()
		newWindow := stream.PackageWindow
		stream.mu.Unlock()

		n.log.Info().
			Uint16("circID", circ.InCircID).
			Uint16("streamID", cell.StreamID).
			Int("newPackageWindow", newWindow).
			Msg("Processed stream RelaySendme, increased Stream PackageWindow")
		return nil
	}

	n.circuitsMu.Lock()
	defer n.circuitsMu.Unlock()

	// Increase the PackageWindow
	circ.PackageWindow += WindowIncrement
	circ.WindowCond.Broadcast()
	n.log.Info().
		Str("peer", circ.PrevHop).
		Uint16("circID", circ.InCircID).
		Int("newPackageWindow", circ.PackageWindow).
		Msg("Processed RelaySendme, increased PackageWindow")

	return nil
}

// Stores a stream that is waiting for RELAY_CONNECTED
func (n *node) storePendingStream(circID, streamID uint16, stream *Stream) {
	n.pendingStreamsMu.Lock()
	defer n.pendingStreamsMu.Unlock()

	if n.pendingStreams[circID] == nil {
		n.pendingStreams[circID] = make(map[uint16]*Stream)
	}
	n.pendingStreams[circID][streamID] = stream

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Stored pending stream")
}

// Retrieves a pending stream
func (n *node) getPendingStream(circID, streamID uint16) *Stream {
	n.pendingStreamsMu.RLock()
	defer n.pendingStreamsMu.RUnlock()

	if n.pendingStreams[circID] == nil {
		return nil
	}
	return n.pendingStreams[circID][streamID]
}

// Removes a stream from pending list
func (n *node) removePendingStream(circID, streamID uint16) {
	n.pendingStreamsMu.Lock()
	defer n.pendingStreamsMu.Unlock()

	if n.pendingStreams[circID] != nil {
		delete(n.pendingStreams[circID], streamID)
		if len(n.pendingStreams[circID]) == 0 {
			delete(n.pendingStreams, circID)
		}
	}

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Removed pending stream")
}

// processCircuitSendmeFromPrevHop handles circuit-level SENDME from PrevHop
// Returns true if SENDME was processed, false otherwise
//
//nolint:dupl // Similar to processCircuitSendmeFromNextHop but handles different direction
func (n *node) processCircuitSendmeFromPrevHop(relayCell RelayCell, circ *Circuit) bool {
	if !n.congestionControl.Load() || relayCell.Command != RelaySendme || relayCell.StreamID != 0 {
		return false
	}

	n.circuitsMu.Lock()
	circ.BackwardPackageWindow += WindowIncrement

	// FLUSH BACKWARD QUEUE
	var packetsToSend []PacketQueueItem
	for circ.BackwardPackageWindow > 0 && len(circ.BackwardQueue) > 0 {
		packetsToSend = append(packetsToSend, circ.BackwardQueue[0])
		circ.BackwardQueue = circ.BackwardQueue[1:]
		circ.BackwardPackageWindow--
	}

	circ.BackwardWindowCond.Broadcast()
	n.circuitsMu.Unlock()

	// Send queued packets
	for _, item := range packetsToSend {
		if err := n.SendCell(item.Dest, item.Cell, circ); err != nil {
			n.log.Error().Err(err).Msg("Failed to send queued backward cell")
		}
	}

	n.log.Info().
		Uint16("circID", circ.InCircID).
		Int("newBackwardPackageWindow", circ.BackwardPackageWindow).
		Msg("Processed hop-by-hop SENDME from PrevHop, flushed BackwardQueue")
	return true
}

// processCircuitSendmeFromNextHop handles circuit-level SENDME from NextHop
// Returns true if SENDME was processed, false otherwise
//
//nolint:dupl // Similar to processCircuitSendmeFromPrevHop but handles different direction
func (n *node) processCircuitSendmeFromNextHop(relayCell RelayCell, circ *Circuit) bool {
	if !n.congestionControl.Load() || relayCell.Command != RelaySendme || relayCell.StreamID != 0 {
		return false
	}

	n.circuitsMu.Lock()
	circ.ForwardPackageWindow += WindowIncrement

	// FLUSH FORWARD QUEUE
	var packetsToSend []PacketQueueItem
	for circ.ForwardPackageWindow > 0 && len(circ.ForwardQueue) > 0 {
		packetsToSend = append(packetsToSend, circ.ForwardQueue[0])
		circ.ForwardQueue = circ.ForwardQueue[1:]
		circ.ForwardPackageWindow--
	}

	circ.ForwardWindowCond.Broadcast()
	n.circuitsMu.Unlock()

	// Send queued packets
	for _, item := range packetsToSend {
		if err := n.SendCell(item.Dest, item.Cell, circ); err != nil {
			n.log.Error().Err(err).Msg("Failed to send queued forward cell")
		}
	}

	n.log.Info().
		Uint16("circID", circ.InCircID).
		Int("newForwardPackageWindow", circ.ForwardPackageWindow).
		Msg("Processed hop-by-hop SENDME from NextHop, flushed ForwardQueue")
	return true
}

// handleForwardFlowControl handles forward direction flow control
func (n *node) handleForwardFlowControl(relayCell RelayCell, circ *Circuit) {
	isDataCell := relayCell.Command == RelayData
	if !n.congestionControl.Load() || !isDataCell {
		return
	}

	// Decrement ForwardDeliverWindow for DATA cells received from PrevHop
	n.circuitsMu.Lock()
	circ.ForwardDeliverWindow--
	shouldSendSendme := (DefaultWindowSize - circ.ForwardDeliverWindow) >= WindowIncrement
	if shouldSendSendme {
		circ.ForwardDeliverWindow += WindowIncrement
	}
	n.circuitsMu.Unlock()

	// Send SENDME back to PrevHop if threshold reached
	if shouldSendSendme {
		if err := n.sendRelaySendmeToHop(circ.PrevHop, circ.InCircID); err != nil {
			n.log.Error().Err(err).Msg("Failed to send RELAY_SENDME to PrevHop")
		}
	}
}

// handleBackwardFlowControl handles backward direction flow control
func (n *node) handleBackwardFlowControl(relayCell RelayCell, circ *Circuit) {
	isDataCell := relayCell.Command == RelayData
	if !n.congestionControl.Load() || !isDataCell {
		return
	}

	// Decrement BackwardDeliverWindow for DATA cells received from NextHop
	n.circuitsMu.Lock()
	circ.BackwardDeliverWindow--
	shouldSendSendme := (DefaultWindowSize - circ.BackwardDeliverWindow) >= WindowIncrement
	if shouldSendSendme {
		circ.BackwardDeliverWindow += WindowIncrement
	}
	n.circuitsMu.Unlock()

	// Send SENDME back to NextHop if threshold reached
	if shouldSendSendme {
		if err := n.sendRelaySendmeToHop(circ.NextHop, circ.OutCircID); err != nil {
			n.log.Error().Err(err).Msg("Failed to send RELAY_SENDME to NextHop")
		}
	}
}

// queueOrSendForward queues or sends a cell in the forward direction
func (n *node) queueOrSendForward(circ *Circuit, cell Cell, isDataCell bool) error {
	if !n.congestionControl.Load() || !isDataCell {
		return n.SendCell(circ.NextHop, cell, circ)
	}

	n.circuitsMu.Lock()
	if circ.ForwardPackageWindow <= 0 {
		// Window full? Queue it!
		circ.ForwardQueue = append(circ.ForwardQueue, PacketQueueItem{Dest: circ.NextHop, Cell: cell})
		n.circuitsMu.Unlock()
		n.log.Debug().Uint16("circID", circ.InCircID).Msg("ForwardPackageWindow exhausted, queued packet")
		return nil
	}
	circ.ForwardPackageWindow--
	n.circuitsMu.Unlock()

	return n.SendCell(circ.NextHop, cell, circ)
}

// queueOrSendBackward queues or sends a cell in the backward direction
func (n *node) queueOrSendBackward(circ *Circuit, cell Cell, isDataCell bool) error {
	if !n.congestionControl.Load() || !isDataCell {
		return n.SendCell(circ.PrevHop, cell, circ)
	}

	n.circuitsMu.Lock()
	if circ.BackwardPackageWindow <= 0 {
		// Window full? Queue it!
		circ.BackwardQueue = append(circ.BackwardQueue, PacketQueueItem{Dest: circ.PrevHop, Cell: cell})
		n.circuitsMu.Unlock()
		n.log.Debug().Uint16("circID", circ.InCircID).Msg("BackwardPackageWindow exhausted, queued packet")
		return nil
	}
	circ.BackwardPackageWindow--
	n.circuitsMu.Unlock()

	return n.SendCell(circ.PrevHop, cell, circ)
}
