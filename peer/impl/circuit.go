package impl

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/udp"
)

// Circuit represents a relay-side circuit state
type Circuit struct {
	InCircID  uint16
	PrevHop   string
	OutCircID uint16
	NextHop   string
	State     string // "pending", "established"
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
		InCircID: cell.CircID,
		PrevHop:  src,
		State:    "established",
	}
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
	relayPayloadCipherText, digest, err := EncryptRelayPayload(
		cryptoStates[0],
		DirectionBackward,
		cell.Payload[:RelayPayloadLen],
	)

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
		return n.SendCell(targetCirc.PrevHop, cellToSend)
	}

	return nil
}

// HandleRelay handles a Relay cell
func (n *node) HandleRelay(cell Cell, src string) error {
	// First, check if this is for a client circuit (OP receiving relay cells)
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
	default:
		return fmt.Errorf("unexpected relay command %d for client circuit", relayCell.Command)
	}
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
	// As the relay cell is always encrypted, it needs to be decrypted first before further processing
	// It goes for all kinds of relay cells: EXTEND, EXTENDED, etc.

	//  Decode the relay cell
	relayCell, err := n.DecodeRelayCell(cell)
	if err != nil {
		return err
	}

	// Get crypto state for this circuit
	cryptoStates := n.circuitCryptoStates[circ.InCircID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto state found for circuit %d", circ.InCircID)
	}

	// Decrypt one layer using our crypto state
	decryptedData, err := DecryptRelayPayload(cryptoStates[0], DirectionForward, relayCell.Data, relayCell.Digest)
	if err != nil {
		return fmt.Errorf("failed to decrypt relay cell data: %w", err)
	}

	if circ.NextHop == "" {
		// We are the end of the circuit, process the relay command
		// Replace the encrypted Data with decrypted plaintext
		relayCell.Data = decryptedData

		switch relayCell.Command {
		case RelayBegin:
			return n.HandleRelayBegin(relayCell, circ)
		case RelayEnd:
			return n.HandleRelayEnd(relayCell, circ)
		case RelayExtend:
			return n.HandleRelayExtend(relayCell, circ)
		case RelayExtended:
			return n.HandleRelayExtended(relayCell, circ)
		default:
			return fmt.Errorf("unknown relay command %d", relayCell.Command)
		}
	}

	n.log.Info().
		Uint16("circID", circ.InCircID).
		Str("nextHop", circ.NextHop).
		Msg("Forwarding Decrypted relay cell to next hop")

	// We are an intermediate node, forward the decrypted data to NextHop
	// Recompute digest for the decrypted data
	h := sha256.New()
	h.Write(cryptoStates[0].ForwardDigest)
	h.Write(decryptedData)
	hash := h.Sum(nil)
	var newDigest [6]byte
	copy(newDigest[:], hash[:6])

	// Re-encode the relay cell with the decrypted data and new digest
	relayCell.Data = decryptedData
	relayCell.Digest = newDigest
	relayCell.Length = uint16(len(decryptedData))
	relayCell.CircID = circ.OutCircID
	forwardCell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}
	return n.SendCell(circ.NextHop, forwardCell)
}

// HandleBackwardRelay handles a relay cell going backward (NextHop -> PrevHop)
func (n *node) HandleBackwardRelay(cell Cell, circ *Circuit) error {
	n.log.Info().
		Uint16("circID", circ.InCircID).
		Str("prevHop", circ.PrevHop).
		Msg("Encrypting and forwarding relay cell to previous hop")

	// Decode the relay cell to get the payload
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

	// Encrypt one layer using our crypto state (adding a layer of encryption)
	encryptedData, digest, err := EncryptRelayPayload(
		cryptoStates[0],
		DirectionBackward,
		relayCell.Data,
	)
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

	// Encode and send to previous hop
	cellToSend, err := n.EncodeRelayCell(encryptedRelayCell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circ.InCircID).
			Msg("Failed to encode encrypted relay cell")
		return err
	}

	return n.SendCell(circ.PrevHop, cellToSend)
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
		ID:         relay.StreamID,
		CircID:     circ.InCircID,
		State:      StreamWaitingForConnected,
		TargetAddr: string(relay.Data),
		Sock:       socket,
	}

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

	encrypted, digest, err := EncryptRelayPayload(
		crypto,
		DirectionBackward,
		[]byte{},
	)

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
	return n.SendCell(circ.PrevHop, cell)
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
func (n *node) SendCell(dest string, cell Cell) error {
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
		CircID:    circID,
		Hops:      hops,
		State:     CircuitStateCreating,
		ReadyChan: make(chan struct{}),
	}

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

		n.log.Info().Uint16("circID", circID).Msg("Middle Responded, Finishing handshake for Middle")

		// At this point the Payload of EXTENDED should have the second half of the handshake
		// So decrypt the payload add complete the handshake
		cryptoStates := n.circuitCryptoStates[cc.CircID]
		if len(cryptoStates) == 0 {
			return fmt.Errorf("no crypto states found for circuit %d", circID)
		}
		relayExtendedPayloadPlainText, err := DecryptRelayPayload(
			cryptoStates[0],
			DirectionBackward,
			relayCell.Data,
			relayCell.Digest,
		)
		if err != nil {
			return fmt.Errorf("failed to decrypt relay extended payload for circuit %d: %w", circID, err)
		}

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

	case CircuitStateExtending2:
		// Exit responded, complete the handshake and circuit is ready!

		n.log.Info().Uint16("circID", circID).Msg("Exit Responded, Finishing handshake for Exit")

		// Decrypt the RELAY_EXTENDED payload through the already established hops
		cryptoStates := n.circuitCryptoStates[cc.CircID]
		if len(cryptoStates) < 2 {
			return fmt.Errorf("insufficient crypto states (%d) for circuit %d", len(cryptoStates), circID)
		}

		// Decrypt through middle and guard layers to get exit's handshake response
		relayExtendedPayloadPlainText, _ := DecryptRelayCellAtHop(
			cryptoStates[1],
			DirectionBackward,
			relayCell.Data,
			relayCell.Digest,
		)

		relayExtendedPayloadPlainText, _ = DecryptRelayCellAtHop(
			cryptoStates[0],
			DirectionBackward,
			relayExtendedPayloadPlainText,
			relayCell.Digest,
		)

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

	case CircuitStateCreating, CircuitStateReady, CircuitStateFailed:
		return fmt.Errorf("unexpected RelayExtended in state %d", cc.State)

	default:
		return fmt.Errorf("unexpected RelayExtended in state %d", cc.State)
	}
}

// HandleRelayConnectedAsOP sets the stream as open
func (n *node) HandleRelayConnectedAsOP(relay RelayCell, cc *ClientCircuit) error {
	n.log.Info().
		Uint16("circID", cc.CircID).
		Uint16("streamID", relay.StreamID).
		Msg("Handling RelayConnected as OP")

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
	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, []byte{})

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
	cc := n.clientCircuits[circID]
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Str("guard", cc.Hops[0]).
		Msg("Sending RelayEnd to guard")
	return n.SendCell(cc.Hops[0], cell)
}

// SendExtendToHop sends a RelayExtend cell to extend the circuit to the next hop
func (n *node) SendExtendToHop(cc *ClientCircuit, nextHop string) error {
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
	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, payloadBuf)
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
	n.createAndAddStream(circID, streamID, targetAddr)

	// Send RELAY_BEGIN cell
	if err := n.sendRelayBegin(circID, streamID, targetAddr, cryptoStates, cc.Hops[0]); err != nil {
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

// createAndAddStream creates a stream object and adds it to the circuit
func (n *node) createAndAddStream(circID, streamID uint16, targetAddr string) {
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Str("targetAddr", targetAddr).
		Msg("Generated stream ID and creating stream object")

	stream := &Stream{
		ID:         streamID,
		CircID:     circID,
		State:      StreamWaitingForConnected,
		TargetAddr: targetAddr,
	}
	n.AddStream(circID, stream)

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Stream added to circuit")
}

// sendRelayBegin encrypts and sends a RELAY_BEGIN cell
func (n *node) sendRelayBegin(
	circID, streamID uint16,
	targetAddr string,
	cryptoStates []*CircuitCryptoState,
	guardAddr string,
) error {
	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Encrypting RELAY_BEGIN payload")

	plainPayload := []byte(targetAddr)
	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, plainPayload)
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
		Str("guard", guardAddr).
		Msg("Sending RELAY_BEGIN to guard")

	err = n.SendCell(guardAddr, cell)
	if err != nil {
		n.log.Error().
			Err(err).
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Str("guard", guardAddr).
			Msg("Failed to send RELAY_BEGIN to guard")
		return fmt.Errorf("failed to send RELAY_BEGIN to guard: %w", err)
	}

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

	cryptoStates := n.circuitCryptoStates[circID]
	if len(cryptoStates) == 0 {
		n.log.Error().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("Cannot close stream: no crypto states found for circuit")
		return fmt.Errorf("no crypto states found for circuit %d", circID)
	}

	n.log.Info().
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Msg("Encrypting RELAY_END payload")

	// empty payload for now
	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, []byte{})
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
	} else {
		n.log.Info().
			Uint16("circID", circID).
			Uint16("streamID", streamID).
			Msg("RELAY_END sent successfully")
	}
	return err
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
