package impl

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// Circuit represents a relay-side circuit state
type Circuit struct {
	InCircID  uint16
	PrevHop   string
	OutCircID uint16
	NextHop   string
	State     string // "pending", "established"
	// TODO: Add crypto keys here
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
	// TODO: Add session keys for each hop here
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
	relayPayloadCipherText, digest, err := EncryptRelayPayload(cryptoStates[0], DirectionBackward, cell.Payload[:RelayPayloadLen])

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
	if src == circ.PrevHop {
		return n.HandleForwardRelay(cell, circ)
	} else if src == circ.NextHop {
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
		case RelayExtend:
			return n.HandleRelayExtend(relayCell, circ)
		case RelayExtended:
			return n.HandleRelayExtended(relayCell, circ)
		default:
			return fmt.Errorf("unknown relay command %d", relayCell.Command)
		}
	}

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
	// Forward to PrevHop with the InCircID
	cell.CircID = circ.InCircID
	return n.SendCell(circ.PrevHop, cell)
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
		newID = uint16(rand.Intn(65535) + 1)
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
		relayExtendedPayloadPlainText, err := DecryptRelayPayload(cryptoStates[0], DirectionBackward, relayCell.Data, relayCell.Digest)
		if err != nil {
			return fmt.Errorf("failed to decrypt relay extended payload for circuit %d: %w", circID, err)
		}

		// Complete the handshake as the initiator for the Middle node
		circuitCryptoState, err := n.FinishHandshakeAsInitiator(n.diffieHellmanHandshakePairs[cc.CircID], relayExtendedPayloadPlainText)
		if err != nil {
			return fmt.Errorf("failed to complete handshake for circuit %d at Middle: %w", circID, err)
		}

		// Append the middle hop crypto state to the slice
		n.circuitCryptoStates[cc.CircID] = append(n.circuitCryptoStates[cc.CircID], circuitCryptoState)

		cc.State = CircuitStateExtending2
		n.log.Info().Uint16("circID", circID).Msg("Middle connected, extending to Exit")
		return n.SendExtendToHop(cc, cc.Hops[2])

	case CircuitStateExtending2:
		// Exit responded, circuit is ready!
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
