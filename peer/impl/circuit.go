package impl

import (
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

func (n *node) handleCreate(cell Cell, src string) error {
	n.circuitsMu.Lock()
	defer n.circuitsMu.Unlock()

	key := circuitKey{PrevHop: src, InCircID: cell.CircID}
	if _, exists := n.circuits[key]; exists {
		return nil
	}

	// Create new circuit
	circ := &Circuit{
		InCircID: cell.CircID,
		PrevHop:  src,
		State:    "established",
	}
	n.circuits[key] = circ

	n.log.Info().Str("src", src).Uint16("circID", cell.CircID).Msg("Created circuit")

	// Send Created
	reply := Cell{
		CircID:  cell.CircID,
		Command: Created,
	}
	return n.sendCell(src, reply)
}

func (n *node) handleCreated(cell Cell, src string) error {
	// First, check if this is for a client circuit (OP case)
	n.clientCircuitsMu.RLock()
	_, isClientCircuit := n.clientCircuits[cell.CircID]
	n.clientCircuitsMu.RUnlock()

	if isClientCircuit {
		return n.handleCreatedAsOP(cell, src)
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

	if targetCirc.PrevHop != "" {
		relayPayload := RelayCell{
			CircID:   targetCirc.InCircID,
			StreamID: 0,
			Command:  RelayExtended,
			Data:     []byte{},
		}

		cellToSend, err := n.EncodeRelayCell(relayPayload)
		if err != nil {
			return err
		}
		return n.sendCell(targetCirc.PrevHop, cellToSend)
	}

	return nil
}

func (n *node) handleRelay(cell Cell, src string) error {
	// First, check if this is for a client circuit (OP receiving relay cells)
	n.clientCircuitsMu.RLock()
	cc, isClientCircuit := n.clientCircuits[cell.CircID]
	n.clientCircuitsMu.RUnlock()

	if isClientCircuit {
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
			return n.handleRelayExtendedAsOP(cell.CircID)
		default:
			return fmt.Errorf("unexpected relay command %d for client circuit", relayCell.Command)
		}
	}

	// Otherwise, it's a relay circuit
	// Try to find circuit where src is PrevHop (cell going forward)
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
		// Cell is going forward (from PrevHop towards NextHop)
		if circ.NextHop == "" {
			// We are the end of the circuit, process the relay command
			relayCell, err := n.DecodeRelayCell(cell)
			if err != nil {
				return err
			}

			switch relayCell.Command {
			case RelayExtend:
				return n.handleRelayExtend(relayCell, circ)
			case RelayExtended:
				return n.handleRelayExtended(relayCell, circ)
			default:
				return fmt.Errorf("unknown relay command %d", relayCell.Command)
			}
		} else {
			// Forward to NextHop
			cell.CircID = circ.OutCircID
			return n.sendCell(circ.NextHop, cell)
		}
	} else if src == circ.NextHop {
		// Cell is coming back (from NextHop towards PrevHop)
		// Forward to PrevHop with the InCircID
		cell.CircID = circ.InCircID
		return n.sendCell(circ.PrevHop, cell)
	}

	return fmt.Errorf("relay cell from unexpected source %s", src)
}

func (n *node) handleRelayExtend(relayCell RelayCell, circ *Circuit) error {
	target := string(relayCell.Data)
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

	createCell := Cell{
		CircID:  newID,
		Command: Create,
	}
	return n.sendCell(target, createCell)
}

func (n *node) handleRelayExtended(relayCell RelayCell, circ *Circuit) error {
	n.log.Info().Msg("Circuit extension confirmed (RelayExtended)")
	return nil
}

func (n *node) sendCell(dest string, cell Cell) error {
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
	circID := n.generateClientCircuitID()

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

	// Step 1: Send Create to the Guard node
	createCell := Cell{
		CircID:  circID,
		Command: Create,
	}
	if err := n.sendCell(hops[0], createCell); err != nil {
		n.cleanupClientCircuit(circID)
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
		n.cleanupClientCircuit(circID)
		return 0, errors.New("circuit creation timed out")
	case <-n.stopCh:
		n.cleanupClientCircuit(circID)
		return 0, errors.New("node stopped during circuit creation")
	}
}

// generateClientCircuitID generates a unique circuit ID for client circuits
func (n *node) generateClientCircuitID() uint16 {
	n.clientCircuitsMu.RLock()
	defer n.clientCircuitsMu.RUnlock()

	for {
		id := uint16(rand.Intn(65535) + 1)
		if _, exists := n.clientCircuits[id]; !exists {
			return id
		}
	}
}

// cleanupClientCircuit removes a client circuit from the map
func (n *node) cleanupClientCircuit(circID uint16) {
	n.clientCircuitsMu.Lock()
	delete(n.clientCircuits, circID)
	n.clientCircuitsMu.Unlock()
}

// handleCreatedAsOP handles a Created cell when this node is the OP
func (n *node) handleCreatedAsOP(cell Cell, src string) error {
	n.clientCircuitsMu.Lock()
	defer n.clientCircuitsMu.Unlock()

	cc, exists := n.clientCircuits[cell.CircID]
	if !exists {
		return fmt.Errorf("received Created for unknown client circuit %d", cell.CircID)
	}

	// Verify it came from the expected hop
	if cc.State == CircuitStateCreating && src == cc.Hops[0] {
		// Guard responded, now extend to Middle
		cc.State = CircuitStateExtending1
		n.log.Info().Uint16("circID", cell.CircID).Msg("Guard connected, extending to Middle")

		return n.sendExtendToHop(cc, cc.Hops[1])
	}

	return fmt.Errorf("unexpected Created in state %d from %s", cc.State, src)
}

// handleRelayExtendedAsOP handles a RelayExtended cell when this node is the OP
func (n *node) handleRelayExtendedAsOP(circID uint16) error {
	n.clientCircuitsMu.Lock()
	defer n.clientCircuitsMu.Unlock()

	cc, exists := n.clientCircuits[circID]
	if !exists {
		return fmt.Errorf("received RelayExtended for unknown client circuit %d", circID)
	}

	switch cc.State {
	case CircuitStateExtending1:
		// Middle responded, now extend to Exit
		cc.State = CircuitStateExtending2
		n.log.Info().Uint16("circID", circID).Msg("Middle connected, extending to Exit")
		return n.sendExtendToHop(cc, cc.Hops[2])

	case CircuitStateExtending2:
		// Exit responded, circuit is ready!
		cc.State = CircuitStateReady
		n.log.Info().Uint16("circID", circID).Msg("Circuit fully established!")
		close(cc.ReadyChan)
		return nil

	default:
		return fmt.Errorf("unexpected RelayExtended in state %d", cc.State)
	}
}

// sendExtendToHop sends a RelayExtend cell to extend the circuit to the next hop
func (n *node) sendExtendToHop(cc *ClientCircuit, nextHop string) error {
	// TODO: When crypto is added, encrypt the relay cell with layers for each hop

	relayCell := RelayCell{
		CircID:   cc.CircID,
		StreamID: 0,
		Command:  RelayExtend,
		Data:     []byte(nextHop),
		Length:   uint16(len(nextHop)),
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}

	// Send to the Guard (first hop) - it will forward through the circuit
	return n.sendCell(cc.Hops[0], cell)
}
