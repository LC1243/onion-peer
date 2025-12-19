package impl

import "sync"

// SecurityStats tracks security-related events for profiling and testing
type SecurityStats struct {
	DigestMismatches      uint64 // Total digest mismatches detected
	RelayDigestMismatches uint64 // Digest mismatches on relay cells (forwarded)
	DroppedCells          uint64 // Total cells dropped due to errors
	DroppedDigestMismatch uint64 // Cells dropped specifically due to digest mismatch
	DroppedNoNextHop      uint64 // Cells dropped because no next hop available
	DroppedDecryptionFail uint64 // Cells dropped due to decryption failure
	mu                    sync.RWMutex
}

// GetDigestMismatches returns the total number of digest mismatches detected
func (n *node) GetDigestMismatches() uint64 {
	n.SecurityStats.mu.RLock()
	defer n.SecurityStats.mu.RUnlock()
	return n.SecurityStats.DigestMismatches
}

// GetRelayDigestMismatches returns digest mismatches on relay cells (forwarded)
func (n *node) GetRelayDigestMismatches() uint64 {
	n.SecurityStats.mu.RLock()
	defer n.SecurityStats.mu.RUnlock()
	return n.SecurityStats.RelayDigestMismatches
}

// GetDroppedCells returns the total number of cells dropped due to errors
func (n *node) GetDroppedCells() uint64 {
	n.SecurityStats.mu.RLock()
	defer n.SecurityStats.mu.RUnlock()
	return n.SecurityStats.DroppedCells
}

// GetDroppedDigestMismatch returns cells dropped specifically due to digest mismatch
func (n *node) GetDroppedDigestMismatch() uint64 {
	n.SecurityStats.mu.RLock()
	defer n.SecurityStats.mu.RUnlock()
	return n.SecurityStats.DroppedDigestMismatch
}

// GetDroppedNoNextHop returns cells dropped because no next hop available
func (n *node) GetDroppedNoNextHop() uint64 {
	n.SecurityStats.mu.RLock()
	defer n.SecurityStats.mu.RUnlock()
	return n.SecurityStats.DroppedNoNextHop
}

// GetDroppedDecryptionFail returns cells dropped due to decryption failure
func (n *node) GetDroppedDecryptionFail() uint64 {
	n.SecurityStats.mu.RLock()
	defer n.SecurityStats.mu.RUnlock()
	return n.SecurityStats.DroppedDecryptionFail
}

// ResetSecurityStats resets all security statistics to zero
func (n *node) ResetSecurityStats() {
	n.SecurityStats.mu.Lock()
	defer n.SecurityStats.mu.Unlock()
	n.SecurityStats.DigestMismatches = 0
	n.SecurityStats.RelayDigestMismatches = 0
	n.SecurityStats.DroppedCells = 0
	n.SecurityStats.DroppedDigestMismatch = 0
	n.SecurityStats.DroppedNoNextHop = 0
	n.SecurityStats.DroppedDecryptionFail = 0
}
