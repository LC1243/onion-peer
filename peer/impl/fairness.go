package impl

import (
	"math"
	"sync"
	"time"

	"go.dedis.ch/cs438/transport"
)

const (
	// EWMA Constants
	// We want a half-life of 30 seconds.
	// Decay factor per tick = exp(ln(0.5) / (HalfLife / TickDuration))
	EwmaHalfLife  = 30.0 * time.Second
	DecayInterval = 1 * time.Second
	BulkThreshold = 100.0
)

var (
	// Calculated decay factor
	EwmaDecayFactor = math.Exp(math.Log(0.5) / (float64(EwmaHalfLife) / float64(DecayInterval)))
)

type queuedPacket struct {
	dest string
	msg  transport.Message
}

// CircuitScheduler manages priority queues for interactive vs bulk traffic
type CircuitScheduler struct {
	node          *node
	interactiveCh chan queuedPacket
	bulkCh        chan queuedPacket
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// NewCircuitScheduler creates a new scheduler
func NewCircuitScheduler(n *node) *CircuitScheduler {
	return &CircuitScheduler{
		node:          n,
		interactiveCh: make(chan queuedPacket, 2000), // Buffer size
		bulkCh:        make(chan queuedPacket, 2000),
		stopCh:        make(chan struct{}),
	}
}

// Start starts the scheduling and decay loops
func (s *CircuitScheduler) Start() {
	s.wg.Add(1)
	go s.run()
	s.wg.Add(1)
	go s.decayLoop()
}

// Stop stops the scheduler
func (s *CircuitScheduler) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// Schedule queues a packet for sending
func (s *CircuitScheduler) Schedule(msg transport.Message, dest string, isBulk bool) {
	qPkt := queuedPacket{dest: dest, msg: msg}

	if isBulk {
		s.node.log.Debug().Str("dest", dest).Msg("Scheduling bulk packet")
		select {
		case s.bulkCh <- qPkt:
		default:
			s.node.log.Warn().Str("dest", dest).Msg("Bulk queue full, blocking")
			s.bulkCh <- qPkt
		}
	} else {
		s.node.log.Debug().Str("dest", dest).Msg("Scheduling interactive packet")
		select {
		case s.interactiveCh <- qPkt:
		default:
			s.node.log.Warn().Str("dest", dest).Msg("Interactive queue full, blocking")
			s.interactiveCh <- qPkt
		}
	}
}

// run is the main scheduling loop
func (s *CircuitScheduler) run() {
	defer s.wg.Done()
	consecutiveInteractive := 0
	const MaxConsecutiveInteractive = 5 // Send 1 bulk for every 5 interactive if saturated

	for {
		// Check if we should force a bulk packet check
		forceBulk := consecutiveInteractive >= MaxConsecutiveInteractive

		if !forceBulk {
			// Priority check: Always try to drain interactive queue first
			select {
			case <-s.stopCh:
				return
			case qPkt := <-s.interactiveCh:
				s.node.log.Debug().Str("dest", qPkt.dest).Msg("Sending interactive packet")
				_ = s.node.Unicast(qPkt.dest, qPkt.msg)
				consecutiveInteractive++
				continue // Loop back to check interactive again
			default:
				// No interactive packet ready immediately
			}
		}

		// If we forced bulk, we want to prioritize bulk.
		if forceBulk {
			select {
			case <-s.stopCh:
				return
			case qPkt := <-s.bulkCh:
				s.node.log.Debug().Str("dest", qPkt.dest).Msg("Sending bulk packet (forced)")
				_ = s.node.Unicast(qPkt.dest, qPkt.msg)
				consecutiveInteractive = 0
				continue
			default:
				// No bulk available, reset counter and continue to normal loop
				consecutiveInteractive = 0
			}
		}

		// If no interactive packet (or we forced bulk check and found none), wait for either
		select {
		case <-s.stopCh:
			return
		case qPkt := <-s.interactiveCh:
			s.node.log.Debug().Str("dest", qPkt.dest).Msg("Sending interactive packet")
			_ = s.node.Unicast(qPkt.dest, qPkt.msg)
			consecutiveInteractive++
		case qPkt := <-s.bulkCh:
			s.node.log.Debug().Str("dest", qPkt.dest).Msg("Sending bulk packet")
			_ = s.node.Unicast(qPkt.dest, qPkt.msg)
			consecutiveInteractive = 0
		}
	}
}

// decayLoop periodically decays the cell counts of all circuits
func (s *CircuitScheduler) decayLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(DecayInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.node.log.Trace().Msg("Decaying circuit priorities")
			s.decayCircuits()
		}
	}
}

func (s *CircuitScheduler) decayCircuits() {
	// Decay relay circuits
	s.node.log.Trace().Msg("Decaying relay circuits: acquiring lock")
	s.node.circuitsMu.Lock()
	s.node.log.Trace().Msg("Decaying relay circuits: lock acquired")
	for _, circ := range s.node.circuits {
		circ.CryptoMu.Lock()
		circ.decayPriority()
		circ.CryptoMu.Unlock()
	}
	s.node.circuitsMu.Unlock()
	s.node.log.Trace().Msg("Decaying relay circuits: lock released")

	// Decay client circuits
	s.node.log.Trace().Msg("Decaying client circuits: acquiring lock")
	s.node.clientCircuitsMu.Lock()
	s.node.log.Trace().Msg("Decaying client circuits: lock acquired")
	for _, circ := range s.node.clientCircuits {
		circ.StatsMu.Lock()
		circ.decayPriority()
		circ.StatsMu.Unlock()
	}
	s.node.clientCircuitsMu.Unlock()
	s.node.log.Trace().Msg("Decaying client circuits: lock released")

	// Decay streams
	s.node.log.Trace().Msg("Decaying streams: acquiring lock")
	s.node.streamsMu.Lock()
	for _, cs := range s.node.streamTables {
		for _, stream := range cs.Streams {
			stream.mu.Lock()
			stream.decayPriority()
			stream.mu.Unlock()
		}
	}
	s.node.streamsMu.Unlock()
	s.node.log.Trace().Msg("Decaying streams: lock released")
}

// updatePriority updates the EWMA count and determines if circuit is Bulk
// Should be called with lock held
func (c *Circuit) updatePriority() {
	c.CellCount++
	if c.CellCount > BulkThreshold {
		c.IsBulk = true
	}
}

// decayPriority reduces the cell count over time
// Should be called with lock held (or from decay loop which holds global lock)
func (c *Circuit) decayPriority() {
	c.CellCount *= EwmaDecayFactor
	if c.CellCount < BulkThreshold {
		c.IsBulk = false
	}
}

// Same for ClientCircuit
func (c *ClientCircuit) updatePriority() {
	c.CellCount++
	if c.CellCount > BulkThreshold {
		c.IsBulk = true
	}
}

func (c *ClientCircuit) decayPriority() {
	c.CellCount *= EwmaDecayFactor
	if c.CellCount < BulkThreshold {
		c.IsBulk = false
	}
}

// Same for Stream
func (s *Stream) updatePriority() {
	s.CellCount++
	if s.CellCount > BulkThreshold {
		s.IsBulk = true
	}
}

func (s *Stream) decayPriority() {
	s.CellCount *= EwmaDecayFactor
	if s.CellCount < BulkThreshold {
		s.IsBulk = false
	}
}
