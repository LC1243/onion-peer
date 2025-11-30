package peer

import (
	"time"

	"go.dedis.ch/cs438/registry"
	"go.dedis.ch/cs438/transport"
)

// Peer defines the interface of a peer in the Peerster system. It embeds all
// the interfaces that will have to be implemented.
type Peer interface {
	Service
	Messaging
	Tor
}

// Tor defines the interface for Tor-like onion routing functionality.
type Tor interface {
	// BuildCircuit creates a 3-hop circuit through the specified relay nodes.
	// hops must contain exactly 3 addresses: [Guard, Middle, Exit].
	// Blocks until the circuit is ready or timeout.
	// Returns the circuit ID on success.
	BuildCircuit(hops [3]string, timeout time.Duration) (uint16, error)

	// DestroyCircuit tears down the circuit with the given ID.
	// Returns an error if the circuit does not exist or teardown fails.
	DestroyCircuit(circuitID uint16) error

	// RelayDestroyCircuit is called by a relay to destroy a circuit initiated
	// by another peer. src is the address of the previous or next hop and allows
	// the relay to identify which circuit to destroy.
	RelayDestroyCircuit(circID uint16, src string) error

	// CleanupAllCircuits tears down all active circuits managed by the peer
	CleanupAllCircuits()

	// GetCircuitsNbr returns the number of active relay circuits managed by the peer.
	GetCircuitsNbr() int

	// GetClientCircuitsNbr returns the number of active client circuits managed by the peer.
	GetClientCircuitsNbr() int
}

// Factory is the type of function we are using to create new instances of
// peers.
type Factory func(Configuration) Peer

// Configuration if the struct that will contain the configuration argument when
// creating a peer. This struct will evolve.
type Configuration struct {
	Socket          transport.Socket
	MessageRegistry registry.Registry

	// AntiEntropyInterval is the interval at which the peer sends a status
	// message to a random neighbor. 0 means no status messages are sent.
	// Default: 0
	AntiEntropyInterval time.Duration

	// HeartbeatInterval is the interval at which a rumor with an EmptyMessage
	// is sent. At startup a rumor with EmptyMessage should always be sent. Note
	// that sending a rumor is expensive as it involve the
	// ack+status+continueMongering mechanism, which generates a lot of
	// messages. Having a low value can flood the system. A value of 0 means the
	// heartbeat mechanism is not activated, ie. no rumors with EmptyMessage are
	// sent at all.
	// Default: 0
	HeartbeatInterval time.Duration

	// AckTimeout is the timeout after which a peer consider a message lost. A
	// value of 0 represents an infinite timeout.
	// Default: 3s
	AckTimeout time.Duration

	// ContinueMongering defines the chance to send the rumor to a random peer
	// in case both peers are synced. 1 means it will continue, 0.5 means there
	// is a 50% chance, and 0 no chance.
	// Default: 0.5
	ContinueMongering float64
}
