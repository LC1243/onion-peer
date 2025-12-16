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
	TorStreams
	TorHiddenServices
}

// Tor defines the interface for Tor-like onion routing functionality.
type Tor interface {
	// BuildCircuit creates a 3-hop circuit through the specified relay nodes.
	// hops must contain exactly 3 addresses: [Guard, Middle, Exit].
	// Blocks until the circuit is ready or timeout.
	// Returns the circuit ID on success.
	BuildCircuit(hops [3]string, timeout time.Duration) (uint16, error)

	// GetOnionPublicKey returns this node's public onion key.
	// Used for Tor-like circuit creation.
	GetOnionPublicKey() any

	// AddPeerOnionKey stores a remote peer's public onion key.
	// This is used to encrypt CREATE/EXTEND cells to that peer.
	AddPeerOnionKey(peerAddr string, pubKey any)
	// DestroyCircuit tears down the circuit with the given ID.
	// Returns an error if the circuit does not exist or teardown fails.
	DestroyCircuit(circuitID uint16) error

	// RelayDestroyCircuit is called by a relay to destroy a circuit initiated
	// by another peer. src is the address of the previous or next hop and allows
	// the relay to identify which circuit to destroy.
	RelayDestroyCircuit(circuitID uint16, src string) error
	// CleanupAllCircuits tears down all active circuits managed by the peer
	CleanupAllCircuits()

	// GetCircuitsNbr returns the number of active relay circuits managed by the peer.
	GetCircuitsNbr() int

	// GetClientCircuitsNbr returns the number of active client circuits managed by the peer.
	GetClientCircuitsNbr() int

	// GetCircuitIDs returns all tracked circuit IDs (for testing)
	GetCircuitIDs() []uint16

	// SetCongestionControl enables or disables congestion control.
	SetCongestionControl(enable bool)
}

// TorStreams defines the interface for Tor-like streams.
type TorStreams interface {

	// OpenStream opens a new RELAY_BEGIN stream to targetAddr over a ready circuit. Returns the new streamID.
	OpenStream(circID uint16, targetAddr string) (uint16, error)

	// CloseStream sends RELAY_END for a stream and marks it closed locally.
	CloseStream(circID, streamID uint16) error

	// HasStream reports whether a stream exists for a given circuit (client side)
	HasStream(circID, streamID uint16) bool

	// ContainsStream reports whether a relay circuit contains a given stream (relay/exit side)
	// TODO: This function serves no purpose and should be removed. HasStream does the same thing.
	ContainsStream(circID, streamID uint16) bool

	// HasStreams reports whether a circuit has any stream or is empty
	HasStreams(circID uint16) (uint16, error)

	// This function is used by the client to send data over a stream.
	SendStreamData(circID, streamID uint16, data []byte) error

	// Get the packets sent over a stream (for testing)
	GetStreamPackets(circID, streamID uint16) ([][]byte, error)

	// Get the packets received over a stream (for testing)
	GetReceivedStreamPackets(circID, streamID uint16) ([][]byte, error)
}

type TorHiddenServices interface {
	// GenerateHiddenServiceID creates a hidden service locally and returns its serviceID
	GenerateHiddenServiceID() (string, error)

	// EstablishIntroPoint establishes an intro point for a hidden service.
	// It tells the exit OR on circID that it should act as an introduction point for Bob's hidden service.
	EstablishIntroPoint(serviceID string, circID uint16, timeout time.Duration) error

	// PublishDescriptorToHSDir publishes a service descriptor to the HSDir
	PublishDescriptorToHSDir(serviceID string, introORs []string,
		lifetime time.Duration, circID uint16, timeout time.Duration) error

	// GetServiceIntroPoints returns the intro points for a hidden service
	GetServiceIntroPoints(serviceID string) []string

	// GetIntroPointCount returns the number of intro points for a hidden service
	GetIntroPointCount(serviceID string) int

	// LookupDescriptor looks up a service descriptor and returns (exists, introduction points[])
	LookupDescriptor(circID uint16, serviceID string, timeout time.Duration) (bool, []string)

	// GetIntroPointStateCount returns the number of intro points that have been established
	GetIntroPointStateCount(serviceID string) int

	// CreateHiddenService creates a full hidden service
	// Create the service locally, builds a circuit, establishes intro points, builds descriptor, publishes descriptor
	CreateHiddenService(introPoints [][3]string,
		timeout time.Duration,
		lifetime time.Duration) (string, []uint16, error)

	// DeleteHiddenService deletes a hidden service from a local node. This is enough since:
	//   - Service descriptors contain an expiration time.
	//   - Hidden Service Directories (HSDirs) automatically discard expired descriptors.
	//   - Introduction points are bound to circuits and disappear when circuits are closed.
	//
	// Therefore, deleting a hidden service is achieved by:
	//   1) Destroying all introduction point circuits.
	//   2) Removing the service from the local state so it is no longer republished.
	DeleteHiddenService(serviceID string) error

	// SetPeerAsHSDir sets the flag to indicate if the peer should act as a lookup server
	SetPeerAsHSDir(value bool)
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
