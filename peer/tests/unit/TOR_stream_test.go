package unit

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
)

// Utility: build a 3-hop circuit for use by stream tests
func build3HopCircuit(t *testing.T) (client, guard, middle, exit z.TestNode, circID uint16) {
	transp := channelFac()

	client = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	guard = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	t.Cleanup(func() {
		client.Stop()
		guard.Stop()
		middle.Stop()
		exit.Stop()
	})

	// Full mesh routing
	nodes := []z.TestNode{client, guard, middle, exit}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)

	// Populate onion keys
	populateOnionKeys(nodes)

	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}

	var err error
	circID, err = client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	return client, guard, middle, exit, circID
}

// Test opening a stream end-to-end
func Test_TOR_Stream_Open_Succeeds(t *testing.T) {
	client, _, _, _, circID := build3HopCircuit(t)

	streamID, err := client.Peer.OpenStream(circID, "dummy-target:9999")
	require.NoError(t, err, "OpenStream should succeed")
	require.NotZero(t, streamID)

	time.Sleep(150 * time.Millisecond)
}

// Test closing a stream cleanly with the two-way RELAY_END handshake
func Test_TOR_Stream_Close_Clean_Shutdown(t *testing.T) {
	client, _, _, exit, circID := build3HopCircuit(t)

	streamID, err := client.Peer.OpenStream(circID, "app:7777")
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Close from the client side
	err = client.Peer.CloseStream(circID, streamID)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Confirm stream is fully removed on OP and Exit
	require.Nil(t, client.Peer.GetStream(circID, streamID), "OP stream should be removed after handshake")

	exitTable := exit.Peer.GetCircuitStreams(circID)
	require.NotContains(t, exitTable.Streams, streamID, "Exit stream should be gone")
}

// Test double-closing stream — second close must not crash
func Test_TOR_Stream_Close_Twice_NoPanic(t *testing.T) {
	client, _, _, exit, circID := build3HopCircuit(t)

	streamID, err := client.Peer.OpenStream(circID, "service:5050")
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// First close
	err = client.Peer.CloseStream(circID, streamID)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Second close: must not panic or error
	err = client.Peer.CloseStream(circID, streamID)
	require.NoError(t, err)

	exitTable := exit.Peer.GetCircuitStreams(circID)
	require.NotContains(t, exitTable.Streams, streamID)
}

// Multiple streams on the same circuit should work
func Test_TOR_Multiple_Streams_On_Same_Circuit(t *testing.T) {
	client, _, _, exit, circID := build3HopCircuit(t)

	stream1, err := client.Peer.OpenStream(circID, "host1:1111")
	require.NoError(t, err)

	stream2, err := client.Peer.OpenStream(circID, "host2:2222")
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Both streams must exist
	require.NotNil(t, client.Peer.GetStream(circID, stream1))
	require.NotNil(t, client.Peer.GetStream(circID, stream2))

	exitTable := exit.Peer.GetCircuitStreams(circID)
	require.Contains(t, exitTable.Streams, stream1)
	require.Contains(t, exitTable.Streams, stream2)
}

// If exit node fails to create socket, stream should immediately close
func Test_TOR_Stream_Open_Fails_When_Exit_Cannot_Open_Socket(t *testing.T) {
	// Replace UDP factory with a version that always errors
	orig := udpFac
	udpFac = func() transport.Transport {
		return fakeFailingTransport{}
	}
	t.Cleanup(func() { udpFac = orig })

	client, _, _, exit, circID := build3HopCircuit(t)

	_, err := client.Peer.OpenStream(circID, "nowhere:1234")
	require.Error(t, err)

	time.Sleep(150 * time.Millisecond)

	// Exit should have no streams
	exitTable := exit.Peer.GetCircuitStreams(circID)
	require.Empty(t, exitTable.Streams)
}

// Fake transport that always fails CreateSocket
type fakeFailingTransport struct{}

func (fakeFailingTransport) CreateSocket(addr string) (transport.ClosableSocket, error) {
	return nil, errors.New("socket failure")
}
func (fakeFailingTransport) Send(string, transport.Packet, time.Duration) error { return nil }
func (fakeFailingTransport) Recv(time.Duration) (transport.Packet, error) {
	return transport.Packet{}, nil
}
func (fakeFailingTransport) GetAddress() string          { return "fake" }
func (fakeFailingTransport) GetIns() []transport.Packet  { return nil }
func (fakeFailingTransport) GetOuts() []transport.Packet { return nil }
func (fakeFailingTransport) Close() error                { return nil }
