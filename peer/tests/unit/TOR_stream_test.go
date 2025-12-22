package unit

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/udp"
)

// Build3HopCircuit builds a 3-hop circuit for use by stream tests.
func Build3HopCircuit(t *testing.T) (client, guard, middle, exit z.TestNode, circID uint16) {
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
	z.PopulateOnionKeys(nodes)

	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}

	var err error
	circID, err = client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	return client, guard, middle, exit, circID
}

// getExitCircuitIDWithStreams returns the circuit ID for the exit node that contains streams
// and fails the test if none is found.
func getExitCircuitIDWithStreams(t *testing.T, exit z.TestNode) uint16 {
	ids := exit.Peer.GetCircuitIDs()
	require.GreaterOrEqual(t, len(ids), 1, "Exit should have at least one circuit")
	for _, id := range ids {
		count, err := exit.Peer.HasStreams(id)
		if err == nil && count > 0 {
			return id
		}
	}
	t.Fatalf("Should find a circuit with streams on exit")
	return 0
}

// assertExitHasNoStreams asserts that the exit has no streams across all circuits
func assertExitHasNoStreams(t *testing.T, exit z.TestNode) {
	ids := exit.Peer.GetCircuitIDs()
	for _, id := range ids {
		count, _ := exit.Peer.HasStreams(id)
		require.Equal(t, uint16(0), count, "Exit circuit %d should have no streams", id)
	}
}

// Test opening a stream end-to-end
func Test_TOR_Stream_Open_Succeeds(t *testing.T) {
	client, _, _, _, circID := Build3HopCircuit(t)

	streamID, err := client.Peer.OpenStream(circID, "dummy-target:9999")
	require.NoError(t, err, "OpenStream should succeed")
	require.NotZero(t, streamID)

	time.Sleep(150 * time.Millisecond)
}

// Test closing a stream cleanly with the two-way RELAY_END handshake
func Test_TOR_Stream_Close_Clean_Shutdown(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	streamID, err := client.Peer.OpenStream(circID, "app:7777")
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Close from the client side
	err = client.Peer.CloseStream(circID, streamID)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Confirm stream is fully removed on OP and Exit
	require.False(t, client.Peer.HasStream(circID, streamID), "OP stream should be removed after handshake")

	// exit should have no streams
	assertExitHasNoStreams(t, exit)
}

// Test double-closing stream — second close must not crash
func Test_TOR_Stream_Close_Twice_NoPanic(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

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

	// exit should have no streams
	assertExitHasNoStreams(t, exit)
}

// Multiple streams on the same circuit should work
func Test_TOR_Multiple_Streams_On_Same_Circuit(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	stream1, err := client.Peer.OpenStream(circID, "host1:1111")
	require.NoError(t, err)

	stream2, err := client.Peer.OpenStream(circID, "host2:2222")
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Both streams must exist
	require.True(t, client.Peer.ContainsStream(circID, stream1))
	require.True(t, client.Peer.ContainsStream(circID, stream2))

	exitID := getExitCircuitIDWithStreams(t, exit)
	require.True(t, exit.Peer.ContainsStream(exitID, stream1))
	require.True(t, exit.Peer.ContainsStream(exitID, stream2))
}

func Test_TOR_Multiple_Streams_With_Single_Close(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	stream1, err := client.Peer.OpenStream(circID, "host1:1111")
	require.NoError(t, err)

	stream2, err := client.Peer.OpenStream(circID, "host2:2222")
	require.NoError(t, err)

	stream3, err := client.Peer.OpenStream(circID, "host3:3333")
	require.NoError(t, err)

	stream4, err := client.Peer.OpenStream(circID, "host4:4444")
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Close only stream1 and stream 4
	err = client.Peer.CloseStream(circID, stream1)
	require.NoError(t, err)

	err = client.Peer.CloseStream(circID, stream4)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Obtain the circuit IDs on exit node
	exitID := getExitCircuitIDWithStreams(t, exit)

	// stream1 and stream4 should be gone, stream2 and stream3 should remain on client
	require.False(t, client.Peer.HasStream(circID, stream1))
	require.True(t, client.Peer.HasStream(circID, stream2))
	require.True(t, client.Peer.HasStream(circID, stream3))
	require.False(t, client.Peer.HasStream(circID, stream4))

	// stream1 and stream4 should be gone, stream2 and stream3 should remain on exit
	require.False(t, exit.Peer.ContainsStream(exitID, stream1))
	require.True(t, exit.Peer.ContainsStream(exitID, stream2))
	require.True(t, exit.Peer.ContainsStream(exitID, stream3))
	require.False(t, exit.Peer.ContainsStream(exitID, stream4))
}

// If exit node fails to create socket, stream should immediately close
func Test_TOR_Stream_Open_Fails_When_Exit_Cannot_Open_Socket(t *testing.T) {
	// Replace UDP factory with a version that always errors
	impl.SetUDPFactory(func() transport.Transport {
		return fakeFailingTransport{}
	})
	t.Cleanup(func() { impl.SetUDPFactory(udp.NewUDP) })

	client, _, _, exit, circID := Build3HopCircuit(t)

	_, _ = client.Peer.OpenStream(circID, "nowhere:1234")

	time.Sleep(150 * time.Millisecond)

	// Exit should have no streams
	assertExitHasNoStreams(t, exit)
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

// Test_TOR_Stream_FlowControl tests that stream-level flow control works
// by sending more data than the initial stream window (500 cells).
func Test_TOR_Stream_FlowControl(t *testing.T) {
	client, _, _, _, circID := Build3HopCircuit(t)

	// Open stream
	streamID, err := client.Peer.OpenStream(circID, "dummy:1234")
	require.NoError(t, err)

	// Send 600 cells (window is 500)
	numCells := 600
	payload := []byte("stream-data")

	go func() {
		// Wait for stream to be fully open
		time.Sleep(500 * time.Millisecond)

		for i := 0; i < numCells; i++ {
			err := client.Peer.SendStreamData(circID, streamID, payload)
			require.NoError(t, err, "Failed to send cell %d", i)
			time.Sleep(1 * time.Millisecond) // Pacing
		}
	}()

	// Wait for all cells
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for all cells")
		case <-ticker.C:
			pkts, err := client.Peer.GetReceivedStreamPackets(circID, streamID)
			if err == nil && len(pkts) >= numCells {
				require.Equal(t, numCells, len(pkts))
				return
			}
		}
	}
}

// Tests bidirectional communication between client and server through the exit node.
func Test_TOR_Stream_ClientServerCommunication(t *testing.T) {
	transp := channelFac()

	// Create nodes
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	server := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	t.Cleanup(func() {
		client.Stop()
		guard.Stop()
		middle.Stop()
		exit.Stop()
		server.Stop()
	})

	// Full mesh routing
	nodes := []z.TestNode{client, guard, middle, exit, server}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)

	// Populate onion keys
	z.PopulateOnionKeys(nodes)

	// Register server with exit node for target address "host:1111"
	err := server.Peer.RegisterAsServer(exit.GetAddr(), "host:1111")
	require.NoError(t, err, "Server should register successfully")

	// Build circuit
	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}
	circID, err := client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err, "Circuit should be built successfully")

	time.Sleep(200 * time.Millisecond)

	// Open stream
	streamID, err := client.Peer.OpenStream(circID, "host:1111")
	require.NoError(t, err, "Stream should open successfully")

	// Wait longer for notifications to propagate
	time.Sleep(1 * time.Second)

	// Client sends message to server
	clientMessage := []byte("Hi Server, Client this side")
	err = client.Peer.SendStreamData(circID, streamID, clientMessage)
	require.NoError(t, err, "Client should send data successfully")

	// Wait for server to receive the message
	time.Sleep(500 * time.Millisecond)

	// Verify server received the data
	serverReceivedData, err := server.Peer.GetServerReceivedData(exit.GetAddr())
	require.NoError(t, err, "Should retrieve server received data")
	require.Equal(t, len(serverReceivedData), 1, "Server should have received at least one packet")
	require.Equal(t, clientMessage, serverReceivedData[0], "Server should receive correct message from client")

	// Server sends reply with modified message
	serverReply := []byte("Hi Client, Server this side")
	err = server.Peer.ServerSendData(exit.GetAddr(), serverReply)
	require.NoError(t, err, "Server should send reply successfully")

	// Wait for client to receive the reply
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for server reply at client")
		case <-ticker.C:
			clientReceivedData, err := client.Peer.GetReceivedStreamPackets(circID, streamID)
			if err == nil && len(clientReceivedData) >= 2 {
				// Client receives: 1) echo reply from exit node, 2) server reply
				// Check if any of the received packets matches the server reply
				foundServerReply := false
				for _, packet := range clientReceivedData {
					if string(packet) == string(serverReply) {
						foundServerReply = true
						break
					}
				}
				require.True(t, foundServerReply, "Client should receive server reply: %s", string(serverReply))
				t.Logf("Client successfully received server reply: %s", string(serverReply))
				return
			}
		}
	}
}
