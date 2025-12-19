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

// Test_TOR_Multiple_Circuits_Multiple_Streams tests creating multiple circuits
// with different topologies (non-intersecting and shared middle node) and
// opening streams on each circuit to verify full functionality.
func Test_TOR_Multiple_Circuits_Multiple_Streams(t *testing.T) {
	// Configurable number of nodes in the network
	const NUM_NODES = 12

	transp := channelFac()

	// Create many nodes
	nodes := make([]z.TestNode, NUM_NODES)
	for i := range NUM_NODES {
		node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
		nodes[i] = node
		t.Cleanup(func() { node.Stop() })
	}

	// Set up full mesh routing so all nodes can communicate
	for i := range NUM_NODES {
		for j := 0; j < NUM_NODES; j++ {
			if i != j {
				nodes[i].AddPeer(nodes[j].GetAddr())
			}
		}
	}

	time.Sleep(200 * time.Millisecond)

	// Populate onion keys for all nodes
	z.PopulateOnionKeys(nodes)

	// Define the client
	client := nodes[0]

	// Circuit 1: Non-intersecting with Circuit 2
	// Client -> Node1 -> Node2 -> Node3
	circuit1Hops := [3]string{
		nodes[1].GetAddr(),
		nodes[2].GetAddr(),
		nodes[3].GetAddr(),
	}

	// Circuit 2: Non-intersecting with Circuit 1
	// Client -> Node4 -> Node5 -> Node6
	circuit2Hops := [3]string{
		nodes[4].GetAddr(),
		nodes[5].GetAddr(),
		nodes[6].GetAddr(),
	}

	// Circuit 3: Shares middle node (Node8) with Circuit 4
	// Client -> Node7 -> Node8 -> Node9
	circuit3Hops := [3]string{
		nodes[7].GetAddr(),
		nodes[8].GetAddr(),
		nodes[9].GetAddr(),
	}

	// Circuit 4: Shares middle node (Node8) with Circuit 3
	// Client -> Node10 -> Node8 -> Node11
	circuit4Hops := [3]string{
		nodes[10].GetAddr(),
		nodes[8].GetAddr(), // Shared middle node
		nodes[11].GetAddr(),
	}

	// Build all circuits
	circID1, err := client.Peer.BuildCircuit(circuit1Hops, 5*time.Second)
	require.NoError(t, err, "Circuit 1 should build successfully")
	require.NotZero(t, circID1)
	t.Logf("Built Circuit 1 (ID: %d) through non-intersecting nodes", circID1)

	circID2, err := client.Peer.BuildCircuit(circuit2Hops, 5*time.Second)
	require.NoError(t, err, "Circuit 2 should build successfully")
	require.NotZero(t, circID2)
	t.Logf("Built Circuit 2 (ID: %d) through non-intersecting nodes", circID2)

	circID3, err := client.Peer.BuildCircuit(circuit3Hops, 5*time.Second)
	require.NoError(t, err, "Circuit 3 should build successfully")
	require.NotZero(t, circID3)
	t.Logf("Built Circuit 3 (ID: %d) with shared middle node", circID3)

	circID4, err := client.Peer.BuildCircuit(circuit4Hops, 5*time.Second)
	require.NoError(t, err, "Circuit 4 should build successfully")
	require.NotZero(t, circID4)
	t.Logf("Built Circuit 4 (ID: %d) with shared middle node", circID4)

	// Verify all circuit IDs are unique
	circuitIDs := []uint16{circID1, circID2, circID3, circID4}
	for i := range circuitIDs {
		for j := i + 1; j < len(circuitIDs); j++ {
			require.NotEqual(t, circuitIDs[i], circuitIDs[j],
				"All circuit IDs should be unique")
		}
	}

	time.Sleep(200 * time.Millisecond)

	// Open streams on each circuit
	stream1_1, err := client.Peer.OpenStream(circID1, "target:1111")
	require.NoError(t, err, "Should open stream on circuit 1")
	require.NotZero(t, stream1_1)

	stream1_2, err := client.Peer.OpenStream(circID1, "target:1112")
	require.NoError(t, err, "Should open second stream on circuit 1")
	require.NotZero(t, stream1_2)

	stream2_1, err := client.Peer.OpenStream(circID2, "target:2221")
	require.NoError(t, err, "Should open stream on circuit 2")
	require.NotZero(t, stream2_1)

	stream3_1, err := client.Peer.OpenStream(circID3, "target:3331")
	require.NoError(t, err, "Should open stream on circuit 3")
	require.NotZero(t, stream3_1)

	stream4_1, err := client.Peer.OpenStream(circID4, "target:4441")
	require.NoError(t, err, "Should open stream on circuit 4")
	require.NotZero(t, stream4_1)

	stream4_2, err := client.Peer.OpenStream(circID4, "target:4442")
	require.NoError(t, err, "Should open second stream on circuit 4")
	require.NotZero(t, stream4_2)

	time.Sleep(300 * time.Millisecond)

	// Verify all streams exist on client
	require.True(t, client.Peer.HasStream(circID1, stream1_1), "Stream 1_1 should exist")
	require.True(t, client.Peer.HasStream(circID1, stream1_2), "Stream 1_2 should exist")
	require.True(t, client.Peer.HasStream(circID2, stream2_1), "Stream 2_1 should exist")
	require.True(t, client.Peer.HasStream(circID3, stream3_1), "Stream 3_1 should exist")
	require.True(t, client.Peer.HasStream(circID4, stream4_1), "Stream 4_1 should exist")
	require.True(t, client.Peer.HasStream(circID4, stream4_2), "Stream 4_2 should exist")

	// Verify exit nodes have the streams
	// Circuit 1 exit is Node3
	exit1 := nodes[3]
	exit1CircIDs := exit1.Peer.GetCircuitIDs()
	require.GreaterOrEqual(t, len(exit1CircIDs), 1, "Exit1 should have circuits")

	var exit1CircID uint16
	for _, id := range exit1CircIDs {
		count, err := exit1.Peer.HasStreams(id)
		if err == nil && count > 0 {
			exit1CircID = id
			break
		}
	}
	require.NotZero(t, exit1CircID, "Exit1 should have a circuit with streams")
	require.True(t, exit1.Peer.ContainsStream(exit1CircID, stream1_1),
		"Exit1 should have stream 1_1")
	require.True(t, exit1.Peer.ContainsStream(exit1CircID, stream1_2),
		"Exit1 should have stream 1_2")

	// Circuit 2 exit is Node6
	exit2 := nodes[6]
	exit2CircIDs := exit2.Peer.GetCircuitIDs()
	require.GreaterOrEqual(t, len(exit2CircIDs), 1, "Exit2 should have circuits")

	var exit2CircID uint16
	for _, id := range exit2CircIDs {
		count, err := exit2.Peer.HasStreams(id)
		if err == nil && count > 0 {
			exit2CircID = id
			break
		}
	}
	require.NotZero(t, exit2CircID, "Exit2 should have a circuit with streams")
	require.True(t, exit2.Peer.ContainsStream(exit2CircID, stream2_1),
		"Exit2 should have stream 2_1")

	// Verify the shared middle node (Node8) is handling both circuits 3 and 4
	sharedMiddle := nodes[8]
	middleCircIDs := sharedMiddle.Peer.GetCircuitIDs()
	require.GreaterOrEqual(t, len(middleCircIDs), 2,
		"Shared middle node should have at least 2 circuits")
	t.Logf("Shared middle node (Node8) is relaying for %d circuits", len(middleCircIDs))

	// Test closing some streams
	err = client.Peer.CloseStream(circID1, stream1_1)
	require.NoError(t, err, "Should close stream 1_1")

	err = client.Peer.CloseStream(circID4, stream4_1)
	require.NoError(t, err, "Should close stream 4_1")

	time.Sleep(200 * time.Millisecond)

	// Verify closures
	require.False(t, client.Peer.HasStream(circID1, stream1_1),
		"Stream 1_1 should be closed")
	require.True(t, client.Peer.HasStream(circID1, stream1_2),
		"Stream 1_2 should still exist")
	require.False(t, client.Peer.HasStream(circID4, stream4_1),
		"Stream 4_1 should be closed")
	require.True(t, client.Peer.HasStream(circID4, stream4_2),
		"Stream 4_2 should still exist")

	// Test sending distinct data on each remaining stream
	// Create unique payloads for each stream
	payload1_2 := []byte("data-for-circuit1-stream2")
	payload2_1 := []byte("data-for-circuit2-stream1")
	payload3_1 := []byte("data-for-circuit3-stream1")
	payload4_2 := []byte("data-for-circuit4-stream2")

	// Send unique data on each stream
	err = client.Peer.SendStreamData(circID1, stream1_2, payload1_2)
	require.NoError(t, err, "Should send data on circuit 1, stream 1_2")

	err = client.Peer.SendStreamData(circID2, stream2_1, payload2_1)
	require.NoError(t, err, "Should send data on circuit 2, stream 2_1")

	err = client.Peer.SendStreamData(circID3, stream3_1, payload3_1)
	require.NoError(t, err, "Should send data on circuit 3, stream 3_1")

	err = client.Peer.SendStreamData(circID4, stream4_2, payload4_2)
	require.NoError(t, err, "Should send data on circuit 4, stream 4_2")

	// Wait for data to be received
	time.Sleep(300 * time.Millisecond)

	// Verify correct data reception on each stream
	packets1_2, err := client.Peer.GetReceivedStreamPackets(circID1, stream1_2)
	require.NoError(t, err, "Should get packets for stream 1_2")
	require.Equal(t, len(packets1_2), 1, "Stream 1_2 should have received data")
	require.Equal(t, payload1_2, packets1_2[0], "Stream 1_2 should receive correct data")
	t.Logf("Stream 1_2 on Circuit 1: received %d bytes", len(packets1_2[0]))

	packets2_1, err := client.Peer.GetReceivedStreamPackets(circID2, stream2_1)
	require.NoError(t, err, "Should get packets for stream 2_1")
	require.Equal(t, len(packets2_1), 1, "Stream 2_1 should have received data")
	require.Equal(t, payload2_1, packets2_1[0], "Stream 2_1 should receive correct data")
	t.Logf("Stream 2_1 on Circuit 2: received %d bytes", len(packets2_1[0]))

	packets3_1, err := client.Peer.GetReceivedStreamPackets(circID3, stream3_1)
	require.NoError(t, err, "Should get packets for stream 3_1")
	require.Equal(t, len(packets3_1), 1, "Stream 3_1 should have received data")
	require.Equal(t, payload3_1, packets3_1[0], "Stream 3_1 should receive correct data")
	t.Logf("Stream 3_1 on Circuit 3: received %d bytes", len(packets3_1[0]))

	packets4_2, err := client.Peer.GetReceivedStreamPackets(circID4, stream4_2)
	require.NoError(t, err, "Should get packets for stream 4_2")
	require.Equal(t, len(packets4_2), 1, "Stream 4_2 should have received data")
	require.Equal(t, payload4_2, packets4_2[0], "Stream 4_2 should receive correct data")
	t.Logf("Stream 4_2 on Circuit 4: received %d bytes", len(packets4_2[0]))

	// Verify no data mingling. Each stream should have received only 1 packet with its own data
	require.Equal(t, 1, len(packets1_2), "Stream 1_2 should have exactly 1 packet")
	require.Equal(t, 1, len(packets2_1), "Stream 2_1 should have exactly 1 packet")
	require.Equal(t, 1, len(packets3_1), "Stream 3_1 should have exactly 1 packet")
	require.Equal(t, 1, len(packets4_2), "Stream 4_2 should have exactly 1 packet")

	// Verify no cross-contamination: check that no stream received data meant for another
	require.NotEqual(t, payload2_1, packets1_2[0], "Stream 1_2 should not receive stream 2_1's data")
	require.NotEqual(t, payload3_1, packets1_2[0], "Stream 1_2 should not receive stream 3_1's data")
	require.NotEqual(t, payload4_2, packets1_2[0], "Stream 1_2 should not receive stream 4_2's data")

	require.NotEqual(t, payload1_2, packets2_1[0], "Stream 2_1 should not receive stream 1_2's data")
	require.NotEqual(t, payload3_1, packets2_1[0], "Stream 2_1 should not receive stream 3_1's data")
	require.NotEqual(t, payload4_2, packets2_1[0], "Stream 2_1 should not receive stream 4_2's data")

	t.Logf("Successfully tested %d circuits with multiple streams", len(circuitIDs))
	t.Logf("  - Circuits 1 and 2: Non-intersecting")
	t.Logf("  - Circuits 3 and 4: Share middle node (Node8)")
	t.Logf("  - Total streams opened: 6")
	t.Logf("  - Streams closed: 2")
	t.Logf("  - Active streams: 4")
	t.Logf("  - Data isolation verified: No cross-stream contamination")
}
