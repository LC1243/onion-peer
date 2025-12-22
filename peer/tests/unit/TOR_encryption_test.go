package unit

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
)

// Test configuration constants for tampering tests
const (
	// Number of data messages to send in tampering tests
	TamperTestMessageCount = 10
	// Number of messages to tamper
	TamperTestTamperCount = 3
	// Number of streams to create in multi-stream tests
	TamperTestStreamCount = 5
	// Number of streams to tamper
	TamperTestStreamTamperCount = 2
)

// Test whether the public key addition happens correctly
func Test_TOR_KeyPopulation(t *testing.T) {
	transp := channelFac()

	// Create 4 nodes
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node3.Stop()

	node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node4.Stop()

	// Give them time to initialize
	time.Sleep(50 * time.Millisecond)

	nodes := []z.TestNode{node1, node2, node3, node4}

	// Verify each node has a public key
	for i, node := range nodes {
		pubKeyInterface := node.Peer.GetOnionPublicKey()
		require.NotNil(t, pubKeyInterface, "Node %d should have an onion public key", i)
		_, ok := pubKeyInterface.(*rsa.PublicKey)
		require.True(t, ok, "Node %d's public key should be an RSA public key", i)
	}

	// Populate keys
	z.PopulateOnionKeys(nodes)

	// Verify each node has keys for all other nodes
	for i, node := range nodes {
		for j, otherNode := range nodes {
			if i != j {
				// Try to get the other node's key from this node
				pubKeyInterface := otherNode.Peer.GetOnionPublicKey()
				require.NotNil(t, pubKeyInterface, "Node %d should have public key", j)

				// Re-add should work without error
				node.Peer.AddPeerOnionKey(otherNode.GetAddr(), pubKeyInterface)
			}
		}
	}

	t.Logf("Successfully populated onion keys for %d nodes", len(nodes))
}

// Test_TOR_KeyPopulation_WithNilKey tests that populateOnionKeys handles
// nodes without keys gracefully
func Test_TOR_KeyPopulation_WithNilKey(t *testing.T) {
	transp := channelFac()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	nodes := []z.TestNode{node1, node2}

	// This should not panic even if some nodes don't have keys
	require.NotPanics(t, func() {
		z.PopulateOnionKeys(nodes)
	}, "populateOnionKeys should handle missing keys gracefully")
}

// Tests that if a relay cell payload is tampered
// with by a malicious intermediate node, the digest mismatch is detected and the
// cell is dropped by the recipient, preventing data corruption or injection attacks.
func Test_TOR_Relay_Tampering_Detected(t *testing.T) {
	// Build a 3-hop circuit
	client, relays, exit, circID := BuildNHopCircuit(t, 3)
	middle := relays[1]

	// Open a stream
	streamID, err := client.OpenStream(circID, "host:1111")
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// Install a tamper hook on the middle node to flip one byte in RELAY cell
	// simulating a malicious intermediate node attempting to modify data in transit
	// Interception methodology suggested by ChatGPT
	type testNode interface {
		SetTestCellInterceptor(func(*impl.Cell))
	}
	middleNode, ok := middle.Peer.(testNode)
	require.True(t, ok, "Failed to cast middle node to testNode interface")

	tamperCount := 0
	middleNode.SetTestCellInterceptor(func(cell *impl.Cell) {
		// Only tamper with RELAY cells, not control cells
		if cell.Command == impl.Relay && tamperCount == 0 {
			tamperCount++
			// Flip one byte in the payload
			if len(cell.Payload) > 20 {
				cell.Payload[20] ^= 0x01
				t.Logf("Tampered with relay cell payload (flipped byte at position 20)")
			}
		}
	})

	// Send data from client through the circuit
	testData := []byte("This is test data that will be tampered within transit and should be detected")
	err = client.SendStreamData(circID, streamID, testData)
	require.NoError(t, err)

	// Wait for potential delivery
	time.Sleep(800 * time.Millisecond)

	// Exit node should NOT have received the tampered data
	// The digest mismatch should cause the cell to be dropped
	exitCircID := getExitCircuitIDWithStreams(t, exit)
	receivedPacketsExit, err := exit.GetReceivedStreamPackets(exitCircID, streamID)
	require.NoError(t, err)

	// The tampered cell should have been dropped due to digest mismatch
	// Exit should have received 0 packets
	require.Equal(t, 0, len(receivedPacketsExit),
		"Exit should NOT receive tampered data as the digest verification should reject it")

	// Verify security statistics on the exit node
	// The exit node should have detected the digest mismatch and dropped the cell
	digestMismatches := exit.GetDigestMismatches()
	droppedCells := exit.GetDroppedCells()
	droppedDigest := exit.GetDroppedDigestMismatch()

	t.Logf("Exit node security stats: DigestMismatches=%d, DroppedCells=%d, DroppedDigestMismatch=%d",
		digestMismatches, droppedCells, droppedDigest)

	// At least one digest mismatch should be detected
	require.Greater(t, digestMismatches, uint64(0),
		"Exit should have detected at least one digest mismatch")

	// Client should also not receive any echo back since exit never got the data
	time.Sleep(500 * time.Millisecond)
	receivedPacketsClient, err := client.GetReceivedStreamPackets(circID, streamID)
	require.NoError(t, err)
	require.Equal(t, 0, len(receivedPacketsClient),
		"Client should NOT receive echo of tampered data")

	t.Log("Successfully verified that tampering is detected and prevents data delivery")

	// Cleanup
	_ = client.CloseStream(circID, streamID)
	time.Sleep(100 * time.Millisecond)
	_ = client.DestroyCircuit(circID)
}

// Digest tampering attacks involve modifying the digest field
func Test_TOR_Relay_CorruptDigest_Detected(t *testing.T) {
	// Build a 3-hop circuit
	client, relays, exit, circID := BuildNHopCircuit(t, 3)
	middle := relays[1]

	// Open a stream
	streamID, err := client.OpenStream(circID, "host:2222")
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// Install a digest corruption hook on the middle node
	type testNode interface {
		SetTestCellInterceptor(func(*impl.Cell))
	}
	middleNode, ok := middle.Peer.(testNode)
	require.True(t, ok, "Failed to cast middle node to testNode interface")

	corruptCount := 0
	middleNode.SetTestCellInterceptor(func(cell *impl.Cell) {
		// Only corrupt digest in RELAY cells
		if cell.Command == impl.Relay && corruptCount == 0 {
			corruptCount++
			// Corrupt the digest field in the relay header
			if len(cell.Payload) >= 8 {
				cell.Payload[3] ^= 0xFF // Flip bits in the digest field
				t.Logf("Corrupted relay cell digest (flipped byte in digest field)")
			}
		}
	})

	// Send data from client through the circuit
	testData := []byte("Message whose disgest will be corrupted in transit")
	err = client.SendStreamData(circID, streamID, testData)
	require.NoError(t, err)

	// Wait for potential delivery
	time.Sleep(800 * time.Millisecond)

	// Exit node should NOT have received data with corrupted digest
	// The digest verification should fail and drop the cell
	exitCircID := getExitCircuitIDWithStreams(t, exit)
	receivedPacketsExit, err := exit.GetReceivedStreamPackets(exitCircID, streamID)
	require.NoError(t, err)

	// The cell with corrupted digest should have been dropped
	require.Equal(t, 0, len(receivedPacketsExit),
		"Exit should NOT receive data with corrupted digest - verification should reject it")

	// Verify security statistics
	digestMismatches := exit.GetDigestMismatches()
	droppedCells := exit.GetDroppedCells()
	droppedDigest := exit.GetDroppedDigestMismatch()

	t.Logf("Exit node security stats: DigestMismatches=%d, DroppedCells=%d, DroppedDigestMismatch=%d",
		digestMismatches, droppedCells, droppedDigest)

	// At least one digest mismatch should be detected
	require.Greater(t, digestMismatches, uint64(0),
		"Exit should have detected at least one digest mismatch from corrupted digest")

	// Client should not receive any echo back
	time.Sleep(500 * time.Millisecond)
	receivedPacketsClient, err := client.GetReceivedStreamPackets(circID, streamID)
	require.NoError(t, err)
	require.Equal(t, 0, len(receivedPacketsClient),
		"Client should NOT receive echo when digest is corrupted")

	t.Log("Successfully verified that digest corruption is detected and prevents data delivery")

	// Cleanup
	_ = client.CloseStream(circID, streamID)
	time.Sleep(100 * time.Millisecond)
	_ = client.DestroyCircuit(circID)
}

// Tampering with CREATE/CREATED control cells prevents circuit establishment due to handshake failure.
func Test_TOR_Circuit_Create_Tampering(t *testing.T) {
	transp := channelFac()

	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	t.Cleanup(func() {
		client.Stop()
		guard.Stop()
		middle.Stop()
		exit.Stop()
	})

	nodes := []z.TestNode{client, guard, middle, exit}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	// Install tamper hook on guard to corrupt CREATE cells
	type testNode interface {
		SetTestCellInterceptor(func(*impl.Cell))
	}
	guardNode, ok := guard.Peer.(testNode)
	require.True(t, ok, "Failed to cast guard node to testNode interface")

	tamperCount := 0
	guardNode.SetTestCellInterceptor(func(cell *impl.Cell) {
		// Tamper with CREATE cells
		if cell.Command == impl.Create && tamperCount == 0 {
			tamperCount++
			// Corrupt the handshake payload
			if len(cell.Payload) > 50 {
				cell.Payload[50] ^= 0xFF
				t.Logf("Tampered with CREATE cell payload")
			}
		}
	})

	// Attempt to build circuit - should fail due to tampered CREATE
	hops := []string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}
	_, err := client.Peer.BuildCircuit(hops, 3*time.Second)

	// Circuit building should fail due to handshake failure from tampered CREATE
	require.Error(t, err, "Circuit building should fail when CREATE cell is tampered")
	t.Logf("Circuit build failed as expected due to tampered CREATE cell: %v", err)

	t.Log("Successfully verified that CREATE cell tampering prevents circuit establishment")
}

// Tampering with RELAY_EXTEND/RELAY_EXTENDED cells prevents circuit extension and causes circuit building to fail.
func Test_TOR_Circuit_Extended_Tampering(t *testing.T) {
	transp := channelFac()

	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	t.Cleanup(func() {
		client.Stop()
		guard.Stop()
		middle.Stop()
		exit.Stop()
	})

	nodes := []z.TestNode{client, guard, middle, exit}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	// Install tamper hook on guard to corrupt RELAY_EXTENDED cells
	type testNode interface {
		SetTestCellInterceptor(func(*impl.Cell))
	}
	guardNode, ok := guard.Peer.(testNode)
	require.True(t, ok, "Failed to cast guard node to testNode interface")

	tamperCount := 0
	guardNode.SetTestCellInterceptor(func(cell *impl.Cell) {
		// Tamper only with RELAY_EXTENDED cells
		if cell.Command == impl.Relay && tamperCount == 0 {
			// Check the relay command byte at offset 10 in payload
			// RelayCell format: StreamID(2) + Digest(6) + Length(2) + Command(1) + Data
			if len(cell.Payload) > impl.RelayHeaderLen {
				relayCmd := cell.Payload[10]
				if relayCmd == impl.RelayExtended {
					tamperCount++
					// Tamper with the handshake data after the relay header
					cell.Payload[impl.RelayHeaderLen+10] ^= 0xFF
					t.Logf("Tampered with RELAY_EXTENDED cell")
				}
			}
		}
	})

	// Attempt to build circuit - should fail due to tampered EXTENDED
	hops := []string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}
	_, err := client.Peer.BuildCircuit(hops, 3*time.Second)

	// Circuit building should fail or timeout due to tampered EXTENDED
	require.Error(t, err, "Circuit building should fail when RELAY_EXTENDED is tampered")
	t.Logf("Circuit build failed as expected due to tampered RELAY_EXTENDED: %v", err)

	t.Log("Successfully verified that RELAY_EXTENDED tampering prevents circuit establishment")
}

// Tests that tampering with RELAY_BEGIN cells prevents stream establishment.
func Test_TOR_Stream_Begin_Tampering(t *testing.T) {
	// Build a working 3-hop circuit first
	client, relays, _, circID := BuildNHopCircuit(t, 3)
	middle := relays[1]

	// Install tamper hook on middle to corrupt RELAY_BEGIN cells
	type testNode interface {
		SetTestCellInterceptor(func(*impl.Cell))
	}
	middleNode, ok := middle.Peer.(testNode)
	require.True(t, ok, "Failed to cast middle node to testNode interface")

	tamperCount := 0
	middleNode.SetTestCellInterceptor(func(cell *impl.Cell) {
		// Tamper only with RELAY_BEGIN cells
		if cell.Command == impl.Relay && tamperCount == 0 {
			// Check the relay command byte at offset 10 in payload
			if len(cell.Payload) > impl.RelayHeaderLen {
				relayCmd := cell.Payload[10]
				if relayCmd == impl.RelayBegin {
					tamperCount++
					// Tamper with the target address data after the relay header
					cell.Payload[impl.RelayHeaderLen+2] ^= 0xFF
					t.Logf("Tampered with RELAY_BEGIN cell")
				}
			}
		}
	})

	// Attempt to open stream
	// This function returns without waiting for RELAY_CONNECTED,
	// so we need to check if the stream was actually established
	// by verifying if it exists later.
	streamID, err := client.OpenStream(circID, "host:3333")

	// Stream opening should fail due to tampered RELAY_BEGIN
	if err != nil {
		t.Logf("Stream open failed as expected due to tampered RELAY_BEGIN: %v", err)
	} else {
		// If no immediate error, wait and check if stream was properly established
		time.Sleep(1 * time.Second)

		// Use TorStreams interface to check if stream exists
		hasStream := client.Peer.HasStream(circID, streamID)
		require.False(t, hasStream,
			"Stream should not exist as RELAY_BEGIN was tampered")
	}

	// Verify tamper hook was triggered
	require.Equal(t, 1, tamperCount, "RELAY_BEGIN should have been tampered once")

	t.Log("Successfully verified that RELAY_BEGIN tampering prevents proper stream establishment")

	// Cleanup
	_ = client.DestroyCircuit(circID)
}

// Tests sending multiple data messages with a configurable number of them being tampered.
func Test_TOR_Multiple_Data_Messages_Tampering(t *testing.T) {
	// Build a 3-hop circuit
	client, relays, exit, circID := BuildNHopCircuit(t, 3)
	middle := relays[1]

	// Open a stream
	streamID, err := client.OpenStream(circID, "host:4444")
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// Install tamper hook on middle to tamper with some RELAY_DATA cells
	type testNode interface {
		SetTestCellInterceptor(func(*impl.Cell))
	}
	middleNode, ok := middle.Peer.(testNode)
	require.True(t, ok, "Failed to cast middle node to testNode interface")

	tamperCount := 0
	totalRelayData := 0
	middleNode.SetTestCellInterceptor(func(cell *impl.Cell) {
		// Only tamper with RELAY cells containing data
		if cell.Command == impl.Relay {
			totalRelayData++
			// Tamper with the first TamperTestTamperCount RELAY_DATA cells
			if tamperCount < TamperTestTamperCount && len(cell.Payload) > 20 {
				tamperCount++
				cell.Payload[20] ^= 0x01
				t.Logf("Tampered RELAY_DATA cell %d/%d", tamperCount, TamperTestTamperCount)
			}
		}
	})

	// Send multiple data messages
	successCount := 0
	for i := range TamperTestMessageCount {
		testData := []byte("Message " + string(rune('A'+i)) + ": Test data for tampering")
		err = client.SendStreamData(circID, streamID, testData)
		require.NoError(t, err)
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for potential delivery
	time.Sleep(1 * time.Second)

	// Check how many messages were received by exit
	exitCircID := getExitCircuitIDWithStreams(t, exit)
	receivedPacketsExit, err := exit.GetReceivedStreamPackets(exitCircID, streamID)
	require.NoError(t, err)

	// Expect to receive fewer messages than sent due to tampering
	successCount = len(receivedPacketsExit)
	t.Logf("Sent %d messages, exit received %d messages (%d tampered, %d dropped)",
		TamperTestMessageCount, successCount, tamperCount, TamperTestMessageCount-successCount)

	// Verify that some messages were dropped due to tampering
	require.Less(t, successCount, TamperTestMessageCount,
		"Some messages should have been dropped due to tampering")

	// Verify security statistics
	digestMismatches := exit.GetDigestMismatches()
	droppedCells := exit.GetDroppedCells()

	t.Logf("Exit node security stats: DigestMismatches=%d, DroppedCells=%d",
		digestMismatches, droppedCells)

	// Once tampering occurs, it corrupts the digest chain, causing ALL subsequent
	// relay cells to fail verification.
	require.GreaterOrEqual(t, digestMismatches, uint64(TamperTestTamperCount),
		"Exit should have detected at least the tampered messages as digest mismatches")

	// Expect all messages after the first tampering to be dropped
	require.Equal(t, 0, successCount,
		"All messages should be dropped after tampering corrupts the digest chain")

	t.Log("Successfully verified that multiple message tampering is detected and prevents delivery")

	// Cleanup
	_ = client.CloseStream(circID, streamID)
	time.Sleep(100 * time.Millisecond)
	_ = client.DestroyCircuit(circID)
}

// Tests creating multiple streams where some RELAY_BEGIN messages are tampered, ensuring tampered streams fail while others succeed.
func Test_TOR_Stream_Creation_With_Tampering(t *testing.T) {
	// Build a 3-hop circuit
	client, relays, _, circID := BuildNHopCircuit(t, 3)
	middle := relays[1]

	// Install tamper hook to corrupt specific RELAY_BEGIN messages
	type testNode interface {
		SetTestCellInterceptor(func(*impl.Cell))
	}
	middleNode, ok := middle.Peer.(testNode)
	require.True(t, ok, "Failed to cast middle node to testNode interface")

	// Track which streams to tamper
	tamperedStreamIndices := map[int]bool{2: true, 4: true} // Tamper 2 streams
	require.Equal(t, TamperTestStreamTamperCount, len(tamperedStreamIndices),
		"Test setup should match TamperTestStreamTamperCount")

	// Install tamper hook before creating streams
	// Only streams created BEFORE the first tampered cell will succeed.
	streamCounter := 0
	middleNode.SetTestCellInterceptor(func(cell *impl.Cell) {
		// Only tamper with RELAY_BEGIN cells, and only count up to TamperTestStreamCount
		if cell.Command == impl.Relay && len(cell.Payload) > impl.RelayHeaderLen && streamCounter < TamperTestStreamCount {
			relayCmd := cell.Payload[10]
			if relayCmd == impl.RelayBegin {
				currentStream := streamCounter
				streamCounter++

				if tamperedStreamIndices[currentStream] {
					// Tamper with this RELAY_BEGIN, which corrupts digest chain for all subsequent cells
					cell.Payload[impl.RelayHeaderLen+2] ^= 0xFF
					t.Logf("Tampered RELAY_BEGIN for stream index %d (streamID from payload: %d)",
						currentStream, uint16(cell.Payload[0])<<8|uint16(cell.Payload[1]))
				}
			}
		}
	})

	// Now create TamperTestStreamCount streams and track their IDs
	streamIDs := make([]uint16, 0, TamperTestStreamCount)
	for i := range TamperTestStreamCount {
		streamID, err := client.OpenStream(circID, "host:"+string(rune('A'+i))+"000")
		require.NoError(t, err, "OpenStream should not return error immediately")
		streamIDs = append(streamIDs, streamID)
		t.Logf("Stream %d (ID=%d) open request sent", i, streamID)
	}

	// Wait for RELAY_CONNECTED messages
	time.Sleep(1 * time.Second)

	// Verify stream creation results
	// Streams before first tampered index succeed, all others fail.
	firstTamperedIndex := TamperTestStreamCount // Find lowest tampered index
	for idx := range tamperedStreamIndices {
		if idx < firstTamperedIndex {
			firstTamperedIndex = idx
		}
	}

	successfulStreams := 0
	for i, streamID := range streamIDs {
		hasStream := client.Peer.HasStream(circID, streamID)

		if i < firstTamperedIndex {
			// Streams created before first tampering should succeed
			require.True(t, hasStream,
				"Stream %d (ID %d) should exist as it was created before tampering at index %d", i, streamID, firstTamperedIndex)
			successfulStreams++
			t.Logf("Stream %d correctly established (before tampering)", i)
		} else {
			// Streams after first tampering fail as either tampered directly or digest chain broken
			require.False(t, hasStream,
				"Stream %d (ID %d) should not exist as it was created after tampering at index %d", i, streamID, firstTamperedIndex)
			if tamperedStreamIndices[i] {
				t.Logf("Stream %d correctly not established due to direct tampering", i)
			} else {
				t.Logf("Stream %d correctly not established due to digest chain broken by earlier tampering", i)
			}
		}
	}

	require.Equal(t, firstTamperedIndex, successfulStreams,
		"Should have %d successful streams",
		firstTamperedIndex, firstTamperedIndex)

	t.Logf("Stream creation results: %d successful, %d failed, %d total",
		successfulStreams, TamperTestStreamCount-successfulStreams, TamperTestStreamCount)

	// Send messages on successfully created streams to verify they work
	for i, streamID := range streamIDs {
		if client.Peer.HasStream(circID, streamID) {
			testData := []byte("Test message on stream " + string(rune('A'+i)))
			err := client.SendStreamData(circID, streamID, testData)
			require.NoError(t, err, "Should be able to send data on established stream %d", streamID)
		}
	}

	time.Sleep(500 * time.Millisecond)

	t.Log("Successfully verified TOR's digest chain security: tampering breaks all subsequent cells")

	// Cleanup
	for _, streamID := range streamIDs {
		if client.Peer.HasStream(circID, streamID) {
			_ = client.CloseStream(circID, streamID)
		}
	}
	time.Sleep(100 * time.Millisecond)
	_ = client.DestroyCircuit(circID)
}
