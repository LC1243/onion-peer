package unit

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
)

// Default number of packets to send when running data transfer tests.
// Can be modified to increase or decrease test load.
const DefaultTestPacketCount = 32

// Default number of streams per circuit for multiple stream tests.
// Can be modified to increase or decrease test load.
const DefaultStreamsPerCircuit = 4

// Default number of packets per stream for multiple stream tests.
// Can be modified to increase or decrease test load.
const DefaultPacketsPerStream = 8

// Test_TOR_Data_Transfer_Basic tests basic data transfer over a stream
// Verifies that data sent by client is received by exit node and echoed back
func Test_TOR_Data_Transfer_Basic(t *testing.T) {
	// Use helper to build circuit
	client, _, _, exit, circID := Build3HopCircuit(t)
	var _ z.TestNode = client // Ensure z import is used

	// Open a stream
	streamID, err := client.OpenStream(circID, "host:1111")
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// Verify stream exists on client
	require.True(t, client.HasStream(circID, streamID), "Client should have the stream")

	// Send data from client to exit
	testData := []byte("Hello Test Message.")
	err = client.SendStreamData(circID, streamID, testData)
	require.NoError(t, err)

	// Wait for data to propagate
	time.Sleep(500 * time.Millisecond)

	// Check packets sent by client
	sentPackets, err := client.GetStreamPackets(circID, streamID)
	require.NoError(t, err)
	require.Equal(t, 1, len(sentPackets), "Client should have sent 1 packet")
	require.Equal(t, testData, sentPackets[0], "Sent data should match original")

	// Get the exit node's circuit ID
	exitCircID := getExitCircuitIDWithStreams(t, exit)

	// Check packets received by exit
	receivedPacketsExit, err := exit.GetReceivedStreamPackets(exitCircID, streamID)
	require.NoError(t, err)
	require.Equal(t, 1, len(receivedPacketsExit), "Exit should have received 1 packet")
	require.Equal(t, testData, receivedPacketsExit[0], "Exit received data should match original")

	// Wait for reply
	time.Sleep(500 * time.Millisecond)

	// Check packets received by client
	// As exit node echoes the data back, it should receive the same data as sent by client
	receivedPacketsClient, err := client.GetReceivedStreamPackets(circID, streamID)
	require.NoError(t, err)
	require.Equal(t, 1, len(receivedPacketsClient), "Client should have received 1 reply")
	require.Equal(t, testData, receivedPacketsClient[0], "Client received data should match original")

	// Cleanup
	_ = client.CloseStream(circID, streamID)
	time.Sleep(200 * time.Millisecond)
	_ = client.DestroyCircuit(circID)
}

// Test_TOR_Data_Transfer_Multiple_Packets tests sending multiple packets
// and verifying that all are received correctly by exit and echoed back to client
func Test_TOR_Data_Transfer_Multiple_Packets(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)
	streamID, err := client.OpenStream(circID, "host:1111")
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// Send multiple packets
	numPackets := DefaultTestPacketCount
	testMessages := make([][]byte, numPackets)
	for i := range testMessages {
		testMessages[i] = []byte("Packet " + string(rune('A'+i)) + ": Test data")
		err = client.SendStreamData(circID, streamID, testMessages[i])
		require.NoError(t, err)
		time.Sleep(100 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify sent packets
	sentPackets, err := client.GetStreamPackets(circID, streamID)
	require.NoError(t, err)
	require.Equal(t, numPackets, len(sentPackets), "Client should have sent %d packets", numPackets)
	for i := range numPackets {
		require.Equal(t, testMessages[i], sentPackets[i], "Sent packet %d should match", i)
	}

	// Get the exit node's circuit ID and verify it received all packets
	exitCircID := getExitCircuitIDWithStreams(t, exit)
	receivedPacketsExit, err := exit.GetReceivedStreamPackets(exitCircID, streamID)
	require.NoError(t, err)
	require.Equal(t, numPackets, len(receivedPacketsExit), "Exit should have received %d packets", numPackets)
	for i := range numPackets {
		require.Equal(t, testMessages[i], receivedPacketsExit[i], "Exit packet %d should match", i)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify client received echoed replies
	receivedPacketsClient, err := client.GetReceivedStreamPackets(circID, streamID)
	require.NoError(t, err)
	require.Equal(t, numPackets, len(receivedPacketsClient), "Client should have received %d replies", numPackets)
	for i := range numPackets {
		require.Equal(t, testMessages[i], receivedPacketsClient[i], "Client reply %d should match", i)
	}

	_ = client.CloseStream(circID, streamID)
	time.Sleep(200 * time.Millisecond)
	_ = client.DestroyCircuit(circID)
}

// Test_TOR_Data_Transfer_Packet_Count verifies accurate packet counting
func Test_TOR_Data_Transfer_Packet_Count(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	streamID, err := client.OpenStream(circID, "host:1111")
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// Use configurable number of packets for the test
	numPackets := DefaultTestPacketCount
	if numPackets < 1 {
		t.Fatalf("DefaultTestPacketCount must be >= 1, got %d", numPackets)
	}

	// Initially no packets
	sentPackets, _ := client.GetStreamPackets(circID, streamID)
	require.Equal(t, 0, len(sentPackets), "Initially no packets sent")

	exitCircID := getExitCircuitIDWithStreams(t, exit)

	// Send multiple packets and verify counts incrementally
	for i := range numPackets {
		data := fmt.Appendf(nil, "Packet %d", i+1)
		_ = client.SendStreamData(circID, streamID, data)
		time.Sleep(500 * time.Millisecond)

		sentPackets, _ = client.GetStreamPackets(circID, streamID)
		require.Equal(t, i+1, len(sentPackets), "After send %d: %d packets", i+1, len(sentPackets))

		receivedExit, _ := exit.GetReceivedStreamPackets(exitCircID, streamID)
		require.Equal(t, i+1, len(receivedExit), "After send %d: exit has %d packets", i+1, len(receivedExit))
	}

	_ = client.CloseStream(circID, streamID)
	_ = client.DestroyCircuit(circID)
}

// Test_TOR_Data_Transfer_Error_Cases tests error conditions
func Test_TOR_Data_Transfer_Error_Cases(t *testing.T) {
	client, _, _, _, circID := Build3HopCircuit(t)

	// Try to send on non-existent stream
	err := client.SendStreamData(circID, 12345, []byte("Should fail"))
	require.Error(t, err, "Should fail on non-existent stream")
	require.Contains(t, err.Error(), "not found", "Error should mention stream not found")

	_ = client.DestroyCircuit(circID)
}

// Test_TOR_Data_Multiple_Streams_No_Leakage specifically tests for data isolation between streams.
// This test focuses on ensuring that data sent on one stream does NOT appear on another stream.
func Test_TOR_Data_Multiple_Streams_No_Leakage(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	// Open 3 streams with very distinct data patterns
	stream1, err := client.OpenStream(circID, "host1:1111")
	require.NoError(t, err)
	stream2, err := client.OpenStream(circID, "host2:2222")
	require.NoError(t, err)
	stream3, err := client.OpenStream(circID, "host3:3333")
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	// Send very distinct data patterns on each stream
	data1 := []byte("AAAAA-Stream1-AAAAA")
	data2 := []byte("BBBBB-Stream2-BBBBB")
	data3 := []byte("CCCCC-Stream3-CCCCC")

	err = client.SendStreamData(circID, stream1, data1)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	err = client.SendStreamData(circID, stream2, data2)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	err = client.SendStreamData(circID, stream3, data3)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)

	exitCircID := getExitCircuitIDWithStreams(t, exit)

	// Verify stream 1 only has data1
	recv1Exit, err := exit.GetReceivedStreamPackets(exitCircID, stream1)
	require.NoError(t, err)
	require.Equal(t, 1, len(recv1Exit), "Stream 1 should have exactly 1 packet at exit")
	require.Equal(t, data1, recv1Exit[0], "Stream 1 exit data should match")
	require.NotContains(t, string(recv1Exit[0]), "Stream2", "Stream 1 should not contain Stream2 data")
	require.NotContains(t, string(recv1Exit[0]), "Stream3", "Stream 1 should not contain Stream3 data")

	// Verify stream 2 only has data2
	recv2Exit, err := exit.GetReceivedStreamPackets(exitCircID, stream2)
	require.NoError(t, err)
	require.Equal(t, 1, len(recv2Exit), "Stream 2 should have exactly 1 packet at exit")
	require.Equal(t, data2, recv2Exit[0], "Stream 2 exit data should match")
	require.NotContains(t, string(recv2Exit[0]), "Stream1", "Stream 2 should not contain Stream1 data")
	require.NotContains(t, string(recv2Exit[0]), "Stream3", "Stream 2 should not contain Stream3 data")

	// Verify stream 3 only has data3
	recv3Exit, err := exit.GetReceivedStreamPackets(exitCircID, stream3)
	require.NoError(t, err)
	require.Equal(t, 1, len(recv3Exit), "Stream 3 should have exactly 1 packet at exit")
	require.Equal(t, data3, recv3Exit[0], "Stream 3 exit data should match")
	require.NotContains(t, string(recv3Exit[0]), "Stream1", "Stream 3 should not contain Stream1 data")
	require.NotContains(t, string(recv3Exit[0]), "Stream2", "Stream 3 should not contain Stream2 data")

	// Wait for echoes
	time.Sleep(500 * time.Millisecond)

	// Verify client received data integrity (echoes)
	recv1Client, err := client.GetReceivedStreamPackets(circID, stream1)
	require.NoError(t, err)
	require.Equal(t, 1, len(recv1Client), "Stream 1 should have exactly 1 echoed packet at client")
	require.Equal(t, data1, recv1Client[0], "Stream 1 client echo should match")

	recv2Client, err := client.GetReceivedStreamPackets(circID, stream2)
	require.NoError(t, err)
	require.Equal(t, 1, len(recv2Client), "Stream 2 should have exactly 1 echoed packet at client")
	require.Equal(t, data2, recv2Client[0], "Stream 2 client echo should match")

	recv3Client, err := client.GetReceivedStreamPackets(circID, stream3)
	require.NoError(t, err)
	require.Equal(t, 1, len(recv3Client), "Stream 3 should have exactly 1 echoed packet at client")
	require.Equal(t, data3, recv3Client[0], "Stream 3 client echo should match")

	t.Log("Successfully verified no data leakage between streams")

	// Cleanup
	_ = client.CloseStream(circID, stream1)
	_ = client.CloseStream(circID, stream2)
	_ = client.CloseStream(circID, stream3)
	time.Sleep(200 * time.Millisecond)
	_ = client.DestroyCircuit(circID)
}

// Test_TOR_Data_Multiple_Streams_Single_Circuit tests multiple streams on a single circuit.
// Verifies:
// 1. Data sent over each stream is correct
// 2. No data leakage between streams and each stream only receives its own data
func Test_TOR_Data_Multiple_Streams_Single_Circuit(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	// Use configurable test parameters
	numStreams := DefaultStreamsPerCircuit
	numPacketsPerStream := DefaultPacketsPerStream

	streamIDs := make([]uint16, numStreams)
	streamData := make(map[uint16][][]byte)

	// Open multiple streams
	for i := range numStreams {
		streamID, err := client.OpenStream(circID, fmt.Sprintf("host:%d", 1000+i))
		require.NoError(t, err, "Stream %d should open successfully", i)
		streamIDs[i] = streamID
		streamData[streamID] = make([][]byte, numPacketsPerStream)
		time.Sleep(100 * time.Millisecond)

		// Verify stream exists on client
		require.True(t, client.HasStream(circID, streamID), "Client should have stream %d", streamID)
	}

	t.Logf("Opened %d streams: %v", numStreams, streamIDs)

	// Send distinct data on each stream
	for i, streamID := range streamIDs {
		for pkt := range numPacketsPerStream {
			data := fmt.Appendf(nil, "Stream-%d-Packet-%d", i, pkt)
			streamData[streamID][pkt] = data
			err := client.SendStreamData(circID, streamID, data)
			require.NoError(t, err, "Should send data on stream %d packet %d", streamID, pkt)
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Wait for all data to propagate
	time.Sleep(1 * time.Second)

	// Get exit circuit ID
	exitCircID := getExitCircuitIDWithStreams(t, exit)

	// Verify each stream's data integrity on client side
	for i, streamID := range streamIDs {
		sentPackets, err := client.GetStreamPackets(circID, streamID)
		require.NoError(t, err, "Should get sent packets for stream %d", streamID)
		require.Equal(t, numPacketsPerStream, len(sentPackets), "Stream %d should have sent %d packets", streamID, numPacketsPerStream)

		for pkt := range numPacketsPerStream {
			require.Equal(t, streamData[streamID][pkt], sentPackets[pkt],
				"Stream %d packet %d sent data should match", i, pkt)
		}
	}

	// Verify each stream's data integrity on exit side
	for i, streamID := range streamIDs {
		receivedPacketsExit, err := exit.GetReceivedStreamPackets(exitCircID, streamID)
		require.NoError(t, err, "Exit should have received packets for stream %d", streamID)
		require.Equal(t, numPacketsPerStream, len(receivedPacketsExit),
			"Exit should have received %d packets on stream %d", numPacketsPerStream, streamID)

		for pkt := range numPacketsPerStream {
			require.Equal(t, streamData[streamID][pkt], receivedPacketsExit[pkt],
				"Stream %d packet %d at exit should match original", i, pkt)
		}
	}

	// Wait for echoes to come back
	time.Sleep(1 * time.Second)

	// Verify each stream's echoed data on client side
	for i, streamID := range streamIDs {
		receivedPacketsClient, err := client.GetReceivedStreamPackets(circID, streamID)
		require.NoError(t, err, "Client should have received echoed packets for stream %d", streamID)
		require.Equal(t, numPacketsPerStream, len(receivedPacketsClient),
			"Client should have received %d echoed packets on stream %d", numPacketsPerStream, streamID)

		for pkt := range numPacketsPerStream {
			require.Equal(t, streamData[streamID][pkt], receivedPacketsClient[pkt],
				"Stream %d packet %d echoed to client should match original", i, pkt)
		}
	}

	// Verify no data leakage: each stream should only contain its own data
	for i, streamID := range streamIDs {
		receivedPacketsClient, _ := client.GetReceivedStreamPackets(circID, streamID)
		for _, receivedData := range receivedPacketsClient {
			// Check that this packet belongs to this stream
			expectedPrefix := fmt.Sprintf("Stream-%d-", i)
			require.Contains(t, string(receivedData), expectedPrefix,
				"Stream %d should only receive its own data, got: %s", streamID, string(receivedData))

			// Check that it doesn't contain data from other streams
			for j := range numStreams {
				if j != i {
					wrongPrefix := fmt.Sprintf("Stream-%d-", j)
					require.NotContains(t, string(receivedData), wrongPrefix,
						"Stream %d should not receive data from stream %d", streamID, j)
				}
			}
		}
	}

	t.Log("Successfully verified data integrity and no leakage across multiple streams")

	// Cleanup
	for _, streamID := range streamIDs {
		_ = client.CloseStream(circID, streamID)
	}
	time.Sleep(200 * time.Millisecond)
	_ = client.DestroyCircuit(circID)
}
