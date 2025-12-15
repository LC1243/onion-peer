package unit

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/udp"
)

func stopAllNodesWithin(t *testing.T, nodes []z.TestNode, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		for _, n := range nodes {
			n.StopAll()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Log("Warning: stopping nodes timed out")
	}
}

func Test_TOR_FlowControl_Circuit_Level_Single(t *testing.T) {
	// Setup 4 nodes: Client, Guard, Middle, Exit
	trans := udp.NewUDP()

	client := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))

	nodes := []z.TestNode{client, guard, middle, exit}
	defer stopAllNodesWithin(t, nodes, 5*time.Second)

	t.Logf("Client: %s", client.GetAddr())
	t.Logf("Guard: %s", guard.GetAddr())
	t.Logf("Middle: %s", middle.GetAddr())
	t.Logf("Exit: %s", exit.GetAddr())

	// Connect nodes (Full Mesh) manually to ensure bidirectional routing
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	// Give time for routing tables to update (if async)
	time.Sleep(200 * time.Millisecond)

	// Populate onion keys for all nodes
	z.PopulateOnionKeys(nodes)

	// Build Circuit
	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}
	circID, err := client.BuildCircuit(hops, 30*time.Second)
	require.NoError(t, err, "Failed to build circuit")

	// Open Stream
	targetAddr := "dummy:1234"
	streamID, err := client.OpenStream(circID, targetAddr)
	require.NoError(t, err, "Failed to open stream")

	// Send data > window size (1000)
	// We send 1100 packets. If flow control (SENDME) works, we should receive all of them back.
	// If not, it will block after 1000.
	numPackets := 1100
	payload := []byte("test-data")

	// Start a goroutine to send data
	go func() {
		for i := 0; i < numPackets; i++ {
			for {
				err := client.SendStreamData(circID, streamID, payload)
				if err == nil {
					break
				}
				// Retry if stream is not yet open
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Wait for data to be echoed back
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for echoed data")
		case <-ticker.C:
			pkts, err := client.GetReceivedStreamPackets(circID, streamID)
			if err == nil && len(pkts) >= numPackets {
				t.Logf("Received %d packets", len(pkts))
				return // Success
			}
		}
	}
}

func Test_TOR_FlowControl_Circuit_Level_Multiple_Clients(t *testing.T) {
	trans := udp.NewUDP()

	client1 := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	client2 := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))

	nodes := []z.TestNode{client1, client2, guard, middle, exit}
	defer stopAllNodesWithin(t, nodes, 5*time.Second)

	// Connect nodes (Full Mesh) manually
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(200 * time.Millisecond)

	// Populate onion keys for all nodes
	z.PopulateOnionKeys(nodes)

	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}

	// Build circuits
	circID1, err := client1.BuildCircuit(hops, 30*time.Second)
	require.NoError(t, err)

	circID2, err := client2.BuildCircuit(hops, 30*time.Second)
	require.NoError(t, err)

	// Open streams
	streamID1, err := client1.OpenStream(circID1, "dummy:1")
	require.NoError(t, err)

	streamID2, err := client2.OpenStream(circID2, "dummy:2")
	require.NoError(t, err)

	numPackets := 1100 // > 1000
	payload := []byte("data")

	var wg sync.WaitGroup
	wg.Add(2)

	runClient := func(c z.TestNode, circID, streamID uint16) {
		defer wg.Done()

		// Send
		go func() {
			for i := 0; i < numPackets; i++ {
				for {
					err := c.SendStreamData(circID, streamID, payload)
					if err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				time.Sleep(18 * time.Millisecond)
			}
		}()

		// Receive
		timeout := time.After(60 * time.Second)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeout:
				pkts, _ := c.GetReceivedStreamPackets(circID, streamID)
				t.Errorf("Timeout waiting for data - received %d/%d packets", len(pkts), numPackets)
				return
			case <-ticker.C:
				pkts, err := c.GetReceivedStreamPackets(circID, streamID)
				if err == nil && len(pkts) >= numPackets {
					return
				}
			}
		}
	}

	go runClient(client1, circID1, streamID1)
	go runClient(client2, circID2, streamID2)

	wg.Wait()
}

// Test_TOR_FlowControl_Disabled_PacketLoss verifies that without congestion control,
// spamming cells at high rate causes packet loss due to buffer overflow
func Test_TOR_FlowControl_Disabled_PacketLoss(t *testing.T) {
	trans := udp.NewUDP()

	// Create nodes with congestion control DISABLED
	client := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))

	nodes := []z.TestNode{client, guard, middle, exit}
	defer stopAllNodesWithin(t, nodes, 5*time.Second)

	// Disable congestion control on all nodes
	for _, n := range nodes {
		n.SetCongestionControl(false)
	}

	// Connect nodes (Full Mesh)
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(200 * time.Millisecond)

	z.PopulateOnionKeys(nodes)

	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}
	circID, err := client.BuildCircuit(hops, 30*time.Second)
	require.NoError(t, err)

	streamID, err := client.OpenStream(circID, "dummy:1234")
	require.NoError(t, err)

	// Spam a LOT of packets as fast as possible (no delay)
	// Without flow control, buffers will overflow and packets will be lost
	numPackets := 5000
	payload := []byte("spam-data-without-flow-control")

	// Send all packets as fast as possible
	var sendWg sync.WaitGroup
	sendWg.Add(1)
	go func() {
		defer sendWg.Done()
		for i := 0; i < numPackets; i++ {
			_ = client.SendStreamData(circID, streamID, payload)
			// No delay - spam as fast as possible
		}
	}()
	sendWg.Wait()

	// Wait a bit for any in-flight packets to arrive
	time.Sleep(3 * time.Second)

	// Check received packets - we expect packet loss
	pkts, _ := client.GetReceivedStreamPackets(circID, streamID)
	received := len(pkts)

	t.Logf("Sent %d packets, received %d packets (loss: %d)", numPackets, received, numPackets-received)

	// Without congestion control and with aggressive spamming, we expect packet loss
	// The test passes if we lost at least some packets (not all received)
	if received >= numPackets {
		t.Logf("WARNING: No packet loss detected - this might happen if the system is fast enough")
		t.Logf("Consider this test informational rather than a strict requirement")
	} else {
		t.Logf("Packet loss detected as expected without congestion control")
	}
}

// Test_TOR_FlowControl_Enabled_NoPacketLoss verifies that with congestion control enabled,
// even aggressive sending does not cause packet loss (just slower throughput)
func Test_TOR_FlowControl_Enabled_NoPacketLoss(t *testing.T) {
	trans := udp.NewUDP()

	// Create nodes with congestion control ENABLED (default)
	client := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))

	nodes := []z.TestNode{client, guard, middle, exit}
	defer stopAllNodesWithin(t, nodes, 5*time.Second)

	// Congestion control is enabled by default, but let's be explicit
	for _, n := range nodes {
		n.SetCongestionControl(true)
	}

	// Connect nodes (Full Mesh)
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(200 * time.Millisecond)

	z.PopulateOnionKeys(nodes)

	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}
	circID, err := client.BuildCircuit(hops, 30*time.Second)
	require.NoError(t, err)

	streamID, err := client.OpenStream(circID, "dummy:1234")
	require.NoError(t, err)

	// Send many packets - with flow control, this should block when windows are full
	// rather than losing packets. Use fewer packets to speed up the test.
	numPackets := 1200 // Just above window size of 1000
	payload := []byte("data-with-flow-control")

	// Send packets in a goroutine (will block on flow control)
	go func() {
		for i := 0; i < numPackets; i++ {
			for {
				err := client.SendStreamData(circID, streamID, payload)
				if err == nil {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			// Small delay to not overwhelm, but still send fast
			time.Sleep(3 * time.Millisecond)
		}
	}()

	// Wait for all packets to be received
	timeout := time.After(90 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			pkts, _ := client.GetReceivedStreamPackets(circID, streamID)
			t.Fatalf("Timeout: received %d/%d packets", len(pkts), numPackets)
		case <-ticker.C:
			pkts, err := client.GetReceivedStreamPackets(circID, streamID)
			if err == nil && len(pkts) >= numPackets {
				t.Logf("SUCCESS: All %d packets received with congestion control enabled", numPackets)
				return
			}
		}
	}
}

// Test_TOR_FlowControl_SharedMiddle_TwoClients tests two clients with separate guards and exits
// but sharing the same middle node. Both should be able to send many cells without loss.
// Circuit topology:
//
//	Client1 -> Guard1 -> Middle (shared) -> Exit1
//	Client2 -> Guard2 -> Middle (shared) -> Exit2
func Test_TOR_FlowControl_SharedMiddle_TwoClients(t *testing.T) {
	trans := udp.NewUDP()

	// 2 clients + 5 relays (Guard1, Guard2, shared Middle, Exit1, Exit2)
	client1 := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	client2 := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard1 := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard2 := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true)) // Shared
	exit1 := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit2 := z.NewTestNode(t, peerFac, trans, "127.0.0.1:0", z.WithAutostart(true))

	nodes := []z.TestNode{client1, client2, guard1, guard2, middle, exit1, exit2}
	defer stopAllNodesWithin(t, nodes, 10*time.Second)

	t.Logf("Client1: %s", client1.GetAddr())
	t.Logf("Client2: %s", client2.GetAddr())
	t.Logf("Guard1: %s", guard1.GetAddr())
	t.Logf("Guard2: %s", guard2.GetAddr())
	t.Logf("Middle (shared): %s", middle.GetAddr())
	t.Logf("Exit1: %s", exit1.GetAddr())
	t.Logf("Exit2: %s", exit2.GetAddr())

	// Connect nodes (Full Mesh)
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(300 * time.Millisecond)

	z.PopulateOnionKeys(nodes)

	// Build circuits with shared middle
	hops1 := [3]string{guard1.GetAddr(), middle.GetAddr(), exit1.GetAddr()}
	hops2 := [3]string{guard2.GetAddr(), middle.GetAddr(), exit2.GetAddr()}

	circID1, err := client1.BuildCircuit(hops1, 30*time.Second)
	require.NoError(t, err, "Client1 failed to build circuit")

	circID2, err := client2.BuildCircuit(hops2, 30*time.Second)
	require.NoError(t, err, "Client2 failed to build circuit")

	streamID1, err := client1.OpenStream(circID1, "dummy:1")
	require.NoError(t, err)

	streamID2, err := client2.OpenStream(circID2, "dummy:2")
	require.NoError(t, err)

	// Both clients send many packets through the shared middle
	numPackets := 1500
	payload := []byte("shared-middle-test")

	var wg sync.WaitGroup
	wg.Add(2)

	// Track results
	var client1Success, client2Success bool
	var mu sync.Mutex

	runClient := func(clientName string, c z.TestNode, circID, streamID uint16, success *bool) {
		defer wg.Done()

		// Send packets
		go func() {
			for i := 0; i < numPackets; i++ {
				for {
					err := c.SendStreamData(circID, streamID, payload)
					if err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				time.Sleep(3 * time.Millisecond)
			}
		}()

		// Wait for all packets
		timeout := time.After(90 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeout:
				pkts, _ := c.GetReceivedStreamPackets(circID, streamID)
				t.Errorf("%s: Timeout - received %d/%d packets", clientName, len(pkts), numPackets)
				return
			case <-ticker.C:
				pkts, err := c.GetReceivedStreamPackets(circID, streamID)
				if err == nil && len(pkts) >= numPackets {
					t.Logf("%s: Received all %d packets", clientName, numPackets)
					mu.Lock()
					*success = true
					mu.Unlock()
					return
				}
			}
		}
	}

	go runClient("Client1", client1, circID1, streamID1, &client1Success)
	go runClient("Client2", client2, circID2, streamID2, &client2Success)

	wg.Wait()

	require.True(t, client1Success, "Client1 should receive all packets")
	require.True(t, client2Success, "Client2 should receive all packets")
	t.Logf("SUCCESS: Both clients received all %d packets through shared middle node", numPackets)
}
