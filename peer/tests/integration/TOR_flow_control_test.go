package integration

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/udp"
)

func Test_TOR_FlowControl_Circuit_Level_Single(t *testing.T) {
	// Setup 4 nodes: Client, Guard, Middle, Exit
	trans := udp.NewUDP()

	client := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))

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

	client1 := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	client2 := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))

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
