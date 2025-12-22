package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/udp"
)

func Test_TOR_Fairness_Interactive_Vs_Bulk(t *testing.T) {
	// Setup: Client -> Guard -> Middle -> Exit
	// We will have two clients using the SAME circuit path (sharing the Guard-Middle link)
	// Client 1: Bulk sender (sends lots of data)
	// Client 2: Interactive sender (sends small data periodically)
	// We want to verify that Client 2's latency is low even when Client 1 is flooding.

	trans := udp.NewUDP()

	clientBulk := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	clientInteractive := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))

	nodes := []z.TestNode{clientBulk, clientInteractive, guard, middle, exit}
	defer stopAllNodesWithin(t, nodes, 5*time.Second)

	// Connect nodes
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(200 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	hops := []string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}

	// Build circuits
	circBulk, err := clientBulk.BuildCircuit(hops, 30*time.Second)
	require.NoError(t, err)

	circInteractive, err := clientInteractive.BuildCircuit(hops, 30*time.Second)
	require.NoError(t, err)

	// Open streams
	streamBulk, err := clientBulk.OpenStream(circBulk, "dummy:bulk")
	require.NoError(t, err)

	streamInteractive, err := clientInteractive.OpenStream(circInteractive, "dummy:interactive")
	require.NoError(t, err)

	// Start Bulk Sender
	bulkPayload := make([]byte, 450) // Almost full cell
	go func() {
		for {
			err := clientBulk.SendStreamData(circBulk, streamBulk, bulkPayload)
			if err != nil {
				return
			}
			// Send as fast as possible
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Give bulk sender time to saturate the link/queues
	time.Sleep(2 * time.Second)

	// Measure Interactive Latency
	interactivePayload := []byte("ping")
	start := time.Now()
	err = clientInteractive.SendStreamData(circInteractive, streamInteractive, interactivePayload)
	require.NoError(t, err)

	// Wait for echo
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for interactive echo")
		case <-ticker.C:
			pkts, err := clientInteractive.GetReceivedStreamPackets(circInteractive, streamInteractive)
			if err == nil && len(pkts) > 0 {
				latency := time.Since(start)
				t.Logf("Interactive latency: %v", latency)
				require.Less(t, latency, 100*time.Millisecond, "Interactive latency should be low (<100ms) even with bulk traffic")
				return
			}
		}
	}
}

func Test_TOR_Fairness_MultipleStreams(t *testing.T) {
	// Setup: Client -> Guard -> Middle -> Exit
	// Client opens two streams on the same circuit.
	// Stream 1: Bulk
	// Stream 2: Interactive

	trans := udp.NewUDP()

	client := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	guard := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	middle := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))
	exit := z.NewTestNode(t, studentFac, trans, "127.0.0.1:0", z.WithAutostart(true))

	nodes := []z.TestNode{client, guard, middle, exit}
	defer stopAllNodesWithin(t, nodes, 5*time.Second)

	// Connect nodes
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(200 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	hops := []string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}

	// Build circuit
	circ, err := client.BuildCircuit(hops, 30*time.Second)
	require.NoError(t, err)

	// Open streams
	streamBulk, err := client.OpenStream(circ, "dummy:bulk")
	require.NoError(t, err)

	streamInteractive, err := client.OpenStream(circ, "dummy:interactive")
	require.NoError(t, err)

	// Start Bulk Sender
	bulkPayload := make([]byte, 450)
	go func() {
		for {
			err := client.SendStreamData(circ, streamBulk, bulkPayload)
			if err != nil {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Give bulk sender time to saturate
	time.Sleep(2 * time.Second)

	// Measure Interactive Latency
	interactivePayload := []byte("ping")
	start := time.Now()
	err = client.SendStreamData(circ, streamInteractive, interactivePayload)
	require.NoError(t, err)

	// Wait for echo
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for interactive echo")
		case <-ticker.C:
			pkts, err := client.GetReceivedStreamPackets(circ, streamInteractive)
			if err == nil && len(pkts) > 0 {
				latency := time.Since(start)
				t.Logf("Interactive latency: %v", latency)
				require.Less(t, latency, 100*time.Millisecond, "Interactive latency should be low (<100ms) even with bulk traffic on same circuit")
				return
			}
		}
	}
}
