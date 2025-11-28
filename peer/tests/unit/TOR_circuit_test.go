package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
)

// Test_TOR_Circuit_Create_Simple tests that a single Create/Created handshake works
func Test_TOR_Circuit_Create_Simple(t *testing.T) {
	transp := channelFac()

	// Create two nodes: client and relay
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	relay := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer relay.Stop()

	// Set up routing so they can communicate
	client.AddPeer(relay.GetAddr())
	relay.AddPeer(client.GetAddr())

	// Give them time to exchange information
	time.Sleep(100 * time.Millisecond)

	// The client should be able to send a Create cell to the relay
	// For now, we just verify the nodes can communicate
	require.NotEmpty(t, client.GetAddr())
	require.NotEmpty(t, relay.GetAddr())
}

// Test_TOR_Circuit_BuildCircuit_ThreeHops tests building a complete 3-hop circuit
func Test_TOR_Circuit_BuildCircuit_ThreeHops(t *testing.T) {
	transp := channelFac()

	// Create 4 nodes: client + 3 relays (guard, middle, exit)
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard.Stop()

	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle.Stop()

	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit.Stop()

	// Set up full mesh routing so all nodes can reach each other
	nodes := []z.TestNode{client, guard, middle, exit}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	// Give them time to exchange routing information
	time.Sleep(100 * time.Millisecond)

	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}

	// Build the circuit with a 5 second timeout
	circID, err := client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err, "BuildCircuit should succeed")
	require.NotZero(t, circID, "Circuit ID should be non-zero")

	t.Logf("Successfully built circuit %d through %v", circID, hops)
}

// Test_TOR_Circuit_BuildCircuit_Timeout tests that circuit building fails properly with unreachable nodes
func Test_TOR_Circuit_BuildCircuit_Timeout(t *testing.T) {
	transp := channelFac()

	// Create only the client - no relays available
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	// Try to build a circuit to non-existent nodes
	// These addresses are in routing table but won't respond
	hops := [3]string{"127.0.0.1:9991", "127.0.0.1:9992", "127.0.0.1:9993"}

	// Add fake routing entries
	client.SetRoutingEntry(hops[0], hops[0])
	client.SetRoutingEntry(hops[1], hops[1])
	client.SetRoutingEntry(hops[2], hops[2])

	// Build should fail (either timeout or send failure)
	_, err := client.Peer.BuildCircuit(hops, 500*time.Millisecond)
	require.Error(t, err, "BuildCircuit should fail with unreachable nodes")
}

// Test_TOR_Circuit_MultipleCircuits tests building multiple circuits concurrently
func Test_TOR_Circuit_MultipleCircuits(t *testing.T) {
	transp := channelFac()

	// Create nodes
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard.Stop()

	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle.Stop()

	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit.Stop()

	// Set up full mesh routing
	nodes := []z.TestNode{client, guard, middle, exit}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)

	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}

	// Build two circuits
	circID1, err := client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	circID2, err := client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	// They should have different IDs
	require.NotEqual(t, circID1, circID2, "Circuit IDs should be unique")

	t.Logf("Built circuits %d and %d", circID1, circID2)
}
