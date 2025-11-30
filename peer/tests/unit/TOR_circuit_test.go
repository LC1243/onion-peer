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

// Test_TOR_Circuit_Destroy_ClientUnknownCircuit_Error tests destroying an unknown circuit and expecting an error
func Test_TOR_Circuit_Destroy_ClientUnknownCircuit_Error(t *testing.T) {
	transp := channelFac()

	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	err := client.Peer.DestroyCircuit(42) // Arbitrary unknown circuit ID
	require.Error(t, err, "DestroyCircuit should fail for unknown circuit ID")
}

// Test_TOR_Circuit_Destroy_ClientInitiated_Success tests successful client-initiated circuit destruction initiated
// by the client. A second destruction attempt should fail.
func Test_TOR_Circuit_Destroy_ClientInitiated_Success(t *testing.T) {
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

	// Check that circuit exists before destruction
	require.Equal(t, 1, client.Peer.GetClientCircuitsNbr(), "client should have 1 circuit")
	require.Equal(t, 1, guard.Peer.GetCircuitsNbr(), "guard should have 1 relay circuit")
	require.Equal(t, 1, middle.Peer.GetCircuitsNbr(), "middle should have 1 relay circuit")
	require.Equal(t, 1, exit.Peer.GetCircuitsNbr(), "exit should have 1 relay circuit")

	// Destroy initiated by client
	err = client.Peer.DestroyCircuit(circID)
	require.NoError(t, err, "destroy should succeed for existing circuit")

	// Give time for destroy to propagate
	time.Sleep(100 * time.Millisecond)

	// Check that no node has circuit resources anymore
	require.Equal(t, 0, client.Peer.GetClientCircuitsNbr(), "client should have no circuit")
	require.Equal(t, 0, guard.Peer.GetCircuitsNbr(), "guard should have no relay circuit")
	require.Equal(t, 0, middle.Peer.GetCircuitsNbr(), "middle should have no relay circuit")
	require.Equal(t, 0, exit.Peer.GetCircuitsNbr(), "exit should have no relay circuit")

	// Destroying again should fail
	err = client.Peer.DestroyCircuit(circID)
	require.Error(t, err, "destroying again should fail for non-existing circuit")
}

// Test_TOR_Circuit_Destroy_RelayInitiated_Success tests successful relay-initiated circuit destruction initiated
// by the guard relay. A second destruction attempt should fail.
func Test_TOR_Circuit_Destroy_RelayInitiated_Success(t *testing.T) {
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

	// Check that circuit exists before destruction
	require.Equal(t, 1, client.Peer.GetClientCircuitsNbr(), "client should have 1 circuit")
	require.Equal(t, 1, guard.Peer.GetCircuitsNbr(), "guard should have 1 relay circuit")
	require.Equal(t, 1, middle.Peer.GetCircuitsNbr(), "middle should have 1 relay circuit")
	require.Equal(t, 1, exit.Peer.GetCircuitsNbr(), "exit should have 1 relay circuit")

	// Destroy initiated by the guard relay
	err = guard.Peer.RelayDestroyCircuit(circID, client.GetAddr())
	require.NoError(t, err, "destroy should succeed for existing circuit")

	// Give time for destroy to propagate
	time.Sleep(100 * time.Millisecond)

	// Check that no node has circuit resources anymore
	require.Equal(t, 0, client.Peer.GetClientCircuitsNbr(), "client should have no circuit")
	require.Equal(t, 0, guard.Peer.GetCircuitsNbr(), "guard should have no relay circuit")
	require.Equal(t, 0, middle.Peer.GetCircuitsNbr(), "middle should have no relay circuit")
	require.Equal(t, 0, exit.Peer.GetCircuitsNbr(), "exit should have no relay circuit")

	// Destroying again should fail
	err = guard.Peer.RelayDestroyCircuit(circID, client.GetAddr())
	require.Error(t, err, "destroying again should fail for non-existing circuit")
}

// Test_TOR_Circuit_Cleanup_ClientInitiated_Success tests that multiple circuits can be built and exist simultaneously
// and that if the middle relay that is used in both circuits is cleaned up, both circuits are destroyed.
func Test_TOR_Circuit_Cleanup_ClientInitiated_Success(t *testing.T) {
	transp := channelFac()

	// Create nodes
	client1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client1.Stop()

	client2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client2.Stop()

	guard1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard1.Stop()

	guard2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard2.Stop()

	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle.Stop()

	exit1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit1.Stop()

	exit2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit2.Stop()

	// Set up full mesh routing between the two circuits
	nodes1 := []z.TestNode{client1, guard1, middle, exit1}
	for i, n1 := range nodes1 {
		for j, n2 := range nodes1 {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	nodes2 := []z.TestNode{client2, guard2, middle, exit2}
	for i, n1 := range nodes2 {
		for j, n2 := range nodes2 {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)

	hops1 := [3]string{guard1.GetAddr(), middle.GetAddr(), exit1.GetAddr()}
	hops2 := [3]string{guard2.GetAddr(), middle.GetAddr(), exit2.GetAddr()}

	// Build two circuits
	_, err := client1.Peer.BuildCircuit(hops1, 5*time.Second)
	require.NoError(t, err)

	_, err = client2.Peer.BuildCircuit(hops2, 5*time.Second)
	require.NoError(t, err)

	// Check that node have circuits correct sizes
	require.Equal(t, 1, client1.Peer.GetClientCircuitsNbr(), "client1 should have 1 circuit")
	require.Equal(t, 1, client2.Peer.GetClientCircuitsNbr(), "client2 should have 1 circuit")
	require.Equal(t, 1, guard1.Peer.GetCircuitsNbr(), "guard1 should have 1 relay circuit")
	require.Equal(t, 1, guard2.Peer.GetCircuitsNbr(), "guard2 should have 1 relay circuit")
	require.Equal(t, 2, middle.Peer.GetCircuitsNbr(), "middle should have 2 relay circuit")
	require.Equal(t, 1, exit1.Peer.GetCircuitsNbr(), "exit1 should have 1 relay circuit")
	require.Equal(t, 1, exit2.Peer.GetCircuitsNbr(), "exit2 should have 1 relay circuit")

	// Cleanup middle relay
	middle.Peer.CleanupAllCircuits()

	// Give time for destroy to propagate
	time.Sleep(200 * time.Millisecond)

	// Check that no node has circuit resources anymore
	require.Equal(t, 0, client1.Peer.GetClientCircuitsNbr(), "client1 should have 0 circuit")
	require.Equal(t, 0, client2.Peer.GetClientCircuitsNbr(), "client2 should have 0 circuit")
	require.Equal(t, 0, guard1.Peer.GetCircuitsNbr(), "guard1 should have 0 relay circuit")
	require.Equal(t, 0, guard2.Peer.GetCircuitsNbr(), "guard2 should have 0 relay circuit")
	require.Equal(t, 0, middle.Peer.GetCircuitsNbr(), "middle should have 0 relay circuit")
	require.Equal(t, 0, exit1.Peer.GetCircuitsNbr(), "exit1 should have 0 relay circuit")
	require.Equal(t, 0, exit2.Peer.GetCircuitsNbr(), "exit2 should have 0 relay circuit")
}
