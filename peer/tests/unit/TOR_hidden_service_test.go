package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
)

// Test_TOR_HS_EstablishIntroPoint_Basic tests the process of establishing an introduction point for a hidden service.
func Test_TOR_HS_EstablishIntroPoint_Basic(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	serviceID, err := client.Peer.CreateHiddenService()
	require.NoError(t, err)
	require.NotEmpty(t, serviceID)

	err = client.Peer.EstablishIntroPoint(serviceID, circID)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// 1. Client-side intro point recording
	introPoints := client.Peer.GetServiceIntroPoints(serviceID)
	require.Len(t, introPoints, 1, "service must have exactly 1 intro point")
	require.Equal(t, exit.GetAddr(), introPoints[0])

	// 2. Exit node must have stored intro state
	count := exit.Peer.GetIntroPointStateCount(serviceID)
	require.Equal(t, 1, count, "exit must store 1 intro point state")
}

// Test_TOR_HS_EstablishIntroPoint_ServiceNotFound tests the case where the hidden service does not exist.
func Test_TOR_HS_EstablishIntroPoint_ServiceNotFound(t *testing.T) {
	client, _, _, _, circID := Build3HopCircuit(t)

	err := client.Peer.EstablishIntroPoint("nonexistent-service", circID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown serviceID")
}

// Test_TOR_HS_EstablishIntroPoint_UnknownCircuit_Error tests the case where the circuit ID is unknown.
func Test_TOR_HS_EstablishIntroPoint_UnknownCircuit_Error(t *testing.T) {
	client, _, _, _, _ := Build3HopCircuit(t)

	serviceID, err := client.Peer.CreateHiddenService()
	require.NoError(t, err)

	// invalid circuit ID
	err = client.Peer.EstablishIntroPoint(serviceID, 9999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no crypto state")
}

// Test_TOR_HS_EstablishIntroPoint_Multiple tests establishing multiple introduction points for a hidden service.
func Test_TOR_HS_EstablishIntroPoint_Multiple(t *testing.T) {
	transp := channelFac()

	// client
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	// First circuit: guard1 → middle1 → exit1
	guard1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard1.Stop()
	middle1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle1.Stop()
	exit1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit1.Stop()

	// Second circuit: guard2 → middle2 → exit2
	guard2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard2.Stop()
	middle2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle2.Stop()
	exit2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit2.Stop()

	// Full mesh so Tor cells can route
	nodes := []z.TestNode{
		client,
		guard1, middle1, exit1,
		guard2, middle2, exit2,
	}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)

	// Populate onion keys for all nodes
	populateOnionKeys(nodes)

	// Build two circuits on the SAME client, but with different exits
	hops1 := [3]string{guard1.GetAddr(), middle1.GetAddr(), exit1.GetAddr()}
	hops2 := [3]string{guard2.GetAddr(), middle2.GetAddr(), exit2.GetAddr()}

	circID1, err := client.Peer.BuildCircuit(hops1, 5*time.Second)
	require.NoError(t, err)

	circID2, err := client.Peer.BuildCircuit(hops2, 5*time.Second)
	require.NoError(t, err)

	require.Equal(t, 2, client.Peer.GetClientCircuitsNbr())

	// One hidden service, multiple intro points
	serviceID, err := client.Peer.CreateHiddenService()
	require.NoError(t, err)

	require.NoError(t, client.Peer.EstablishIntroPoint(serviceID, circID1))
	require.NoError(t, client.Peer.EstablishIntroPoint(serviceID, circID2))

	time.Sleep(200 * time.Millisecond)

	intros := client.Peer.GetServiceIntroPoints(serviceID)
	require.Len(t, intros, 2)
	require.Contains(t, intros, exit1.GetAddr())
	require.Contains(t, intros, exit2.GetAddr())

	count1 := exit1.Peer.GetIntroPointStateCount(serviceID)
	count2 := exit2.Peer.GetIntroPointStateCount(serviceID)
	require.Equal(t, 1, count1)
	require.Equal(t, 1, count2)
}

// Test_TOR_HS_DescriptorExpired tests the case where a hidden service descriptor expires.
func Test_TOR_HS_DescriptorExpired(t *testing.T) {
	client, _, _, _, _ := Build3HopCircuit(t)

	serviceID, _ := client.Peer.CreateHiddenService()

	// Build descriptor that expires immediately
	err := client.Peer.BuildServiceDescriptor(serviceID, []string{"or1"}, 0)
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)

	ok, _ := client.Peer.LookupDescriptor(serviceID)
	require.False(t, ok, "descriptor should be expired")
}

// Test_TOR_HS_DescriptorPublish_AndLookup tests the process of publishing a hidden service descriptor and looking it up
func Test_TOR_HS_DescriptorPublish_AndLookup(t *testing.T) {
	client, _, _, exit, _ := Build3HopCircuit(t)

	serviceID, err := client.Peer.CreateHiddenService()
	require.NoError(t, err)

	introORs := []string{"or1", "or2"}

	// Build descriptor (stored internally)
	err = client.Peer.BuildServiceDescriptor(serviceID, introORs, time.Minute)
	require.NoError(t, err)

	// Lookup via global accessor
	// Even another node, besides the one who created the descriptor should be able to find it.
	ok, found := exit.Peer.LookupDescriptor(serviceID)
	require.True(t, ok)
	require.NotNil(t, found)

	require.Equal(t, introORs, found)
}
