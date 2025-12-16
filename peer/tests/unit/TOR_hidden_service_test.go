package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
)

// Test_TOR_HS_EstablishIntroPoint_Basic tests the process of establishing an introduction point for a hidden service.
func Test_TOR_HS_Establish_IntroPoint_Basic(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)
	clientOutsBefore := client.GetOuts()
	clientInsBefore := client.GetIns()
	exitInsBefore := exit.GetIns()
	exitOutsBefore := exit.GetOuts()

	serviceID, err := client.Peer.GenerateHiddenServiceID()
	require.NoError(t, err)
	require.NotEmpty(t, serviceID)

	err = client.Peer.EstablishIntroPoint(serviceID, circID, time.Second)
	require.NoError(t, err)
	clientOuts := client.GetOuts()
	require.Len(t, clientOuts, len(clientOutsBefore)+1)

	time.Sleep(200 * time.Millisecond)

	exitIns := exit.GetIns()
	exitOuts := exit.GetOuts()
	clientIns := client.GetIns()

	require.Len(t, exitIns, len(exitInsBefore)+1)
	require.Len(t, exitOuts, len(exitOutsBefore)+1)
	require.Len(t, clientIns, len(clientInsBefore)+1)

	// 1. Client-side intro point recording
	introPoints := client.Peer.GetServiceIntroPoints(serviceID)
	require.Len(t, introPoints, 1, "service must have exactly 1 intro point")
	require.Equal(t, exit.GetAddr(), introPoints[0])

	// 2. Exit node must have stored intro state
	count := exit.Peer.GetIntroPointStateCount(serviceID)
	require.Equal(t, 1, count, "exit must store 1 intro point state")
}

// Test_TOR_HS_EstablishIntroPoint_ServiceNotFound tests the case where the hidden service does not exist.
func Test_TOR_HS_Establish_IntroPoint_ServiceNotFound(t *testing.T) {
	client, _, _, _, circID := Build3HopCircuit(t)

	err := client.Peer.EstablishIntroPoint("nonexistent-service", circID, time.Second)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown serviceID")

	clientIns := client.GetIns()
	clientOuts := client.GetOuts()

	require.Len(t, clientIns, len(clientIns))
	require.Len(t, clientOuts, len(clientOuts))
}

// Test_TOR_HS_EstablishIntroPoint_UnknownCircuit_Error tests the case where the circuit ID is unknown.
func Test_TOR_HS_Establish_IntroPoint_UnknownCircuit_Error(t *testing.T) {
	client, _, _, _, _ := Build3HopCircuit(t)

	serviceID, err := client.Peer.GenerateHiddenServiceID()
	require.NoError(t, err)

	// invalid circuit ID
	err = client.Peer.EstablishIntroPoint(serviceID, 9999, time.Second)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no crypto state")

	clientIns := client.GetIns()
	clientOuts := client.GetOuts()

	require.Len(t, clientIns, len(clientIns))
	require.Len(t, clientOuts, len(clientOuts))
}

// Test_TOR_HS_EstablishIntroPoint_Multiple tests establishing multiple introduction points for a hidden service.
func Test_TOR_HS_Establish_IntroPoint_Multiple(t *testing.T) {
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
	z.PopulateOnionKeys(nodes)

	// Build two circuits on the SAME client, but with different exits
	hops1 := [3]string{guard1.GetAddr(), middle1.GetAddr(), exit1.GetAddr()}
	hops2 := [3]string{guard2.GetAddr(), middle2.GetAddr(), exit2.GetAddr()}

	circID1, err := client.Peer.BuildCircuit(hops1, 5*time.Second)
	require.NoError(t, err)

	circID2, err := client.Peer.BuildCircuit(hops2, 5*time.Second)
	require.NoError(t, err)

	require.Equal(t, 2, client.Peer.GetClientCircuitsNbr())
	clientInsBefore := client.GetIns()
	clientOutsBefore := client.GetOuts()
	exit1InsBefore := exit1.GetIns()
	exit1OutsBefore := exit1.GetOuts()
	exit2InsBefore := exit2.GetIns()
	exit2OutsBefore := exit2.GetOuts()

	// One hidden service, multiple intro points
	serviceID, err := client.Peer.GenerateHiddenServiceID()
	require.NoError(t, err)

	require.NoError(t, client.Peer.EstablishIntroPoint(serviceID, circID1, time.Second))
	require.NoError(t, client.Peer.EstablishIntroPoint(serviceID, circID2, time.Second))

	time.Sleep(200 * time.Millisecond)

	clientIns := client.GetIns()
	clientOuts := client.GetOuts()
	exit1Ins := exit1.GetIns()
	exit1Outs := exit1.GetOuts()
	exit2Ins := exit2.GetIns()
	exit2Outs := exit2.GetOuts()

	require.Len(t, clientOuts, len(clientOutsBefore)+2)
	require.Len(t, clientIns, len(clientInsBefore)+2)
	require.Len(t, exit1Ins, len(exit1InsBefore)+1)
	require.Len(t, exit1Outs, len(exit1OutsBefore)+1)
	require.Len(t, exit2Ins, len(exit2InsBefore)+1)
	require.Len(t, exit2Outs, len(exit2OutsBefore)+1)

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
func Test_TOR_HS_Descriptor_Expired(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	exit.Peer.SetPeerAsHSDir(true)

	serviceID, err := client.Peer.GenerateHiddenServiceID()
	require.NoError(t, err)

	introORs := []string{"or1"}

	// Build descriptor that expires immediately
	err = client.Peer.PublishDescriptorToHSDir(
		serviceID,
		introORs,
		2*time.Second,
		circID,
		1*time.Second,
	)
	require.NoError(t, err)

	ok, _ := client.Peer.LookupDescriptor(circID, serviceID, time.Second)
	require.True(t, ok)

	time.Sleep(2 * time.Second)

	ok, _ = client.Peer.LookupDescriptor(circID, serviceID, time.Second)
	require.False(t, ok)

}

// Test_TOR_HS_DescriptorPublish_AndLookup tests the process of publishing a hidden service descriptor and looking it up
func Test_TOR_HS_Descriptor_Publish_AndLookup(t *testing.T) {
	transp := channelFac()

	// Publisher
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	// Lookup client
	lookupClient := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer lookupClient.Stop()

	// HSDir circuit nodes
	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit.Peer.SetPeerAsHSDir(true)

	nodes := []z.TestNode{
		client, lookupClient,
		guard, middle, exit,
	}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	// Publisher circuit
	publishCircID, err := client.Peer.BuildCircuit(
		[3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	serviceID, err := client.Peer.GenerateHiddenServiceID()
	require.NoError(t, err)

	introORs := []string{"or1", "or2"}

	err = client.Peer.PublishDescriptorToHSDir(
		serviceID,
		introORs,
		time.Minute,
		publishCircID,
		1*time.Second,
	)
	require.NoError(t, err)

	// Lookup circuit (different client)
	lookupCircID, err := lookupClient.Peer.BuildCircuit(
		[3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	ok, found := lookupClient.Peer.LookupDescriptor(
		lookupCircID,
		serviceID,
		time.Second,
	)
	require.True(t, ok)
	require.Equal(t, introORs, found)
}

// Test_TOR_HS_CreateHiddenService_Basic tests the process of a full creation of a hidden service
// It involves creating a circuit, establishing an intro point, and publishing a descriptor.
// High level test for Hidden Service creation.
func Test_TOR_HS_Create_HiddenService_Basic(t *testing.T) {
	transp := channelFac()

	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard.Stop()
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle.Stop()
	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit.Stop()

	// Exit acts as HSDir
	exit.Peer.SetPeerAsHSDir(true)

	nodes := []z.TestNode{
		client,
		guard, middle, exit,
	}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	hops := [][3]string{
		{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()},
	}

	serviceID, circuits, err := client.Peer.CreateHiddenService(
		hops,
		5*time.Second,
		time.Minute,
	)
	require.NoError(t, err)
	require.NotEmpty(t, serviceID)
	require.Len(t, circuits, 1)

	// Local intro point recorded
	intros := client.Peer.GetServiceIntroPoints(serviceID)
	require.Len(t, intros, 1)
	require.Equal(t, exit.GetAddr(), intros[0])

	// Exit stored intro state
	require.Equal(t, 1, exit.Peer.GetIntroPointStateCount(serviceID))

	// Descriptor published and retrievable via HSDir
	ok, introORs := client.Peer.LookupDescriptor(
		circuits[0], // reuse circuit to HSDir
		serviceID,
		time.Second,
	)
	require.True(t, ok)
	require.Len(t, introORs, 1)
	require.Equal(t, exit.GetAddr(), introORs[0])
}

// Test_TOR_HS_CreateHiddenService_MultipleIntroPoints tests the creation of a hidden service with multiple intro points
// High level test for Hidden Service creation.
func Test_TOR_HS_Create_HiddenService_MultipleIntroPoints(t *testing.T) {
	transp := channelFac()

	// Publisher client
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	// Introduction point paths
	guard1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	guard2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	// Exit1 acts as HSDir
	exit1.Peer.SetPeerAsHSDir(true)

	// Lookup clients
	lookup1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer lookup1.Stop()
	lookup2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer lookup2.Stop()
	lookup3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer lookup3.Stop()

	nodes := []z.TestNode{
		client,
		guard1, middle1, exit1,
		guard2, middle2, exit2,
		lookup1, lookup2, lookup3,
	}

	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	introPaths := [][3]string{
		{guard1.GetAddr(), middle1.GetAddr(), exit1.GetAddr()},
		{guard2.GetAddr(), middle2.GetAddr(), exit2.GetAddr()},
	}

	// Create the hidden service
	serviceID, circuits, err := client.Peer.CreateHiddenService(
		introPaths,
		5*time.Second,
		time.Minute,
	)
	require.NoError(t, err)
	require.Len(t, circuits, 2)

	// Publisher-side intro points
	intros := client.Peer.GetServiceIntroPoints(serviceID)
	require.Len(t, intros, 2)
	require.Contains(t, intros, exit1.GetAddr())
	require.Contains(t, intros, exit2.GetAddr())

	// Intro state stored at exits
	require.Equal(t, 1, exit1.Peer.GetIntroPointStateCount(serviceID))
	require.Equal(t, 1, exit2.Peer.GetIntroPointStateCount(serviceID))

	// Lookups by 3 independent clients
	lookupClients := []z.TestNode{lookup1, lookup2, lookup3}

	for _, lc := range lookupClients {
		circID, err := lc.Peer.BuildCircuit(
			[3]string{guard1.GetAddr(), middle1.GetAddr(), exit1.GetAddr()},
			5*time.Second,
		)
		require.NoError(t, err)

		ok, found := lc.Peer.LookupDescriptor(
			circID,
			serviceID,
			time.Second,
		)

		require.True(t, ok)
		require.Len(t, found, 2)
		require.Contains(t, found, exit1.GetAddr())
		require.Contains(t, found, exit2.GetAddr())
	}
}

// Test_TOR_HS_DeleteHiddenService_Basic tests deleting a hidden service
// after it has established introduction points.
func Test_TOR_HS_Delete_HiddenService_Basic(t *testing.T) {
	transp := channelFac()

	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard.Stop()
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle.Stop()
	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit.Stop()

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

	exit.SetPeerAsHSDir(true)

	// Create HS with one intro point
	serviceID, circuits, err := client.Peer.CreateHiddenService(
		[][3]string{
			{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()},
		},
		5*time.Second,
		time.Minute,
	)
	require.NoError(t, err)
	require.Len(t, circuits, 1)

	require.Len(t, client.Peer.GetServiceIntroPoints(serviceID), 1)
	require.Equal(t, 1, exit.Peer.GetIntroPointStateCount(serviceID))

	err = client.Peer.DeleteHiddenService(serviceID)
	require.NoError(t, err)

	// Hidden service must be gone locally
	require.Nil(t, client.Peer.GetServiceIntroPoints(serviceID))

	// Intro circuit should be destroyed
	require.Equal(t, 0, client.Peer.GetClientCircuitsNbr())
}

// Test_TOR_HS_DeleteHiddenService_MultipleIntroPoints tests deletion
// of a hidden service with multiple intro points.
func Test_TOR_HS_Delete_HiddenService_MultipleIntroPoints(t *testing.T) {
	transp := channelFac()

	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	guard1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	guard2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

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
	z.PopulateOnionKeys(nodes)

	exit1.SetPeerAsHSDir(true)
	exit2.SetPeerAsHSDir(true)

	serviceID, circuits, err := client.Peer.CreateHiddenService(
		[][3]string{
			{guard1.GetAddr(), middle1.GetAddr(), exit1.GetAddr()},
			{guard2.GetAddr(), middle2.GetAddr(), exit2.GetAddr()},
		},
		5*time.Second,
		time.Minute,
	)
	require.NoError(t, err)
	require.Len(t, circuits, 2)

	require.Len(t, client.Peer.GetServiceIntroPoints(serviceID), 2)
	require.Equal(t, 2, client.Peer.GetClientCircuitsNbr())

	// Delete HS
	err = client.Peer.DeleteHiddenService(serviceID)
	require.NoError(t, err)

	// All intro points removed
	require.Nil(t, client.Peer.GetServiceIntroPoints(serviceID))

	// All circuits destroyed
	require.Equal(t, 0, client.Peer.GetClientCircuitsNbr())
}

// Test_TOR_HS_DeleteHiddenService_NotFound tests deleting a non-existent hidden service
func Test_TOR_HS_Delete_HiddenService_NotFound(t *testing.T) {
	client, _, _, _, _ := Build3HopCircuit(t)

	err := client.Peer.DeleteHiddenService("non-existent-service")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// Test_TOR_HS_PrepareRendezvousPoint_Succeeds tests preparing a rendezvous point for a hidden service and
// expect it to succeed
func Test_TOR_HS_PrepareRendezvousPoint_Succeeds(t *testing.T) {
	client, guard, middle, exit, circID := Build3HopCircuit(t)

	time.Sleep(100 * time.Millisecond) // Ensure all nodes are ready

	// Check initial packet counts
	clientSentBefore := len(client.GetOuts())
	exitRecvBefore := len(exit.GetIns())
	exitSentBefore := len(exit.GetOuts())

	serviceID := uint16(42)
	cookie, err := client.Peer.PrepareRendezvousPoint(serviceID, circID, 2*time.Second)

	// Check packet counts after
	clientSentAfter := len(client.GetOuts())
	exitRecvAfter := len(exit.GetIns())
	exitSentAfter := len(exit.GetOuts())

	// Client should have sent exactly 1 packet
	require.Equal(t, clientSentBefore+1, clientSentAfter, "Client should have sent 1 packet")

	// Exit should have received exactly 1 packet and sent exactly 1 packet
	require.Equal(t, exitRecvBefore+1, exitRecvAfter, "Exit should have received 1 packet")
	require.Equal(t, exitSentBefore+1, exitSentAfter, "Exit should have sent 1 packet")

	// Should succeed and return a non-empty cookie
	require.NoError(t, err)
	require.NotEqual(t, [20]byte{}, cookie, "Cookie should not be empty")

	// Exit node should have one rendezvous point recorded
	exitEntriesCount := exit.Peer.GetRendezvousEntriesCount()
	require.Equal(t, 1, exitEntriesCount, "Exit should have 1 rendezvous point")

	// Guard and middle nodes should have no rendezvous points recorded
	guardEntriesCount := guard.Peer.GetRendezvousEntriesCount()
	require.Equal(t, 0, guardEntriesCount, "Guard should have 0 rendezvous points")
	middleEntriesCount := middle.Peer.GetRendezvousEntriesCount()
	require.Equal(t, 0, middleEntriesCount, "Middle should have 0 rendezvous points")
}

func Test_TOR_HS_PrepareRendezvousPoint_SmallTimeout_Fails(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	serviceID := uint16(42)
	cookie, err := client.Peer.PrepareRendezvousPoint(serviceID, circID, 1*time.Nanosecond)

	require.Error(t, err)
	require.Equal(t, cookie, [20]byte{}, "Cookie should be empty on error")
	require.Contains(t, err.Error(), "timed out")

	time.Sleep(200 * time.Millisecond) // Give time for any async operations

	// Exit node still should have a rendezvous point recorded
	exitEntriesCount := exit.Peer.GetRendezvousEntriesCount()
	require.Equal(t, 1, exitEntriesCount, "Exit should have 1 rendezvous point")
}
