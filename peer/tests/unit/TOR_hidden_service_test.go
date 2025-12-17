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
// High-level test for Hidden Service creation.
func Test_TOR_HS_Create_HiddenService_Basic(t *testing.T) {
	transp := channelFac()

	// build circuit to HSDir
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()
	hsGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsGuard.Stop()
	hsMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsMiddle.Stop()
	hsDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsDir.Stop()

	hsDir.Peer.SetPeerAsHSDir(true)

	// circuit to the introduction point
	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard.Stop()
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle.Stop()
	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit.Stop()

	nodes := []z.TestNode{
		client,
		hsGuard, hsMiddle, hsDir,
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

	hops := [3]string{
		hsGuard.GetAddr(), hsMiddle.GetAddr(), hsDir.GetAddr(),
	}

	introCircID, err := client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	introHops := [][3]string{
		{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()},
	}

	serviceID, circuits, err := client.Peer.CreateHiddenService(
		introHops,
		5*time.Second,
		time.Minute,
		introCircID,
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
		introCircID, // reuse circuit to HSDir
		serviceID,
		time.Second,
	)
	require.True(t, ok)
	require.Len(t, introORs, 1)
	require.Equal(t, exit.GetAddr(), introORs[0])
}

// Test_TOR_HS_CreateHiddenService_MultipleIntroPoints tests the creation of a hidden service with multiple intro points
// A client publishes a service with 2 introduction points available, and then 3 clients attempt to look it up, being
// able to find the 2 introduction points available for that service.
func Test_TOR_HS_Create_HiddenService_MultipleIntroPoints(t *testing.T) {
	transp := channelFac()

	// Publisher client, builds circuit to HSDir
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()
	hsGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsGuard.Stop()
	hsMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsMiddle.Stop()
	hsDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsDir.Stop()

	hsDir.Peer.SetPeerAsHSDir(true)

	// Introduction point paths
	guard1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	guard2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	// Lookup clients
	lookup1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer lookup1.Stop()
	lookup2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer lookup2.Stop()
	lookup3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer lookup3.Stop()

	nodes := []z.TestNode{
		client,
		hsGuard, hsMiddle, hsDir,
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

	hops := [3]string{
		hsGuard.GetAddr(), hsMiddle.GetAddr(), hsDir.GetAddr(),
	}

	introCircID, err := client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	introPaths := [][3]string{
		{guard1.GetAddr(), middle1.GetAddr(), exit1.GetAddr()},
		{guard2.GetAddr(), middle2.GetAddr(), exit2.GetAddr()},
	}

	// Create the hidden service
	serviceID, circuits, err := client.Peer.CreateHiddenService(
		introPaths,
		5*time.Second,
		time.Minute,
		introCircID,
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
			[3]string{guard1.GetAddr(), middle1.GetAddr(), hsDir.GetAddr()},
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
	hsGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsGuard.Stop()
	hsMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsMiddle.Stop()
	hsDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsDir.Stop()

	hsDir.Peer.SetPeerAsHSDir(true)

	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard.Stop()
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middle.Stop()
	exit := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer exit.Stop()

	nodes := []z.TestNode{
		client,
		hsGuard, hsMiddle, hsDir,
		guard, middle, exit}

	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	hops := [3]string{
		hsGuard.GetAddr(), hsMiddle.GetAddr(), hsDir.GetAddr(),
	}

	introCircID, err := client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	// Create HS with one intro point
	serviceID, circuits, err := client.Peer.CreateHiddenService(
		[][3]string{
			{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()},
		},
		5*time.Second,
		time.Minute,
		introCircID,
	)
	require.NoError(t, err)
	require.Len(t, circuits, 1)

	require.Len(t, client.Peer.GetServiceIntroPoints(serviceID), 1)
	require.Equal(t, 1, exit.Peer.GetIntroPointStateCount(serviceID))

	err = client.Peer.DeleteHiddenService(serviceID, introCircID)
	require.NoError(t, err)

	// Hidden service must be gone locally
	require.Nil(t, client.Peer.GetServiceIntroPoints(serviceID))

	// Intro circuit should be destroyed (only the circuit to HSDir should exist)
	require.Equal(t, []uint16{introCircID}, client.Peer.GetCircuitIDs())

	// Descriptor should not be available via HSDir
	ok, introORs := client.Peer.LookupDescriptor(
		introCircID, // reuse circuit to HSDir
		serviceID,
		time.Second,
	)
	require.False(t, ok)
	require.Len(t, introORs, 0)
	require.Nil(t, introORs)
}

// Test_TOR_HS_DeleteHiddenService_MultipleIntroPoints tests deletion
// of a hidden service with multiple intro points.
func Test_TOR_HS_Delete_HiddenService_MultipleIntroPoints(t *testing.T) {
	transp := channelFac()

	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()
	hsGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsGuard.Stop()
	hsMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsMiddle.Stop()
	hsDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsDir.Stop()

	hsDir.Peer.SetPeerAsHSDir(true)

	guard1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	guard2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	nodes := []z.TestNode{
		client,
		hsGuard, hsMiddle, hsDir,
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

	hops := [3]string{
		hsGuard.GetAddr(), hsMiddle.GetAddr(), hsDir.GetAddr(),
	}

	introCircID, err := client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	serviceID, circuits, err := client.Peer.CreateHiddenService(
		[][3]string{
			{guard1.GetAddr(), middle1.GetAddr(), exit1.GetAddr()},
			{guard2.GetAddr(), middle2.GetAddr(), exit2.GetAddr()},
		},
		5*time.Second,
		time.Minute,
		introCircID,
	)
	require.NoError(t, err)
	require.Len(t, circuits, 2)

	require.Len(t, client.Peer.GetServiceIntroPoints(serviceID), 2)
	// one circuit to each intro point and one to HSDir
	require.Equal(t, 3, client.Peer.GetClientCircuitsNbr())

	// Delete HS
	err = client.Peer.DeleteHiddenService(serviceID, introCircID)
	require.NoError(t, err)

	// All intro points removed
	require.Nil(t, client.Peer.GetServiceIntroPoints(serviceID))

	// Intro circuits should be destroyed (only the circuit to HSDir should exist)
	require.Equal(t, []uint16{introCircID}, client.Peer.GetCircuitIDs())

	// Descriptor should not be available via HSDir
	ok, introORs := client.Peer.LookupDescriptor(
		introCircID, // reuse circuit to HSDir
		serviceID,
		time.Second,
	)
	require.False(t, ok)
	require.Len(t, introORs, 0)
	require.Nil(t, introORs)
}

// Test_TOR_HS_DeleteHiddenService_NotFound tests deleting a non-existent hidden service
func Test_TOR_HS_Delete_HiddenService_NotFound(t *testing.T) {
	client, _, _, _, circID := Build3HopCircuit(t)

	err := client.Peer.DeleteHiddenService("non-existent-service", circID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// Test_TOR_HS_Descriptor_Fragmentation checks that hidden service descriptors are fragmented correctly.
func Test_TOR_HS_Descriptor_Fragmentation(t *testing.T) {
	transp := channelFac()

	// Publisher client
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()

	// HSDir circuit
	guard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	hsDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guard.Stop()
	defer middle.Stop()
	defer hsDir.Stop()

	hsDir.Peer.SetPeerAsHSDir(true)

	nodes := []z.TestNode{client, guard, middle, hsDir}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	// Build circuit to HSDir
	circID, err := client.Peer.BuildCircuit(
		[3]string{guard.GetAddr(), middle.GetAddr(), hsDir.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	clientOutsBefore := len(client.GetOuts())
	hsdirInsBefore := len(hsDir.GetIns())

	serviceID, err := client.Peer.GenerateHiddenServiceID()
	require.NoError(t, err)

	// Force fragmentation by adding many intro points
	introORs := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		introORs = append(introORs, "intro-or-"+string(rune('A'+i)))
	}

	err = client.Peer.PublishDescriptorToHSDir(
		serviceID,
		introORs,
		time.Minute,
		circID,
		2*time.Second,
	)
	require.NoError(t, err)

	// Assert that more than one relay cell was sent (fragmentation happened)
	clientOutsAfter := len(client.GetOuts())
	require.Greater(
		t,
		clientOutsAfter,
		clientOutsBefore+1,
		"descriptor publish should span multiple relay cells",
	)
	require.Greater(t, len(hsDir.GetIns()), hsdirInsBefore+1, "should have received multiple relay cells")

	clientInsBefore := len(client.GetIns())
	hsdirOutsBefore := len(hsDir.GetOuts())
	// Lookup descriptor
	ok, found := client.Peer.LookupDescriptor(
		circID,
		serviceID,
		time.Second,
	)
	require.Greater(t, len(hsDir.GetOuts()), hsdirOutsBefore+1, "should have sent multiple relay cells")
	require.Greater(t, len(client.GetIns()), clientInsBefore+1, "should have received multiple relay cells")

	require.True(t, ok)
	require.Equal(t, introORs, found)
}
