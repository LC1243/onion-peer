package unit

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
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

	ok, _, _ := client.Peer.LookupDescriptor(circID, serviceID, time.Second)
	require.True(t, ok)

	time.Sleep(2 * time.Second)

	ok, _, _ = client.Peer.LookupDescriptor(circID, serviceID, time.Second)
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

	ok, found, _ := lookupClient.Peer.LookupDescriptor(
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
	ok, introORs, _ := client.Peer.LookupDescriptor(
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

		ok, found, _ := lc.Peer.LookupDescriptor(
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
	ok, introORs, _ := client.Peer.LookupDescriptor(
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
	ok, introORs, _ := client.Peer.LookupDescriptor(
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
	ok, found, _ := client.Peer.LookupDescriptor(
		circID,
		serviceID,
		time.Second,
	)
	require.Greater(t, len(hsDir.GetOuts()), hsdirOutsBefore+1, "should have sent multiple relay cells")
	require.Greater(t, len(client.GetIns()), clientInsBefore+1, "should have received multiple relay cells")

	require.True(t, ok)
	require.Equal(t, introORs, found)
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

	cookie, err := client.Peer.PrepareRendezvousPoint(circID, 2*time.Second)

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

	cookie, err := client.Peer.PrepareRendezvousPoint(circID, 1*time.Nanosecond)

	require.Error(t, err)
	require.Equal(t, cookie, [20]byte{}, "Cookie should be empty on error")
	require.Contains(t, err.Error(), "timed out")

	time.Sleep(200 * time.Millisecond) // Give time for any async operations

	// Exit node still should have a rendezvous point recorded
	exitEntriesCount := exit.Peer.GetRendezvousEntriesCount()
	require.Equal(t, 1, exitEntriesCount, "Exit should have 1 rendezvous point")
}

// Test_TOR_HS_EncodeDecodeServiceIntroductionMessage_Succeeds tests encoding and decoding of a
// Service Introduction Message
func Test_TOR_HS_EncodeDecodeServiceIntroductionMessage_Succeeds(t *testing.T) {
	cookie := [20]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	RPAddr := "rendezvous.example.onion:1234"
	clientDHPub := []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc3, 0x5d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c}

	msg := impl.ServiceIntroduceMessage{
		Cookie:      cookie,
		RPAddr:      RPAddr,
		ClientDHPub: clientDHPub,
	}

	encoded, err := impl.EncodeServiceIntroduceMessage(&msg)
	require.NoError(t, err)
	decoded, err := impl.DecodeServiceIntroduceMessage(encoded)
	require.NoError(t, err)

	require.Equal(t, msg.Cookie, decoded.Cookie, "Cookies should match")
	require.Equal(t, msg.RPAddr, decoded.RPAddr, "RP addresses should match")
	require.Equal(t, msg.ClientDHPub, decoded.ClientDHPub, "Client DH public keys should match")
}

// Test_TOR_HS_EncodeDecodeIPIntroductionMessage_Succeeds tests encoding and decoding of an
// IP Introduction Message
func Test_TO_HS_EncodeDecodeIPIntroductionMessage_Succeeds(t *testing.T) {
	serviceID := "42"
	encryptedBlob := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}

	msg := impl.IPIntroduceMessage{
		ServiceID:     serviceID,
		EncryptedBlob: encryptedBlob,
	}

	encoded, err := impl.EncodeIPIntroduceMessage(&msg)
	require.NoError(t, err)
	decoded, err := impl.DecodeIPIntroduceMessage(encoded)
	require.NoError(t, err)

	require.Equal(t, msg.ServiceID, decoded.ServiceID, "Service IDs should match")
	require.Equal(t, msg.EncryptedBlob, decoded.EncryptedBlob, "Encrypted blobs should match")
}

// Test_TOR_HS_IntroduceToHiddenService_NoSuchService_Fails tests introducing to a non-existent hidden service
func Test_TOR_HS_IntroduceToHiddenService_NoIntroPoints_Fails(t *testing.T) {
	transp := channelFac()

	// Create introduction point circuit nodes
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()
	IPGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer IPGuard.Stop()
	IPMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer IPMiddle.Stop()
	IP := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer IP.Stop()

	// Create rendezvous point circuit nodes
	RPGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer RPGuard.Stop()
	RPMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer RPMiddle.Stop()
	RP := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer RP.Stop()

	// Set up the nodes
	nodes := []z.TestNode{client, IPGuard, IPMiddle, IP, RPGuard, RPMiddle, RP}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	RPCircID, err := client.Peer.BuildCircuit(
		[3]string{RPGuard.GetAddr(), RPMiddle.GetAddr(), RP.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)
	IPCircID, err := client.Peer.BuildCircuit(
		[3]string{IPGuard.GetAddr(), IPMiddle.GetAddr(), IP.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	// Get cookie and set up RP
	cookie, err := client.Peer.PrepareRendezvousPoint(RPCircID, 2*time.Second)
	require.NoError(t, err)

	// Create a fake service ID
	serviceID := "42"
	keyPair, err := impl.GenerateServiceKeyPair()
	require.NoError(t, err)
	servicePubKey := x509.MarshalPKCS1PublicKey(keyPair.Public)

	// The introduction should send a false Introduce ACK back since it do not contain any intro points info
	err = client.Peer.IntroduceToHiddenService(IPCircID, serviceID, servicePubKey, cookie, RP.GetAddr(), time.Second)
	require.Error(t, err)
	require.Contains(t, err.Error(), "introduction failed according to ACK")
}

// Test_TOR_HS_IntroduceToHiddenService_Succeeds tests that a client introducing to an existing hidden service
// with available intro points succeeds. It covers the full flow of creating the hidden service, publishing its
// descriptor, looking up the descriptor from the client, and performing the introduction but does not cover
// the rendezvous establishment.
func Test_TOR_HS_IntroduceToHiddenService_Succeeds(t *testing.T) {
	transp := channelFac()

	// Hidden service <-> HSDir circuit nodes
	service := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer service.Stop()
	serviceHSDirGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer serviceHSDirGuard.Stop()
	serviceHSDirMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer serviceHSDirMiddle.Stop()
	HSDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer HSDir.Stop()
	HSDir.Peer.SetPeerAsHSDir(true)

	// Client <-> HSDir circuit nodes
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()
	clientHSDirGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientHSDirGuard.Stop()
	clientHSDirMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientHSDirMiddle.Stop()

	// Client <-> Rendezvous Point circuit nodes
	clientRPGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientRPGuard.Stop()
	clientRPMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientRPMiddle.Stop()
	RP := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer RP.Stop()

	// Hidden service <-> Intro Point circuit nodes
	serviceIntroGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer serviceIntroGuard.Stop()
	serviceIntroMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer serviceIntroMiddle.Stop()
	IntroPoint := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer IntroPoint.Stop()

	// Client <-> Intro Point circuit nodes
	clientIntroGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientIntroGuard.Stop()
	clientIntroMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientIntroMiddle.Stop()

	// Set up the nodes
	nodes := []z.TestNode{
		client, service,
		HSDir, serviceHSDirGuard, serviceHSDirMiddle, clientHSDirGuard, clientHSDirMiddle,
		IntroPoint, serviceIntroGuard, serviceIntroMiddle, clientIntroGuard, clientIntroMiddle,
		RP, clientRPGuard, clientRPMiddle,
	}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(1 * time.Second)
	z.PopulateOnionKeys(nodes)

	// Create the circuits
	serviceHSDirCircID, err := service.Peer.BuildCircuit(
		[3]string{serviceHSDirGuard.GetAddr(), serviceHSDirMiddle.GetAddr(), HSDir.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	clientHSDirCircID, err := client.Peer.BuildCircuit(
		[3]string{clientHSDirGuard.GetAddr(), clientHSDirMiddle.GetAddr(), HSDir.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	clientIntroCircID, err := client.Peer.BuildCircuit(
		[3]string{clientIntroGuard.GetAddr(), clientIntroMiddle.GetAddr(), IntroPoint.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	clientRPCircID, err := client.Peer.BuildCircuit(
		[3]string{clientRPGuard.GetAddr(), clientRPMiddle.GetAddr(), RP.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	// Create the hidden service with one intro point and publish its descriptor
	introHops := [][3]string{
		{serviceIntroGuard.GetAddr(), serviceIntroMiddle.GetAddr(), IntroPoint.GetAddr()},
	}

	serviceID, serverIntroCircID, err := service.Peer.CreateHiddenService(
		introHops,
		5*time.Second,
		time.Minute,
		serviceHSDirCircID,
	)
	require.NoError(t, err)
	require.NotEmpty(t, serviceID)
	require.Len(t, serverIntroCircID, 1)

	// Service local intro point recorded
	intros := service.Peer.GetServiceIntroPoints(serviceID)
	require.Len(t, intros, 1)
	require.Equal(t, IntroPoint.GetAddr(), intros[0])

	// Intro point store the intro state
	require.Equal(t, 1, IntroPoint.Peer.GetIntroPointStateCount(serviceID))

	// Descriptor published and retrievable from client via HSDir
	ok, introORs, servicePubKey := client.Peer.LookupDescriptor(
		clientHSDirCircID,
		serviceID,
		time.Second,
	)
	require.True(t, ok)
	require.Len(t, introORs, 1)
	require.Equal(t, IntroPoint.GetAddr(), introORs[0])

	// Prepare rendezvous point
	cookie, err := client.Peer.PrepareRendezvousPoint(clientRPCircID, 2*time.Second)
	require.NoError(t, err)

	// Check initial packet counts
	clientSentBefore := len(client.GetOuts())
	clientReceivedBefore := len(client.GetOuts())
	introRecvBefore := len(IntroPoint.GetIns())
	introSentBefore := len(IntroPoint.GetOuts())

	// Introduce to hidden service
	err = client.Peer.IntroduceToHiddenService(clientIntroCircID, serviceID, servicePubKey,
		cookie, "rendezvous.example.onion:1234", time.Second)
	require.NoError(t, err)

	// Check packet counts after
	clientSentAfter := len(client.GetOuts())
	clientReceivedAfter := len(client.GetOuts())
	introRecvAfter := len(IntroPoint.GetIns())
	introSentAfter := len(IntroPoint.GetOuts())

	require.Equal(t, clientSentAfter-clientSentBefore, 1, "Client should have sent 1 packet")
	require.Equal(t, clientReceivedAfter-clientReceivedBefore, 1,
		"Client should have received 1 packet")
	require.Equal(t, introRecvAfter-introRecvBefore, 1, "Intro point should have received 1 packet")
	require.Equal(t, introSentAfter-introSentBefore, 2, "Intro point should have sent 2 packets")
}

// Test_TOR_HS_IntroduceToHiddenService_SmallTimeout_Fails tests that introducing to a hidden service
// with a too small timeout fails.
func Test_TOR_HS_IntroduceToHiddenService_SmallTimeout_Fails(t *testing.T) {
	transp := channelFac()

	// Hidden service <-> HSDir circuit nodes
	service := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer service.Stop()
	serviceHSDirGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer serviceHSDirGuard.Stop()
	serviceHSDirMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer serviceHSDirMiddle.Stop()
	HSDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer HSDir.Stop()
	HSDir.Peer.SetPeerAsHSDir(true)

	// Client <-> HSDir circuit nodes
	client := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer client.Stop()
	clientHSDirGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientHSDirGuard.Stop()
	clientHSDirMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientHSDirMiddle.Stop()

	// Client <-> Rendezvous Point circuit nodes
	clientRPGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientRPGuard.Stop()
	clientRPMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientRPMiddle.Stop()
	RP := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer RP.Stop()

	// Hidden service <-> Intro Point circuit nodes
	serviceIntroGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer serviceIntroGuard.Stop()
	serviceIntroMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer serviceIntroMiddle.Stop()
	IntroPoint := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer IntroPoint.Stop()

	// Client <-> Intro Point circuit nodes
	clientIntroGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientIntroGuard.Stop()
	clientIntroMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer clientIntroMiddle.Stop()

	// Set up the nodes
	nodes := []z.TestNode{
		client, service,
		HSDir, serviceHSDirGuard, serviceHSDirMiddle, clientHSDirGuard, clientHSDirMiddle,
		IntroPoint, serviceIntroGuard, serviceIntroMiddle, clientIntroGuard, clientIntroMiddle,
		RP, clientRPGuard, clientRPMiddle,
	}
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}
	time.Sleep(1 * time.Second)
	z.PopulateOnionKeys(nodes)

	// Create the circuits
	serviceHSDirCircID, err := service.Peer.BuildCircuit(
		[3]string{serviceHSDirGuard.GetAddr(), serviceHSDirMiddle.GetAddr(), HSDir.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	clientHSDirCircID, err := client.Peer.BuildCircuit(
		[3]string{clientHSDirGuard.GetAddr(), clientHSDirMiddle.GetAddr(), HSDir.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	clientIntroCircID, err := client.Peer.BuildCircuit(
		[3]string{clientIntroGuard.GetAddr(), clientIntroMiddle.GetAddr(), IntroPoint.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	clientRPCircID, err := client.Peer.BuildCircuit(
		[3]string{clientRPGuard.GetAddr(), clientRPMiddle.GetAddr(), RP.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	// Create the hidden service with one intro point and publish its descriptor
	introHops := [][3]string{
		{serviceIntroGuard.GetAddr(), serviceIntroMiddle.GetAddr(), IntroPoint.GetAddr()},
	}

	serviceID, serverIntroCircID, err := service.Peer.CreateHiddenService(
		introHops,
		5*time.Second,
		time.Minute,
		serviceHSDirCircID,
	)
	require.NoError(t, err)
	require.NotEmpty(t, serviceID)
	require.Len(t, serverIntroCircID, 1)

	// Service local intro point recorded
	intros := service.Peer.GetServiceIntroPoints(serviceID)
	require.Len(t, intros, 1)
	require.Equal(t, IntroPoint.GetAddr(), intros[0])

	// Intro point store the intro state
	require.Equal(t, 1, IntroPoint.Peer.GetIntroPointStateCount(serviceID))

	// Descriptor published and retrievable from client via HSDir
	ok, introORs, servicePubKey := client.Peer.LookupDescriptor(
		clientHSDirCircID,
		serviceID,
		time.Second,
	)
	require.True(t, ok)
	require.Len(t, introORs, 1)
	require.Equal(t, IntroPoint.GetAddr(), introORs[0])

	// Prepare rendezvous point
	cookie, err := client.Peer.PrepareRendezvousPoint(clientRPCircID, 2*time.Second)
	require.NoError(t, err)

	// Check initial packet counts
	clientSentBefore := len(client.GetOuts())
	clientReceivedBefore := len(client.GetOuts())
	introRecvBefore := len(IntroPoint.GetIns())
	introSentBefore := len(IntroPoint.GetOuts())

	// Introduce to hidden service
	err = client.Peer.IntroduceToHiddenService(clientIntroCircID, serviceID, servicePubKey,
		cookie, "rendezvous.example.onion:1234", time.Nanosecond) // too small timeout
	require.Error(t, err)
	require.Contains(t, err.Error(), "timed out")

	time.Sleep(200 * time.Millisecond) // Give time for any async operations

	// Check packet counts after
	clientSentAfter := len(client.GetOuts())
	clientReceivedAfter := len(client.GetOuts())
	introRecvAfter := len(IntroPoint.GetIns())
	introSentAfter := len(IntroPoint.GetOuts())

	// Intro point still should have received the introduction and sent the ACK and intro2 messages
	require.Equal(t, clientSentAfter-clientSentBefore, 1, "Client should have sent 1 packet")
	require.Equal(t, clientReceivedAfter-clientReceivedBefore, 1,
		"Client should have received 1 (after the timeout)")
	require.Equal(t, introRecvAfter-introRecvBefore, 1, "Intro point should have received 1 packet")
	require.Equal(t, introSentAfter-introSentBefore, 2, "Intro point should have sent 2 packets")
}

// Test_TOR_HS_Rendezvous_FullHandshake_Succeeds tests the full rendezvous handshake:
//  1. Bob creates a hidden service and publishes its descriptor to an HSDir
//  2. Bob establishes an introduction point for the service
//  3. Alice builds a circuit to a rendezvous point (RP)
//  4. Alice prepares the rendezvous point and obtains a cookie
//  5. Alice builds a circuit to the introduction point
//  6. Alice sends an INTRODUCE1 message containing the rendezvous cookie and RP address
//  7. The introduction point forwards INTRODUCE2 to Bob
//  8. Bob connects to the rendezvous point and sends RENDEZVOUS1
//  9. The rendezvous point forwards RENDEZVOUS2 to Alice
//  10. Alice extends her RP circuit with a new crypto state shared with Bob
func Test_TOR_HS_Rendezvous_FullHandshake_Succeeds(t *testing.T) {
	transp := channelFac()

	// Alice (client)
	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer alice.Stop()

	// Bob
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer bob.Stop()

	// Bob -> HSDir
	hsGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsGuard.Stop()
	hsMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsMiddle.Stop()
	hsDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsDir.Stop()

	hsDir.Peer.SetPeerAsHSDir(true)

	// Bob -> Introduction Point
	guardIntro := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guardIntro.Stop()
	middleIntro := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middleIntro.Stop()
	introPoint := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer introPoint.Stop()

	// Alice -> Rendezvous point
	guardRp := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guardRp.Stop()
	middleRp := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middleRp.Stop()
	rp := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer rp.Stop()

	// Alice -> Introduction Point
	guardAliceIntro := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guardAliceIntro.Stop()
	middleAliceIntro := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middleAliceIntro.Stop()

	nodes := []z.TestNode{
		alice, bob,
		hsGuard, hsMiddle, hsDir,
		guardIntro, middleIntro, introPoint,
		guardRp, middleRp, rp,
		guardAliceIntro, middleAliceIntro,
	}

	for _, n := range nodes {
		for _, m := range nodes {

			if n == m {
				continue
			}
			// Alice <-> Bob can't be neighbors
			if (n == alice && m == bob) || (n == bob && m == alice) {
				continue
			}

			n.AddPeer(m.GetAddr())
		}
	}

	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	// Bob creates a circuit to HSDir
	circID, err := bob.Peer.BuildCircuit(
		[3]string{hsGuard.GetAddr(), hsMiddle.GetAddr(), hsDir.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	// Bob creates a hidden service with one introduction point
	introPoints := [][3]string{{guardIntro.GetAddr(), middleIntro.GetAddr(), introPoint.GetAddr()}}
	serviceID, _, err := bob.Peer.CreateHiddenService(
		introPoints, 5*time.Second, time.Minute, circID)
	require.NoError(t, err)

	// Alice builds a circuit to the RP
	aliceRPCirc, err := alice.Peer.BuildCircuit(
		[3]string{guardRp.GetAddr(), middleRp.GetAddr(), rp.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	// Alice establishes a rendezvous point
	cookie, err := alice.Peer.PrepareRendezvousPoint(aliceRPCirc, time.Second)
	require.NoError(t, err)

	// Alice builds a circuit to the introduction point
	aliceIntroCirc, err := alice.Peer.BuildCircuit(
		[3]string{guardAliceIntro.GetAddr(), middleAliceIntro.GetAddr(), introPoint.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	aliceOutsBefore := len(alice.GetOuts())
	aliceInsBefore := len(alice.GetIns())

	bobOutsBefore := len(bob.GetOuts())
	bobInsBefore := len(bob.GetIns())

	rpOutsBefore := len(rp.GetOuts())
	rpInsBefore := len(rp.GetIns())

	introOutsBefore := len(introPoint.GetOuts())
	introInsBefore := len(introPoint.GetIns())

	// Alice sends Introduce1
	cryptoStateBefore := alice.Peer.GetCircuitCryptoStatesCount(aliceRPCirc)

	err = alice.Peer.IntroduceToHiddenService(
		aliceIntroCirc,
		serviceID,
		bob.Peer.GetServicePublicKey(serviceID),
		cookie,
		rp.GetAddr(),
		time.Second,
	)
	require.NoError(t, err)

	time.Sleep(300 * time.Millisecond)

	require.Equal(t, aliceOutsBefore+1, len(alice.GetOuts()),
		"Alice should've sent INTRODUCE1")
	require.Equal(t, aliceInsBefore+2, len(alice.GetIns()),
		"Alice should've received INTRODUCE_ACK and RENDEZVOUS2")

	// Bob should receive INTRODUCE2 and send RENDEZVOUS1 (besides the cells related to circuit creation, Bob->RP)
	require.GreaterOrEqual(t, len(bob.GetIns()), bobInsBefore+1,
		"Bob must receive at least one INTRODUCE2-related cell")
	require.GreaterOrEqual(t, len(bob.GetOuts()), bobOutsBefore+1,
		"Bob must send at least one RENDEZVOUS1-related cell")

	require.GreaterOrEqual(t, len(rp.GetIns()), rpInsBefore+2, "RP should receive CREATE and RENDEZVOUS1")
	require.GreaterOrEqual(t, len(rp.GetOuts()), rpOutsBefore+2, "RP should send CREATED and RENDEZVOUS2")

	require.Equal(t, introInsBefore+1, len(introPoint.GetIns()),
		"Introduction point should receive exactly one INTRODUCE1")
	require.Equal(t, introOutsBefore+2, len(introPoint.GetOuts()),
		"Introduction point should send INTRODUCE2 and INTRODUCE_ACK")

	require.Equal(t, cryptoStateBefore+1, alice.Peer.GetCircuitCryptoStatesCount(aliceRPCirc),
		"rendezvous must extend Alice circuit")
}

// Test_TOR_HS_Rendezvous_WrongCookie tests the case when Alice tries to introduce to Bob using a wrong cookie.
// Ending up in a failed establishment of communication between Alice and Bob.
func Test_TOR_HS_Rendezvous_WrongCookie(t *testing.T) {
	transp := channelFac()

	// Alice (client)
	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer alice.Stop()

	// Bob
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer bob.Stop()

	// Bob -> HSDir
	hsGuard := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsGuard.Stop()
	hsMiddle := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsMiddle.Stop()
	hsDir := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer hsDir.Stop()
	hsDir.Peer.SetPeerAsHSDir(true)

	// Bob -> Introduction Point
	guardIntro := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guardIntro.Stop()
	middleIntro := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middleIntro.Stop()
	introPoint := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer introPoint.Stop()

	// Alice -> Rendezvous Point
	guardRp := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guardRp.Stop()
	middleRp := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middleRp.Stop()
	rp := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer rp.Stop()

	// Alice -> Introduction Point
	guardAliceIntro := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer guardAliceIntro.Stop()
	middleAliceIntro := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer middleAliceIntro.Stop()

	nodes := []z.TestNode{
		alice, bob,
		hsGuard, hsMiddle, hsDir,
		guardIntro, middleIntro, introPoint,
		guardRp, middleRp, rp,
		guardAliceIntro, middleAliceIntro,
	}
	for _, n := range nodes {
		for _, m := range nodes {
			if n != m {
				n.AddPeer(m.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
	z.PopulateOnionKeys(nodes)

	// Bob circuit to HSDir
	hsDirCirc, err := bob.Peer.BuildCircuit(
		[3]string{hsGuard.GetAddr(), hsMiddle.GetAddr(), hsDir.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	// Bob creates HS with introPoint
	introPoints := [][3]string{{guardIntro.GetAddr(), middleIntro.GetAddr(), introPoint.GetAddr()}}
	serviceID, _, err := bob.Peer.CreateHiddenService(introPoints, 5*time.Second, time.Minute, hsDirCirc)
	require.NoError(t, err)

	// Alice circuit to RP
	aliceRPCirc, err := alice.Peer.BuildCircuit(
		[3]string{guardRp.GetAddr(), middleRp.GetAddr(), rp.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	// Alice prepares RP (creates a valid cookie, but we won't use it)
	_, err = alice.Peer.PrepareRendezvousPoint(aliceRPCirc, time.Second)
	require.NoError(t, err)

	// Alice circuit to introPoint
	aliceIntroCirc, err := alice.Peer.BuildCircuit(
		[3]string{guardAliceIntro.GetAddr(), middleAliceIntro.GetAddr(), introPoint.GetAddr()},
		5*time.Second,
	)
	require.NoError(t, err)

	// Use wrong cookie
	var wrongCookie [20]byte
	copy(wrongCookie[:], []byte("this-cookie-is-wrong!!"))

	cryptoBefore := alice.Peer.GetCircuitCryptoStatesCount(aliceRPCirc)

	err = alice.Peer.IntroduceToHiddenService(
		aliceIntroCirc,
		serviceID,
		bob.Peer.GetServicePublicKey(serviceID),
		wrongCookie,
		rp.GetAddr(),
		time.Second,
	)
	// Rendezvous must fail: no RENDEZVOUS2.
	require.Error(t, err)

	time.Sleep(400 * time.Millisecond)

	require.Equal(t, cryptoBefore, alice.Peer.GetCircuitCryptoStatesCount(aliceRPCirc),
		"Alice RP circuit must NOT extend if cookie is unknown at RP")
}
