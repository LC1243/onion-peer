package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_TOR_HS_EstablishIntroPoint_Basic(t *testing.T) {
	client, _, _, exit, circID := Build3HopCircuit(t)

	// Bob creates hidden service → returns serviceID only
	serviceID, err := client.Peer.CreateHiddenService()
	require.NoError(t, err)
	require.NotEmpty(t, serviceID)

	// Establish intro point
	err = client.Peer.EstablishIntroPoint(serviceID, circID)
	require.NoError(t, err)

	// Let RelayEstablishIntro propagate to exit
	time.Sleep(200 * time.Millisecond)

	// 1. Client-side intro point recording
	introPoints := client.Peer.GetServiceIntroPoints(serviceID)
	require.Len(t, introPoints, 1, "service must have exactly 1 intro point")
	require.Equal(t, exit.GetAddr(), introPoints[0])

	// 2. Exit node must have stored intro state
	count := exit.Peer.GetIntroPointStateCount(serviceID)
	require.Equal(t, 1, count, "exit must store 1 intro point state")
}

func Test_TOR_HS_EstablishIntroPoint_ServiceNotFound(t *testing.T) {
	client, _, _, _, circID := Build3HopCircuit(t)

	err := client.Peer.EstablishIntroPoint("nonexistent-service", circID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown serviceID")
}

func Test_TOR_HS_EstablishIntroPoint_UnknownCircuit_Error(t *testing.T) {
	client, _, _, _, _ := Build3HopCircuit(t)

	serviceID, err := client.Peer.CreateHiddenService()
	require.NoError(t, err)

	// invalid circuit ID
	err = client.Peer.EstablishIntroPoint(serviceID, 9999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no crypto state")
}

func Test_TOR_HS_DescriptorPublish_AndLookup(t *testing.T) {
	client, _, _, _, _ := Build3HopCircuit(t)

	serviceID, err := client.Peer.CreateHiddenService()
	require.NoError(t, err)

	introORs := []string{"or1", "or2"}

	// Build descriptor (stored internally)
	err = client.Peer.BuildServiceDescriptor(serviceID, introORs, time.Minute)
	require.NoError(t, err)

	// Publish descriptor globally
	ok := client.Peer.GetPublishedDescriptor(serviceID)
	require.True(t, ok, "descriptor should be published")

	// Lookup via global accessor
	ok, found := client.Peer.LookupDescriptor(serviceID)
	require.True(t, ok)
	require.NotNil(t, found)

	require.ElementsMatch(t, introORs, found)
}
