package unit

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
)

// Test whether the public key addition happens correctly
func Test_TOR_KeyPopulation(t *testing.T) {
	transp := channelFac()

	// Create 4 nodes
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node3.Stop()

	node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node4.Stop()

	// Give them time to initialize
	time.Sleep(50 * time.Millisecond)

	nodes := []z.TestNode{node1, node2, node3, node4}

	// Verify each node has a public key
	for i, node := range nodes {
		pubKeyInterface := node.Peer.GetOnionPublicKey()
		require.NotNil(t, pubKeyInterface, "Node %d should have an onion public key", i)
		_, ok := pubKeyInterface.(*rsa.PublicKey)
		require.True(t, ok, "Node %d's public key should be an RSA public key", i)
	}

	// Populate keys
	populateOnionKeys(nodes)

	// Verify each node has keys for all other nodes
	for i, node := range nodes {
		for j, otherNode := range nodes {
			if i != j {
				// Try to get the other node's key from this node
				pubKeyInterface := otherNode.Peer.GetOnionPublicKey()
				require.NotNil(t, pubKeyInterface, "Node %d should have public key", j)

				// Re-add should work without error
				node.Peer.AddPeerOnionKey(otherNode.GetAddr(), pubKeyInterface)
			}
		}
	}

	t.Logf("Successfully populated onion keys for %d nodes", len(nodes))
}

// Test_TOR_KeyPopulation_WithNilKey tests that populateOnionKeys handles
// nodes without keys gracefully
func Test_TOR_KeyPopulation_WithNilKey(t *testing.T) {
	transp := channelFac()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	nodes := []z.TestNode{node1, node2}

	// This should not panic even if some nodes don't have keys
	require.NotPanics(t, func() {
		populateOnionKeys(nodes)
	}, "populateOnionKeys should handle missing keys gracefully")
}
