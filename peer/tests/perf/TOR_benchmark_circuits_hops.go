//go:build performance
// +build performance

package perf

import "testing"

const (
	LatencyPackets = 100
	PayloadSize    = 300
	MinHops        = 3
	MaxHops        = 7
)

func init() {
	os.Setenv("GLOG", "no")
}

// BuildNHopCircuit builds n-hop circuit to be used in benchmark tests.
// relays include the middle nodes and the exit node.
func BuildNHopCircuit(t *testing.T, n int) (client z.TestNode, relays []z.TestNode, exit z.TestNode, circID uint16) {
	require.GreaterOrEqual(t, n, 3)
	transp := channelFac()

	client = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	relays = make([]z.TestNode, n)
	for i := 0; i < n; i++ {
		relays[i] = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	}

	t.Cleanup(func() {
		for _, node := range relays {
			node.Stop()
		}
	})

	// Full mesh routing
	nodes := append([]z.TestNode{client}, relays...)
	for i, n1 := range nodes {
		for j, n2 := range nodes {
			if i != j {
				n1.AddPeer(n2.GetAddr())
			}
		}
	}

	time.Sleep(100 * time.Millisecond)

	// Populate onion keys
	z.PopulateOnionKeys(nodes)

	hops := make([]string, n)
	for i := 0; i < n; i++ {
		hops[i] = relays[i].GetAddr()
	}

	var err error
	circID, err = client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	exit = relays[n-1]
	return client, relays, exit, circID
}

func Benchmark_TOR_Circuits(b *testing.B, plot bool) {
	latencyMap := RunBenchmarkLatency(b)
	RunBenchmarkThroughput(b)
}

func RunBenchmarkLatency(b *testing.B) map[int]float64 {
	results := make(map[int]float64)

	for hops := MinHops; hops <= MaxHops; hops++ {
		client, _, _, circID := z.BuildNHopCircuit(t, hops)

		streamID, err := client.Peer.OpenStream(circID, "latency:test")
		require.NoError(t, err)

		payload := make([]byte, PayloadSize)
		var total time.Duration

		// Warm-up
		time.Sleep(300 * time.Millisecond)

		for i := 0; i < LatencyPackets; i++ {
			start := time.Now()

			err = client.Peer.SendStreamData(circID, streamID, payload)
			require.NoError(t, err)

			// Wait for echo
			for {
				pkts, _ := client.Peer.GetReceivedStreamPackets(circID, streamID)
				if len(pkts) > i {
					break
				}
				time.Sleep(1 * time.Millisecond)
			}

			total += time.Since(start)
		}

		avgMs := float64(total.Milliseconds()) / LatencyPackets
		results[hops] = avgMs

		client.Peer.CloseStream(circID, streamID)
		client.Peer.DestroyCircuit(circID)
	}

	return results
}
