//go:build performance
// +build performance

package perf

import (
	"os"
	"testing"
	"time"
	"sort"
	"fmt"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

const (
	ThroughputPackets = 1000
	LatencyPackets    = 100
	PayloadSize       = 300
	MinHops           = 3
	MaxHops           = 10
)

func init() {
	os.Setenv("GLOG", "no")
}

// BuildNHopCircuit builds n-hop circuit to be used in benchmark tests.
// relays include the middle nodes and the exit node.
func BuildNHopCircuit(t *testing.B, n int) (client z.TestNode, relays []z.TestNode, exit z.TestNode, circID uint16) {
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

// If you want to plot the results, run this test
func Test_Plot_And_Benchmark_TOR_Circuits(b *testing.B) {
	latencyMap := RunBenchmarkLatency(b)
	ThroughputMap := RunBenchmarkThroughput(b)

	PlotResults(latencyMap, "latency")
	PlotResults(ThroughputMap, "throughput")
}

func Benchmark_TOR_Circuits(b *testing.B) {
	RunBenchmarkLatency(b)
	RunBenchmarkThroughput(b)
}

func RunBenchmarkLatency(b *testing.B) map[int]float64 {
	results := make(map[int]float64)

	for hops := MinHops; hops <= MaxHops; hops++ {
		client, _, _, circID := BuildNHopCircuit(b, hops)

		streamID, err := client.Peer.OpenStream(circID, "latency:test")
		require.NoError(b, err)

		payload := make([]byte, PayloadSize)
		var total time.Duration

		// Warm-up
		time.Sleep(300 * time.Millisecond)

		for i := 0; i < LatencyPackets; i++ {
			start := time.Now()

			err = client.Peer.SendStreamData(circID, streamID, payload)
			require.NoError(b, err)

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

func RunBenchmarkThroughput(b *testing.B) map[int]float64 {
	results := make(map[int]float64)

	for hops := MinHops; hops <= MaxHops; hops++ {
		client, _, _, circID := BuildNHopCircuit(b, hops)

		streamID, err := client.Peer.OpenStream(circID, "throughput:test")
		require.NoError(b, err)

		payload := make([]byte, PayloadSize)

		// Warm-up
		time.Sleep(300 * time.Millisecond)

		start := time.Now()
		for i := 0; i < ThroughputPackets; i++ {
			err = client.Peer.SendStreamData(circID, streamID, payload)
			require.NoError(b, err)
		}

		// Wait for all echos
		for {
			pkts, _ := client.Peer.GetReceivedStreamPackets(circID, streamID)
			if len(pkts) >= ThroughputPackets {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

		elapsed := time.Since(start).Seconds()
		kb := float64(ThroughputPackets*PayloadSize) / 1024.0
		kbps := kb / elapsed
		results[hops] = kbps

		client.Peer.CloseStream(circID, streamID)
		client.Peer.DestroyCircuit(circID)
	}
	return results
}

func PlotResults(results map[int]float64, plotType string) error {
	points := make(plotter.XYs, 0, len(results))
	for hops, value := range results {
		points = append(points, plotter.XY{
			X: float64(hops),
			Y: value,
		})
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].X < points[j].X
	})

	p := plot.New()

	switch plotType {
	case "latency":
		p.Title.Text = "Latency vs Circuit Length"
		p.X.Label.Text = "Number of hops"
		p.Y.Label.Text = "Average latency (ms)"
	case "throughput":
		p.Title.Text = "Throughput vs Circuit Length"
		p.X.Label.Text = "Number of hops"
		p.Y.Label.Text = "Throughput (kB/s)"
	default:
		return fmt.Errorf("invalid type: %s", plotType)
	}

	line, _ := plotter.NewLine(points)
	scatter, _ := plotter.NewScatter(points)

	p.Add(line, scatter, plotter.NewGrid())

	filename := fmt.Sprintf("perf/results/%s_vs_hops.png", plotType)
	return p.Save(6*vg.Inch, 4*vg.Inch, filename)
}
