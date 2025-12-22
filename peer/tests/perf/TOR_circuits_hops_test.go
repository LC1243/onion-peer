//go:build performance
// +build performance

package perf

import (
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

const (
	Runs              = 3
	ThroughputPackets = 1000
	LatencyPackets    = 500
	PayloadSize       = 300
	MinHops           = 3
	MaxHops           = 10
)

var plotFlag = false

func init() {
	os.Setenv("GLOG", "no")

	v := os.Getenv("PLOT")
	if v == "1" || v == "true" {
		plotFlag = true
	}
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
		client.Stop()
		for _, node := range relays {
			node.Stop()
		}
	})

	// Enable congestion control on all nodes for consistent performance testing
	client.SetCongestionControl(true)
	for _, node := range relays {
		node.SetCongestionControl(true)
	}

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

func Test_Plot_And_Benchmark_TOR_Circuits(t *testing.T) {
	var latencyRuns []map[int]float64
	var throughputRuns []map[int]float64

	for i := 1; i <= Runs; i++ {
		t.Logf("Latency benchmark run %d/%d", i, Runs)
		latencyRuns = append(latencyRuns, RunBenchmarkLatency(t))

		t.Logf("Throughput benchmark run %d/%d", i, Runs)
		throughputRuns = append(throughputRuns, RunBenchmarkThroughput(t))
	}

	avgLatency := AverageResults(latencyRuns)
	avgThroughput := AverageResults(throughputRuns)

	PrintResults("Average Latency Results", avgLatency, "ms")
	PrintResults("Average Throughput Results", avgThroughput, "kB/s")

	if !plotFlag {
		t.Skip("plotting disabled (set PLOT=1 to enable)")
	}

	t.Logf("Plotting averaged results")
	require.NoError(t, PlotResults(avgLatency, "latency"))
	require.NoError(t, PlotResults(avgThroughput, "throughput"))
}

func RunBenchmarkLatency(b *testing.T) map[int]float64 {
	results := make(map[int]float64)

	for hops := MinHops; hops <= MaxHops; hops++ {
		client, _, _, circID := BuildNHopCircuit(b, hops)

		streamID, err := client.Peer.OpenStream(circID, "latency:test")
		require.NoError(b, err)

		payload := make([]byte, PayloadSize)

		// Wait for stream to be fully established
		ready := false
		for k := 0; k < 50; k++ {
			if client.Peer.HasStream(circID, streamID) {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		require.True(b, ready, "Stream failed to open")

		// Warm-up to establish circuit state
		time.Sleep(300 * time.Millisecond)

		var totalLatency time.Duration
		successfulMeasurements := 0

		for i := 0; i < LatencyPackets; i++ {
			sendTime := time.Now()
			
			err = client.Peer.SendStreamData(circID, streamID, payload)
			require.NoError(b, err)

			timeout := time.After(5 * time.Second)
			ticker := time.NewTicker(1 * time.Millisecond)
			
			received := false
			for !received {
				select {
				case <-timeout:
					b.Logf("Timeout waiting for packet %d on %d hops", i, hops)
					goto nextPacket
				case <-ticker.C:
					pkts, _ := client.Peer.GetReceivedStreamPackets(circID, streamID)
					if len(pkts) > i {
						latency := time.Since(sendTime)
						totalLatency += latency
						successfulMeasurements++
						received = true
					}
				}
			}
			ticker.Stop()
			
			nextPacket:
			// Small delay between measurements
			time.Sleep(10 * time.Millisecond)
		}

		if successfulMeasurements > 0 {
			avgMs := float64(totalLatency.Nanoseconds()) / 1e6 / float64(successfulMeasurements)
			results[hops] = avgMs
			b.Logf("Hops: %d, Successful: %d/%d, Avg Latency: %.2f ms", 
				hops, successfulMeasurements, LatencyPackets, avgMs)
		} else {
			results[hops] = 0
			b.Logf("Hops: %d, No successful measurements", hops)
		}

		client.Peer.CloseStream(circID, streamID)
		client.Peer.DestroyCircuit(circID)
	}
	return results
}

func RunBenchmarkThroughput(b *testing.T) map[int]float64 {
	results := make(map[int]float64)

	for hops := MinHops; hops <= MaxHops; hops++ {
		client, _, _, circID := BuildNHopCircuit(b, hops)

		streamID, err := client.Peer.OpenStream(circID, "throughput:test")
		require.NoError(b, err)

		ready := false
		for k := 0; k < 50; k++ {
			if client.Peer.HasStream(circID, streamID) {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		require.True(b, ready, "Stream failed to open for %d hops", hops)

		payload := make([]byte, PayloadSize)
		
		// Use adaptive packet count based on circuit complexity
		// Fewer packets for longer circuits to keep test duration reasonable
		packetsToSend := ThroughputPackets
		//if hops > 6 {
		//	packetsToSend = ThroughputPackets / 2 // Half packets for 7+ hops
		//}
		//if hops > 8 {
		//	packetsToSend = ThroughputPackets / 4 // Quarter packets for 9+ hops
		//}
		
		// More conservative scaling for longer circuits to prevent overwhelming
		baseDelay := 200 * time.Microsecond
		hopPenalty := time.Duration(hops * 100) * time.Microsecond 
		sendDelay := baseDelay + hopPenalty
		
		b.Logf("Testing %d hops with %d packets and send delay %v", hops, packetsToSend, sendDelay)

		time.Sleep(200 * time.Millisecond)

		var sendStart, sendEnd time.Time
		var packetsSent int
		
		sendDone := make(chan struct{})
		
		go func() {
			defer close(sendDone)
			sendStart = time.Now()
			
			for i := 0; i < packetsToSend; i++ {
				// Retry mechanism for flow control: more retries for longer circuits
				maxRetries := 5 + hops*2
				success := false
				
				for retry := 0; retry < maxRetries; retry++ {
					err := client.Peer.SendStreamData(circID, streamID, payload)
					if err == nil {
						packetsSent++
						success = true
						break
					}

					backoff := time.Duration((retry+1)*hops) * 5 * time.Millisecond
					time.Sleep(backoff)
				}
				
				if !success {
					b.Logf("Failed to send packet %d after %d retries on %d hops", i, maxRetries, hops)
				}
				
				// avoid overwhelming longer circuits
				time.Sleep(sendDelay)
			}
			sendEnd = time.Now()
		}()

		// Wait for sending to complete
		<-sendDone
		
		// Wait additional time for packets to traverse the circuit
		drainTime := time.Duration(1000 + hops*300) * time.Millisecond
		time.Sleep(drainTime)

		// Monitor packet reception with reasonable timeout
		timeoutSeconds := 20 + hops*5 // Much more reasonable timeout
		timeout := time.After(time.Duration(timeoutSeconds) * time.Second)
		ticker := time.NewTicker(50 * time.Millisecond)
		
		var finalReceived int
		var lastReceived int
		stableCount := 0
		
		for {
			select {
			case <-timeout:
				b.Logf("Timeout for %d hops - received %d/%d packets", hops, finalReceived, packetsSent)
				goto measurementDone
				
			case <-ticker.C:
				pkts, err := client.Peer.GetReceivedStreamPackets(circID, streamID)
				if err == nil {
					finalReceived = len(pkts)
					
					if finalReceived >= packetsSent {
						goto measurementDone
					}
					
					if finalReceived == lastReceived {
						stableCount++
						stabilityThreshold := 20 + hops*10
						if stableCount > stabilityThreshold {
							goto measurementDone
						}
					} else {
						stableCount = 0
						lastReceived = finalReceived
					}
				}
			}
		}
		
		measurementDone:
		ticker.Stop()
		
		sendDuration := sendEnd.Sub(sendStart).Seconds()
		
		if finalReceived > 0 && sendDuration > 0 {
			bytesReceived := float64(finalReceived * PayloadSize)
			kbps := (bytesReceived / 1024.0) / sendDuration
			results[hops] = kbps
			
			lossRate := float64(packetsSent - finalReceived) / float64(packetsSent) * 100.0
			b.Logf("Hops: %d, Sent: %d, Received: %d, Loss: %.1f%%, Throughput: %.2f kB/s", 
				hops, packetsSent, finalReceived, lossRate, kbps)
		} else {
			results[hops] = 0
			b.Logf("Hops: %d, Sent: %d, Received: %d, Throughput: 0.00 kB/s", 
				hops, packetsSent, finalReceived)
		}

		client.Peer.CloseStream(circID, streamID)
		client.Peer.DestroyCircuit(circID)
		
		// Clean shutdown between tests
		time.Sleep(100 * time.Millisecond)
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

	outDir := "results/"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	filename := fmt.Sprintf("%s/%s_vs_hops.png", outDir, plotType)
	return p.Save(6*vg.Inch, 4*vg.Inch, filename)
}

func AverageResults(runs []map[int]float64) map[int]float64 {
	avg := make(map[int]float64)

	if len(runs) == 0 {
		return avg
	}

	for _, run := range runs {
		for hops, value := range run {
			avg[hops] += value
		}
	}

	for hops := range avg {
		avg[hops] /= float64(len(runs))
	}

	return avg
}

func PrintResults(title string, results map[int]float64, unit string) {
	fmt.Printf("\n=== %s ===\n", title)

	keys := make([]int, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	for _, hops := range keys {
		fmt.Printf("Hops: %2d -> %.2f %s\n", hops, results[hops], unit)
	}
}
