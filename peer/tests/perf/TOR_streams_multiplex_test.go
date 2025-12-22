//go:build performance
// +build performance

package perf

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

const (
	StreamMultiplexRuns             = 3
	StreamMultiplexHops             = 3
	StreamMultiplexPayloadSize      = 300
	StreamMultiplexPacketsPerStream = 200

	MinStreams = 2
	MaxStreams = 80
)

var streamPlotFlag = false

func init() {
	v := os.Getenv("PLOT")
	if v == "1" || v == "true" {
		streamPlotFlag = true
	}
}

// Test written primarily using copilot assistance.

// Test_Plot_And_Benchmark_TOR_Stream_Multiplex measures the performance impact
// of multiplexing multiple streams over a single 3-hop circuit.
func Test_Plot_And_Benchmark_TOR_Stream_Multiplex(t *testing.T) {
	var latencyRuns []map[int]float64
	var throughputRuns []map[int]float64

	for i := 1; i <= StreamMultiplexRuns; i++ {
		t.Logf("Stream multiplex latency benchmark run %d/%d", i, StreamMultiplexRuns)
		latencyRuns = append(latencyRuns, RunBenchmarkStreamMultiplexLatency(t))

		t.Logf("Stream multiplex throughput benchmark run %d/%d", i, StreamMultiplexRuns)
		throughputRuns = append(throughputRuns, RunBenchmarkStreamMultiplexThroughput(t))
	}

	avgLatency := AverageStreamResults(latencyRuns)
	avgThroughput := AverageStreamResults(throughputRuns)

	PrintStreamResults("Average Stream Multiplex Latency Results", avgLatency, "ms")
	PrintStreamResults("Average Stream Multiplex Throughput Results", avgThroughput, "kB/s")

	if !streamPlotFlag {
		t.Skip("plotting disabled (set PLOT=1 to enable)")
	}

	t.Logf("Plotting averaged stream multiplex results")
	require.NoError(t, PlotStreamMultiplexResults(avgLatency, "stream_multiplex_latency"))
	require.NoError(t, PlotStreamMultiplexResults(avgThroughput, "stream_multiplex_throughput"))
}

// RunBenchmarkStreamMultiplexLatency measures the latency for different numbers of streams
// multiplexed over a single 3-hop circuit.
func RunBenchmarkStreamMultiplexLatency(t *testing.T) map[int]float64 {
	results := make(map[int]float64)

	for numStreams := MinStreams; numStreams <= MaxStreams; numStreams = numStreams + 8 {
		t.Logf("Testing latency with %d streams", numStreams)

		// Build a single 3-hop circuit
		client, _, _, circID, cleanup := BuildNHopCircuit(t, StreamMultiplexHops)

		// Open all streams
		streamIDs := make([]uint16, numStreams)
		for i := 0; i < numStreams; i++ {
			streamID, err := client.Peer.OpenStream(circID, fmt.Sprintf("latency:stream%d", i))
			require.NoError(t, err)
			streamIDs[i] = streamID
		}

		// Wait for all streams to be fully established
		time.Sleep(500 * time.Millisecond)
		for _, streamID := range streamIDs {
			require.True(t, client.Peer.HasStream(circID, streamID), "Stream %d should be open", streamID)
		}

		payload := make([]byte, StreamMultiplexPayloadSize)

		var totalLatency time.Duration
		successfulMeasurements := 0

		// Measure latency by sending packets on all streams in round-robin fashion
		packetsPerStream := StreamMultiplexPacketsPerStream / numStreams
		if packetsPerStream < 10 {
			packetsPerStream = 10
		}

		for pkt := 0; pkt < packetsPerStream; pkt++ {
			for streamIdx, streamID := range streamIDs {
				// Clear any previous received packets before measurement
				initialCount := 0
				pkts, err := client.Peer.GetReceivedStreamPackets(circID, streamID)
				if err == nil {
					initialCount = len(pkts)
				}

				sendTime := time.Now()

				err = client.Peer.SendStreamData(circID, streamID, payload)
				require.NoError(t, err, "Failed to send on stream %d", streamID)

				// Wait for the echo to come back
				timeout := time.After(5 * time.Second)
				ticker := time.NewTicker(1 * time.Millisecond)

				received := false
				for !received {
					select {
					case <-timeout:
						t.Logf("Timeout waiting for packet on stream %d (streams=%d, pkt=%d)", streamIdx, numStreams, pkt)
						goto nextPacket
					case <-ticker.C:
						pkts, err := client.Peer.GetReceivedStreamPackets(circID, streamID)
						if err == nil && len(pkts) > initialCount {
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
				time.Sleep(5 * time.Millisecond)
			}
		}

		if successfulMeasurements > 0 {
			avgMs := float64(totalLatency.Nanoseconds()) / 1e6 / float64(successfulMeasurements)
			results[numStreams] = avgMs
			t.Logf("Streams: %d, Successful: %d, Avg Latency: %.2f ms",
				numStreams, successfulMeasurements, avgMs)
		} else {
			results[numStreams] = 0
			t.Logf("Streams: %d, No successful measurements", numStreams)
		}

		// Cleanup
		for _, streamID := range streamIDs {
			client.Peer.CloseStream(circID, streamID)
		}
		client.Peer.DestroyCircuit(circID)
		if cleanup != nil {
			cleanup()
		}
		time.Sleep(200 * time.Millisecond)
	}
	return results
}

// RunBenchmarkStreamMultiplexThroughput measures the aggregate throughput for different
// numbers of streams multiplexed over a single 3-hop circuit.
func RunBenchmarkStreamMultiplexThroughput(t *testing.T) map[int]float64 {
	results := make(map[int]float64)

	for numStreams := MinStreams; numStreams <= MaxStreams; numStreams = numStreams + 8 {
		t.Logf("Testing throughput with %d streams", numStreams)

		// Build a single 3-hop circuit
		client, _, _, circID, cleanup := BuildNHopCircuit(t, StreamMultiplexHops)

		// Open all streams
		streamIDs := make([]uint16, numStreams)
		for i := 0; i < numStreams; i++ {
			streamID, err := client.Peer.OpenStream(circID, fmt.Sprintf("throughput:stream%d", i))
			require.NoError(t, err)
			streamIDs[i] = streamID
		}

		// Wait for all streams to be fully established
		time.Sleep(500 * time.Millisecond)
		for _, streamID := range streamIDs {
			require.True(t, client.Peer.HasStream(circID, streamID), "Stream %d should be open", streamID)
		}

		payload := make([]byte, StreamMultiplexPayloadSize)

		// Calculate packets per stream
		packetsPerStream := StreamMultiplexPacketsPerStream

		// Use a wait group to send on all streams concurrently
		var wg sync.WaitGroup
		var sendStart, sendEnd time.Time
		var totalPacketsSent int
		var mu sync.Mutex

		sendStart = time.Now()

		for streamIdx, streamID := range streamIDs {
			wg.Add(1)
			go func(idx int, sid uint16) {
				defer wg.Done()

				localSent := 0
				for pkt := 0; pkt < packetsPerStream; pkt++ {
					// Retry mechanism for flow control
					maxRetries := 10
					success := false

					for retry := 0; retry < maxRetries && !success; retry++ {
						err := client.Peer.SendStreamData(circID, sid, payload)
						if err == nil {
							localSent++
							success = true
						} else {
							time.Sleep(time.Duration(retry*50) * time.Millisecond)
						}
					}

					// Adaptive delay based on number of streams to prevent congestion
					baseDelay := 500 * time.Microsecond
					streamPenalty := time.Duration(numStreams*50) * time.Microsecond
					time.Sleep(baseDelay + streamPenalty)
				}

				mu.Lock()
				totalPacketsSent += localSent
				mu.Unlock()

				t.Logf("Stream %d sent %d/%d packets", idx, localSent, packetsPerStream)
			}(streamIdx, streamID)
		}

		// Wait for all goroutines to complete
		wg.Wait()
		sendEnd = time.Now()

		duration := sendEnd.Sub(sendStart)
		totalBytes := totalPacketsSent * StreamMultiplexPayloadSize

		if duration.Seconds() > 0 {
			throughputKBps := float64(totalBytes) / 1024.0 / duration.Seconds()
			results[numStreams] = throughputKBps
			t.Logf("Streams: %d, Packets sent: %d/%d, Duration: %v, Throughput: %.2f kB/s",
				numStreams, totalPacketsSent, numStreams*packetsPerStream, duration, throughputKBps)
		} else {
			results[numStreams] = 0
			t.Logf("Streams: %d, Duration too short to measure", numStreams)
		}

		// Cleanup
		for _, streamID := range streamIDs {
			client.Peer.CloseStream(circID, streamID)
		}
		client.Peer.DestroyCircuit(circID)
		if cleanup != nil {
			cleanup()
		}
		time.Sleep(200 * time.Millisecond)
	}
	return results
}

// PlotStreamMultiplexResults creates a plot for stream multiplex performance
func PlotStreamMultiplexResults(results map[int]float64, metric string) error {
	p := plot.New()

	var xlabel, ylabel, filename string
	switch metric {
	case "stream_multiplex_latency":
		xlabel = "Number of Streams"
		ylabel = "Average Latency (ms)"
		filename = "results/stream_multiplex_latency.png"
		p.Title.Text = "Stream Multiplexing: Latency vs Number of Streams (3-hop circuit)"
	case "stream_multiplex_throughput":
		xlabel = "Number of Streams"
		ylabel = "Aggregate Throughput (kB/s)"
		filename = "results/stream_multiplex_throughput.png"
		p.Title.Text = "Stream Multiplexing: Throughput vs Number of Streams (3-hop circuit)"
	default:
		return fmt.Errorf("unknown metric: %s", metric)
	}

	p.X.Label.Text = xlabel
	p.Y.Label.Text = ylabel

	// Convert map to sorted slice
	var streams []int
	for s := range results {
		streams = append(streams, s)
	}
	sort.Ints(streams)

	pts := make(plotter.XYs, len(streams))
	for i, s := range streams {
		pts[i].X = float64(s)
		pts[i].Y = results[s]
	}

	line, err := plotter.NewLine(pts)
	if err != nil {
		return err
	}
	line.LineStyle.Width = vg.Points(2)
	p.Add(line)

	scatter, err := plotter.NewScatter(pts)
	if err != nil {
		return err
	}
	p.Add(scatter)

	// Create results directory if it doesn't exist
	os.MkdirAll("results", 0755)

	if err := p.Save(8*vg.Inch, 6*vg.Inch, filename); err != nil {
		return err
	}

	return nil
}

// AverageStreamResults calculates the average results across multiple runs
// for stream multiplex benchmarks (keyed by number of streams)
func AverageStreamResults(runs []map[int]float64) map[int]float64 {
	if len(runs) == 0 {
		return make(map[int]float64)
	}

	avgResults := make(map[int]float64)

	// Get all stream counts from the first run
	for numStreams := range runs[0] {
		var sum float64
		count := 0

		// Sum values across all runs for this stream count
		for _, run := range runs {
			if val, exists := run[numStreams]; exists {
				sum += val
				count++
			}
		}

		// Calculate average
		if count > 0 {
			avgResults[numStreams] = sum / float64(count)
		}
	}

	return avgResults
}

// PrintStreamResults prints the results in a formatted table
// for stream multiplex benchmarks (keyed by number of streams)
func PrintStreamResults(title string, results map[int]float64, unit string) {
	fmt.Printf("\n=== %s ===\n", title)

	// Get sorted stream counts
	var streams []int
	for s := range results {
		streams = append(streams, s)
	}
	sort.Ints(streams)

	// Print each result
	for _, s := range streams {
		fmt.Printf("Streams: %2d -> %.2f %s\n", s, results[s], unit)
	}
	fmt.Println()
}
