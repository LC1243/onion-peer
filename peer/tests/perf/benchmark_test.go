//go:build performance
// +build performance

package perf

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
)

func init() {
	os.Setenv("GLOG", "no")
}

// Build3HopCircuit builds a 3-hop circuit for use by benchmarks.
func Build3HopCircuit(t *testing.T) (client, guard, middle, exit z.TestNode, circID uint16) {
	transp := channelFac()

	client = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	guard = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	middle = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	exit = z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	t.Cleanup(func() {
		client.Stop()
		guard.Stop()
		middle.Stop()
		exit.Stop()
	})

	// Full mesh routing
	nodes := []z.TestNode{client, guard, middle, exit}
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

	hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}

	var err error
	circID, err = client.Peer.BuildCircuit(hops, 5*time.Second)
	require.NoError(t, err)

	return client, guard, middle, exit, circID
}

func BenchmarkLatency(b *testing.B) {
	runLatencyBenchmark(b, true)
	runLatencyBenchmark(b, false)
}

func runLatencyBenchmark(b *testing.B, congestionControl bool) {
	name := "CongestionControl_Enabled"
	if !congestionControl {
		name = "CongestionControl_Disabled"
	}

	b.Run(name, func(b *testing.B) {
		// Setup nodes
		transp := channelFac()
		client := z.NewTestNode(b, peerFac, transp, "127.0.0.1:0")
		guard := z.NewTestNode(b, peerFac, transp, "127.0.0.1:0")
		middle := z.NewTestNode(b, peerFac, transp, "127.0.0.1:0")
		exit := z.NewTestNode(b, peerFac, transp, "127.0.0.1:0")

		nodes := []z.TestNode{client, guard, middle, exit}
		for _, n := range nodes {
			n.Peer.SetCongestionControl(congestionControl)
		}

		b.Cleanup(func() {
			client.Stop()
			guard.Stop()
			middle.Stop()
			exit.Stop()
		})

		// Full mesh routing
		for i, n1 := range nodes {
			for j, n2 := range nodes {
				if i != j {
					n1.AddPeer(n2.GetAddr())
				}
			}
		}

		time.Sleep(100 * time.Millisecond)
		z.PopulateOnionKeys(nodes)

		hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}
		payload := []byte("ping")

		var totalColdTime time.Duration
		var totalHotTime time.Duration
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			start := time.Now()
			// Measure time for circuit creation + 1 packet round trip
			circID, err := client.Peer.BuildCircuit(hops, 5*time.Second)
			require.NoError(b, err)

			streamID, err := client.Peer.OpenStream(circID, "dummy:1234")
			require.NoError(b, err)

			// Wait for stream to be ready
			ready := false
			for k := 0; k < 50; k++ {
				if client.Peer.HasStream(circID, streamID) {
					ready = true
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			require.True(b, ready, "Stream failed to open")

			err = client.Peer.SendStreamData(circID, streamID, payload)
			require.NoError(b, err)

			// Wait for echo
			timeout := time.After(5 * time.Second)
			ticker := time.NewTicker(10 * time.Millisecond)
			
			received := false
			for !received {
				select {
				case <-timeout:
					b.Fatal("Timeout waiting for echo")
				case <-ticker.C:
					pkts, err := client.Peer.GetReceivedStreamPackets(circID, streamID)
					if err == nil && len(pkts) >= 1 {
						received = true
					}
				}
			}
			ticker.Stop()
			totalColdTime += time.Since(start)

			// Hot path: send another packet on existing circuit
			hotStart := time.Now()
			err = client.Peer.SendStreamData(circID, streamID, payload)
			require.NoError(b, err)

			timeout2 := time.After(5 * time.Second)
			ticker2 := time.NewTicker(10 * time.Millisecond)
			received2 := false
			for !received2 {
				select {
				case <-timeout2:
					b.Fatal("Timeout waiting for second echo")
				case <-ticker2.C:
					pkts, err := client.Peer.GetReceivedStreamPackets(circID, streamID)
					if err == nil && len(pkts) >= 2 {
						received2 = true
					}
				}
			}
			ticker2.Stop()
			totalHotTime += time.Since(hotStart)
		}

		if b.N > 0 {
			b.ReportMetric(float64(totalColdTime.Nanoseconds())/1e6/float64(b.N), "cold_latency_ms")
			b.ReportMetric(float64(totalHotTime.Nanoseconds())/1e6/float64(b.N), "hot_latency_ms")
		}
	})
}

func BenchmarkThroughput(b *testing.B) {
	runThroughputBenchmark(b, true)
	runThroughputBenchmark(b, false)
}

func runThroughputBenchmark(b *testing.B, congestionControl bool) {
	name := "CongestionControl_Enabled"
	if !congestionControl {
		name = "CongestionControl_Disabled"
	}

	b.Run(name, func(b *testing.B) {
		// Setup nodes
		transp := channelFac()
		
		client := z.NewTestNode(b, peerFac, transp, "127.0.0.1:0")
		guard := z.NewTestNode(b, peerFac, transp, "127.0.0.1:0")
		middle := z.NewTestNode(b, peerFac, transp, "127.0.0.1:0")
		exit := z.NewTestNode(b, peerFac, transp, "127.0.0.1:0")

		nodes := []z.TestNode{client, guard, middle, exit}
		for _, n := range nodes {
			n.Peer.SetCongestionControl(congestionControl)
		}

		b.Cleanup(func() {
			client.Stop()
			guard.Stop()
			middle.Stop()
			exit.Stop()
		})

		// Full mesh routing
		for i, n1 := range nodes {
			for j, n2 := range nodes {
				if i != j {
					n1.AddPeer(n2.GetAddr())
				}
			}
		}

		time.Sleep(100 * time.Millisecond)
		z.PopulateOnionKeys(nodes)

		hops := [3]string{guard.GetAddr(), middle.GetAddr(), exit.GetAddr()}
		
		circID, err := client.Peer.BuildCircuit(hops, 5*time.Second)
		require.NoError(b, err)
		require.NoError(b, err)

		streamID, err := client.Peer.OpenStream(circID, "dummy:1234")
		require.NoError(b, err)

		// Wait for stream to be ready
		ready := false
		for k := 0; k < 50; k++ {
			if client.Peer.HasStream(circID, streamID) {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		require.True(b, ready, "Stream failed to open")

		// Prepare payload
		payloadSize := 400 // Reduced from 1024 to fit in a single cell
		b.SetBytes(int64(payloadSize))
		payload := make([]byte, payloadSize)
		
		// Determine delay based on congestion control setting
		var sendDelay time.Duration
		if congestionControl {
			// With congestion control, we can try to send faster and rely on the window
			// We add a tiny delay just to yield CPU
			sendDelay = 10 * time.Microsecond
		} else {
			// Without congestion control, we must limit rate to avoid packet loss
			// 35us is the experimental limit (30us causes loss)
			sendDelay = 35 * time.Microsecond
		}

		b.ResetTimer()
		
		// Send b.N packets
		for i := 0; i < b.N; i++ {
			// Retry sending if it fails (e.g. due to flow control)
			for {
				err := client.Peer.SendStreamData(circID, streamID, payload)
				if err == nil {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}

			time.Sleep(sendDelay)
		}
		
		// Wait for packets to drain with a timeout
		timeout := time.After(5 * time.Second)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		
		var finalReceived int
		done := false
		for !done {
			select {
			case <-timeout:
				done = true
			case <-ticker.C:
				pkts, err := client.Peer.GetReceivedStreamPackets(circID, streamID)
				if err == nil {
					finalReceived = len(pkts)
					if finalReceived >= b.N {
						done = true
					}
				}
			}
		}

		loss := b.N - finalReceived
		lossPct := float64(loss) / float64(b.N) * 100.0
		
		b.ReportMetric(float64(lossPct), "loss_pct")
		b.ReportMetric(float64(finalReceived), "pkts_recv")

		if b.N > 0 {
			msPerOp := float64(b.Elapsed().Nanoseconds()) / 1e6 / float64(b.N)
			b.ReportMetric(msPerOp, "ms/op")
		}
		
		if loss > 0 {
			b.Logf("Packet Loss Detected: Sent=%d, Recv=%d, Loss=%d (%.2f%%)", 
				b.N, finalReceived, loss, lossPct)
		} else {
			b.Logf("Success: Sent=%d, Recv=%d, Loss=0%%", b.N, finalReceived)
		}
	})
}
