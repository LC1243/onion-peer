// Package main implements an interactive CLI for the Tor-like onion routing system
package main

import (
	"bufio"
	"crypto/rsa"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/registry/standard"
	"go.dedis.ch/cs438/transport/channel"
)

// Developed and debugged with help of Copilot

var (
	nodes      []peer.Peer
	nodeAddrs  []string
	circuits   map[int]uint16 // map from circuit number to actual circuit ID
	streams    map[int]streamInfo
	nextCircID = 1
	nextStrID  = 1
	log        zerolog.Logger
	reader     *bufio.Reader
)

type streamInfo struct {
	circuitID  uint16
	streamID   uint16
	userCircID int
}

func init() {
	reader = bufio.NewReader(os.Stdin)

	// Configure logger
	level := zerolog.InfoLevel
	if os.Getenv("CLILOG") == "no" {
		level = zerolog.Disabled
	}
	writer := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "", PartsOrder: []string{"message"}}
	log = zerolog.New(writer).Level(level)
}

func main() {
	log.Info().Msg("==============================================")
	log.Info().Msg(" Welcome To TOR! Let's Keep You Anonymous!")
	log.Info().Msg("==============================================")
	log.Info().Msg("")

	// Step 1: Get number of nodes
	numNodes := promptForNodeCount()

	// Step 2: Create nodes
	log.Info().Msgf("\nCreating %d nodes...\n", numNodes)
	createNodes(numNodes)

	// Step 3: Display node addresses
	log.Info().Msg("\nNode addresses:")
	for i, addr := range nodeAddrs {
		log.Info().Msgf("\tNode %d: %s", i+1, addr)
	}

	// Step 4: Populate onion keys
	log.Info().Msg("\nPopulating onion keys...")
	populateOnionKeys()
	log.Info().Msg("All onion keys distributed!")

	// Step 5: Create initial circuit
	log.Info().Msg("\nBuilding initial 3-hop circuit with random nodes...")
	createRandomCircuit()

	// Step 6: Interactive menu
	log.Info().Msg("")
	runInteractiveMenu()

	// Cleanup
	log.Info().Msg("\nCleaning up...")
	cleanupNodes()
	log.Info().Msg("Goodbye!")
}

func promptForNodeCount() int {
	for {
		log.Info().Msg("Enter number of nodes to create (minimum 4): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		num, err := strconv.Atoi(input)
		if err != nil || num < 4 {
			log.Info().Msg("Please enter a valid number (minimum 4)")
			continue
		}
		return num
	}
}

func createNodes(numNodes int) {
	circuits = make(map[int]uint16)
	streams = make(map[int]streamInfo)

	transp := channel.NewTransport()

	for i := range numNodes {
		socket, err := transp.CreateSocket("127.0.0.1:0")
		if err != nil {
			log.Error().Msgf("Failed to create socket for node %d: %v", i+1, err)
			os.Exit(1)
		}

		reg := standard.NewRegistry()

		conf := peer.Configuration{
			Socket:              socket,
			MessageRegistry:     reg,
			AntiEntropyInterval: 0,
			HeartbeatInterval:   0,
			AckTimeout:          time.Second * 3,
			ContinueMongering:   0.5,
		}

		node := impl.NewPeer(conf)

		err = node.Start()
		if err != nil {
			log.Error().Msgf("Failed to start node %d: %v", i+1, err)
			os.Exit(1)
		}

		nodes = append(nodes, node)
		nodeAddrs = append(nodeAddrs, socket.GetAddress())

		log.Info().Msgf("\tNode %d created at %s", i+1, socket.GetAddress())
	}

	// Establish fully connected routing
	log.Info().Msg("\nEstablishing fully connected routing...")
	for i, node1 := range nodes {
		for j, addr2 := range nodeAddrs {
			if i != j {
				node1.AddPeer(addr2)
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
	log.Info().Msg("Fully Connected routing established!")
}

func populateOnionKeys() {
	for i, node := range nodes {
		pubKeyInterface := node.GetOnionPublicKey()
		if pubKeyInterface == nil {
			continue
		}
		pubKey, ok := pubKeyInterface.(*rsa.PublicKey)
		if !ok {
			continue
		}

		for j, otherNode := range nodes {
			if i != j {
				otherNode.AddPeerOnionKey(nodeAddrs[i], pubKey)
			}
		}
	}
}

func createRandomCircuit() {
	if len(nodes) < 4 {
		log.Info().Msg("Need at least 4 nodes (1 client + 3 relays)")
		return
	}

	// Choose client node as the first node
	clientIdx := 0
	client := nodes[clientIdx]

	relayIndices := make([]int, 0, len(nodes)-1)
	for i := 1; i < len(nodes); i++ {
		relayIndices = append(relayIndices, i)
	}

	rand.Shuffle(len(relayIndices), func(i, j int) {
		relayIndices[i], relayIndices[j] = relayIndices[j], relayIndices[i]
	})

	hops := [3]string{
		nodeAddrs[relayIndices[0]],
		nodeAddrs[relayIndices[1]],
		nodeAddrs[relayIndices[2]],
	}

	log.Info().Msgf("  Client: Node 1 (%s)", nodeAddrs[clientIdx])
	log.Info().Msgf("  Guard:  Node %d (%s)", relayIndices[0]+1, hops[0])
	log.Info().Msgf("  Middle: Node %d (%s)", relayIndices[1]+1, hops[1])
	log.Info().Msgf("  Exit:   Node %d (%s)", relayIndices[2]+1, hops[2])

	log.Info().Msg("\nBuilding circuit...")
	circID, err := client.BuildCircuit(hops, 10*time.Second)
	if err != nil {
		log.Error().Msgf("Failed to build circuit: %v", err)
		return
	}

	circuits[nextCircID] = circID
	log.Info().Msgf("Circuit #%d created successfully! (Internal ID: %d)", nextCircID, circID)
	nextCircID++

	time.Sleep(200 * time.Millisecond)
}

func runInteractiveMenu() {
	for {
		log.Info().Msg("\n==============================================")
		log.Info().Msg("  MAIN MENU")
		log.Info().Msg("==============================================")
		log.Info().Msg("1. Create a new circuit")
		log.Info().Msg("2. Create a new stream")
		log.Info().Msg("3. Send a message")
		log.Info().Msg("4. Close a stream")
		log.Info().Msg("5. Close a circuit")
		log.Info().Msg("6. Show status")
		log.Info().Msg("7. Exit")
		log.Info().Msg("==============================================")
		log.Info().Msg("Choose an option (1-7): ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			handleCreateCircuit()
		case "2":
			handleCreateStream()
		case "3":
			handleSendMessage()
		case "4":
			handleCloseStream()
		case "5":
			handleCloseCircuit()
		case "6":
			handleShowStatus()
		case "7":
			return
		default:
			log.Info().Msg("Invalid option. Please choose 1-7.")
		}
	}
}

func handleCreateCircuit() {
	log.Info().Msg("\n--- CREATE NEW CIRCUIT ---")

	if len(nodes) < 4 {
		log.Info().Msg("Need at least 4 nodes")
		return
	}

	// Choose client node as the first node
	clientIdx := 0
	client := nodes[clientIdx]

	relayIndices := make([]int, 0, len(nodes)-1)
	for i := 1; i < len(nodes); i++ {
		relayIndices = append(relayIndices, i)
	}

	rand.Shuffle(len(relayIndices), func(i, j int) {
		relayIndices[i], relayIndices[j] = relayIndices[j], relayIndices[i]
	})

	hops := [3]string{
		nodeAddrs[relayIndices[0]],
		nodeAddrs[relayIndices[1]],
		nodeAddrs[relayIndices[2]],
	}

	log.Info().Msgf("  Client: Node 1 (%s)", nodeAddrs[clientIdx])
	log.Info().Msgf("  Guard:  Node %d (%s)", relayIndices[0]+1, hops[0])
	log.Info().Msgf("  Middle: Node %d (%s)", relayIndices[1]+1, hops[1])
	log.Info().Msgf("  Exit:   Node %d (%s)", relayIndices[2]+1, hops[2])

	log.Info().Msg("\nBuilding circuit...")
	circID, err := client.BuildCircuit(hops, 10*time.Second)
	if err != nil {
		log.Error().Msgf("Failed to build circuit: %v", err)
		return
	}

	circuits[nextCircID] = circID
	log.Info().Msgf("Circuit #%d created successfully! (Internal ID: %d)", nextCircID, circID)
	nextCircID++

	time.Sleep(200 * time.Millisecond)
}

func handleCreateStream() {
	log.Info().Msg("\n--- CREATE NEW STREAM ---")

	if len(circuits) == 0 {
		log.Info().Msg("No circuits available. Create a circuit first.")
		return
	}

	log.Info().Msg("\nAvailable circuits:")
	for userID, circID := range circuits {
		log.Info().Msgf("\tCircuit #%d (Internal ID: %d)", userID, circID)
	}

	log.Info().Msg("\nEnter circuit number to use: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userCircID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid circuit number")
		return
	}

	circID, exists := circuits[userCircID]
	if !exists {
		log.Info().Msg("Circuit not found")
		return
	}

	log.Info().Msg("Enter target address (e.g., service:8080): ")
	targetAddr, _ := reader.ReadString('\n')
	targetAddr = strings.TrimSpace(targetAddr)

	log.Info().Msgf("\nOpening stream to %s...", targetAddr)
	client := nodes[0] // Always use first node as client
	streamID, err := client.OpenStream(circID, targetAddr)
	if err != nil {
		log.Error().Msgf("Failed to open stream: %v", err)
		return
	}

	streams[nextStrID] = streamInfo{
		circuitID:  circID,
		streamID:   streamID,
		userCircID: userCircID,
	}

	log.Info().Msgf("Stream #%d created successfully! (Internal ID: %d, Circuit: #%d)",
		nextStrID, streamID, userCircID)
	nextStrID++

	time.Sleep(200 * time.Millisecond)
}

func handleSendMessage() {
	log.Info().Msg("\n--- SEND MESSAGE ---")

	if len(streams) == 0 {
		log.Info().Msg("No streams available. Create a stream first.")
		return
	}

	log.Info().Msg("\nAvailable streams:")
	for userID, info := range streams {
		log.Info().Msgf("\tStream #%d (Circuit #%d, Internal Stream ID: %d)",
			userID, info.userCircID, info.streamID)
	}

	log.Info().Msg("\nEnter stream number to use: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userStrID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid stream number")
		return
	}

	info, exists := streams[userStrID]
	if !exists {
		log.Info().Msg("Stream not found")
		return
	}

	log.Info().Msg("\nEnter message to send: ")
	message, _ := reader.ReadString('\n')
	message = strings.TrimSpace(message)

	if message == "" {
		log.Info().Msg("Empty message")
		return
	}

	log.Info().Msgf("\nSending message through stream #%d...", userStrID)
	client := nodes[0]
	err = client.SendStreamData(info.circuitID, info.streamID, []byte(message))
	if err != nil {
		log.Error().Msgf("Failed to send message: %v", err)
		return
	}

	log.Info().Msg("Message sent successfully!")
	time.Sleep(300 * time.Millisecond)

	log.Info().Msg("\nChecking for response from exit node...")
	receivedPackets, err := client.GetReceivedStreamPackets(info.circuitID, info.streamID)
	if err == nil && len(receivedPackets) > 0 {
		log.Info().Msg("Received responses:")
		for i, packet := range receivedPackets {
			log.Info().Msgf("\tResponse %d: %s", i+1, string(packet))
		}
	} else {
		log.Info().Msg("No response received!")
	}
}

func handleCloseStream() {
	log.Info().Msg("\n--- CLOSE STREAM ---")

	if len(streams) == 0 {
		log.Info().Msg("No streams available")
		return
	}

	log.Info().Msg("\nAvailable streams:")
	for userID, info := range streams {
		log.Info().Msgf("\tStream #%d (Circuit #%d, Internal Stream ID: %d)",
			userID, info.userCircID, info.streamID)
	}

	log.Info().Msg("\nEnter stream number to close: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userStrID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid stream number")
		return
	}

	info, exists := streams[userStrID]
	if !exists {
		log.Info().Msg("Stream not found")
		return
	}

	log.Info().Msgf("\nClosing stream #%d...", userStrID)
	client := nodes[0]
	err = client.CloseStream(info.circuitID, info.streamID)
	if err != nil {
		log.Error().Msgf("Failed to close stream: %v", err)
		return
	}

	delete(streams, userStrID)
	log.Info().Msgf("Stream #%d closed successfully!", userStrID)

	time.Sleep(200 * time.Millisecond)
}

func handleCloseCircuit() {
	log.Info().Msg("\n--- CLOSE CIRCUIT ---")

	if len(circuits) == 0 {
		log.Info().Msg("No circuits available")
		return
	}

	log.Info().Msg("\nAvailable circuits:")
	for userID, circID := range circuits {
		log.Info().Msgf("\tCircuit #%d (Internal ID: %d)", userID, circID)
	}

	log.Info().Msg("\nEnter circuit number to close: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userCircID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid circuit number")
		return
	}

	circID, exists := circuits[userCircID]
	if !exists {
		log.Info().Msg("Circuit not found")
		return
	}

	// Check if there are streams on this circuit
	streamsOnCircuit := []int{}
	for strID, info := range streams {
		if info.userCircID == userCircID {
			streamsOnCircuit = append(streamsOnCircuit, strID)
		}
	}

	if len(streamsOnCircuit) > 0 {
		log.Warn().Msgf("Warning: Circuit #%d has %d open stream(s)", userCircID, len(streamsOnCircuit))
		log.Info().Msg("Close them first? (y/n): ")
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(strings.ToLower(confirm))

		if confirm == "y" || confirm == "yes" {
			for _, strID := range streamsOnCircuit {
				info := streams[strID]
				client := nodes[0]
				err := client.CloseStream(info.circuitID, info.streamID)
				if err != nil {
					log.Error().Msgf("Failed to close stream #%d: %v", strID, err)
				} else {
					log.Info().Msgf("  ✓ Closed stream #%d", strID)
				}
				delete(streams, strID)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	log.Info().Msgf("\nDestroying circuit #%d...", userCircID)
	client := nodes[0]
	err = client.DestroyCircuit(circID)
	if err != nil {
		log.Error().Msgf("Failed to destroy circuit: %v", err)
		return
	}

	delete(circuits, userCircID)
	log.Info().Msgf("Circuit #%d destroyed successfully!", userCircID)

	time.Sleep(200 * time.Millisecond)
}

func handleShowStatus() {
	log.Info().Msg("\n--- SYSTEM STATUS ---")
	log.Info().Msgf("Total nodes: %d", len(nodes))
	log.Info().Msgf("Active circuits: %d", len(circuits))
	log.Info().Msgf("Active streams: %d", len(streams))

	if len(circuits) > 0 {
		log.Info().Msg("\nCircuits:")
		for userID, circID := range circuits {
			log.Info().Msgf("\tCircuit #%d (Internal ID: %d)", userID, circID)
		}
	}

	if len(streams) > 0 {
		log.Info().Msg("\nStreams:")
		for userID, info := range streams {
			log.Info().Msgf("\tStream #%d (Circuit #%d, Internal Stream ID: %d)",
				userID, info.userCircID, info.streamID)
		}
	}
}

func cleanupNodes() {
	for i, node := range nodes {
		err := node.Stop()
		if err != nil {
			log.Warn().Msgf("Warning: Failed to stop node %d: %v", i+1, err)
		}
	}
}
