// Package main implements an interactive CLI for the Tor-like onion routing system
package main

import (
	"bufio"
	"crypto/rsa"
	"fmt"
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
	writer := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	log = zerolog.New(writer).Level(level).With().Timestamp().Logger().
		With().Str("role", "cli").Logger()
}

func main() {
	fmt.Println("==============================================")
	fmt.Println(" Welcome To TOR! Let's Keep You Anonymous!")
	fmt.Println("==============================================")
	fmt.Println()

	// Step 1: Get number of nodes
	numNodes := promptForNodeCount()

	// Step 2: Create nodes
	fmt.Printf("\nCreating %d nodes...\n", numNodes)
	createNodes(numNodes)

	// Step 3: Display node addresses
	fmt.Println("\nNode addresses:")
	for i, addr := range nodeAddrs {
		fmt.Printf("\tNode %d: %s\n", i+1, addr)
	}

	// Step 4: Populate onion keys
	fmt.Println("\nPopulating onion keys...")
	populateOnionKeys()
	fmt.Println("All onion keys distributed!")

	// Step 5: Create initial circuit
	fmt.Println("\nBuilding initial 3-hop circuit with random nodes...")
	createRandomCircuit()

	// Step 6: Interactive menu
	fmt.Println()
	runInteractiveMenu()

	// Cleanup
	fmt.Println("\nCleaning up...")
	cleanupNodes()
	fmt.Println("Goodbye!")
}

func promptForNodeCount() int {
	for {
		fmt.Print("Enter number of nodes to create (minimum 4): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		num, err := strconv.Atoi(input)
		if err != nil || num < 4 {
			fmt.Println("Please enter a valid number (minimum 4)")
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
			fmt.Printf("Failed to create socket for node %d: %v\n", i+1, err)
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
			fmt.Printf("Failed to start node %d: %v\n", i+1, err)
			os.Exit(1)
		}

		nodes = append(nodes, node)
		nodeAddrs = append(nodeAddrs, socket.GetAddress())

		fmt.Printf("\tNode %d created at %s\n", i+1, socket.GetAddress())
	}

	// Establish fully connected routing
	fmt.Println("\nEstablishing fully connected routing...")
	for i, node1 := range nodes {
		for j, addr2 := range nodeAddrs {
			if i != j {
				node1.AddPeer(addr2)
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
	fmt.Println("Fully Connected routing established!")
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
		fmt.Println("Need at least 4 nodes (1 client + 3 relays)")
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

	fmt.Printf("  Client: Node 1 (%s)\n", nodeAddrs[clientIdx])
	fmt.Printf("  Guard:  Node %d (%s)\n", relayIndices[0]+1, hops[0])
	fmt.Printf("  Middle: Node %d (%s)\n", relayIndices[1]+1, hops[1])
	fmt.Printf("  Exit:   Node %d (%s)\n", relayIndices[2]+1, hops[2])

	fmt.Println("\nBuilding circuit...")
	circID, err := client.BuildCircuit(hops, 10*time.Second)
	if err != nil {
		fmt.Printf("Failed to build circuit: %v\n", err)
		return
	}

	circuits[nextCircID] = circID
	fmt.Printf("Circuit #%d created successfully! (Internal ID: %d)\n", nextCircID, circID)
	nextCircID++

	time.Sleep(200 * time.Millisecond)
}

func runInteractiveMenu() {
	for {
		fmt.Println("\n==============================================")
		fmt.Println("  MAIN MENU")
		fmt.Println("==============================================")
		fmt.Println("1. Create a new circuit")
		fmt.Println("2. Create a new stream")
		fmt.Println("3. Send a message")
		fmt.Println("4. Close a stream")
		fmt.Println("5. Close a circuit")
		fmt.Println("6. Show status")
		fmt.Println("7. Exit")
		fmt.Println("==============================================")
		fmt.Print("Choose an option (1-7): ")

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
			fmt.Println("Invalid option. Please choose 1-7.")
		}
	}
}

func handleCreateCircuit() {
	fmt.Println("\n--- CREATE NEW CIRCUIT ---")

	if len(nodes) < 4 {
		fmt.Println("Need at least 4 nodes")
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

	fmt.Printf("  Client: Node 1 (%s)\n", nodeAddrs[clientIdx])
	fmt.Printf("  Guard:  Node %d (%s)\n", relayIndices[0]+1, hops[0])
	fmt.Printf("  Middle: Node %d (%s)\n", relayIndices[1]+1, hops[1])
	fmt.Printf("  Exit:   Node %d (%s)\n", relayIndices[2]+1, hops[2])

	fmt.Println("\nBuilding circuit...")
	circID, err := client.BuildCircuit(hops, 10*time.Second)
	if err != nil {
		fmt.Printf("Failed to build circuit: %v\n", err)
		return
	}

	circuits[nextCircID] = circID
	fmt.Printf("Circuit #%d created successfully! (Internal ID: %d)\n", nextCircID, circID)
	nextCircID++

	time.Sleep(200 * time.Millisecond)
}

func handleCreateStream() {
	fmt.Println("\n--- CREATE NEW STREAM ---")

	if len(circuits) == 0 {
		fmt.Println("No circuits available. Create a circuit first.")
		return
	}

	fmt.Println("\nAvailable circuits:")
	for userID, circID := range circuits {
		fmt.Printf("\tCircuit #%d (Internal ID: %d)\n", userID, circID)
	}

	fmt.Print("\nEnter circuit number to use: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userCircID, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("Invalid circuit number")
		return
	}

	circID, exists := circuits[userCircID]
	if !exists {
		fmt.Println("Circuit not found")
		return
	}

	fmt.Print("Enter target address (e.g., service:8080): ")
	targetAddr, _ := reader.ReadString('\n')
	targetAddr = strings.TrimSpace(targetAddr)

	fmt.Printf("\nOpening stream to %s...\n", targetAddr)
	client := nodes[0] // Always use first node as client
	streamID, err := client.OpenStream(circID, targetAddr)
	if err != nil {
		fmt.Printf("Failed to open stream: %v\n", err)
		return
	}

	streams[nextStrID] = streamInfo{
		circuitID:  circID,
		streamID:   streamID,
		userCircID: userCircID,
	}

	fmt.Printf("Stream #%d created successfully! (Internal ID: %d, Circuit: #%d)\n",
		nextStrID, streamID, userCircID)
	nextStrID++

	time.Sleep(200 * time.Millisecond)
}

func handleSendMessage() {
	fmt.Println("\n--- SEND MESSAGE ---")

	if len(streams) == 0 {
		fmt.Println("No streams available. Create a stream first.")
		return
	}

	fmt.Println("\nAvailable streams:")
	for userID, info := range streams {
		fmt.Printf("\tStream #%d (Circuit #%d, Internal Stream ID: %d)\n",
			userID, info.userCircID, info.streamID)
	}

	fmt.Print("\nEnter stream number to use: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userStrID, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("Invalid stream number")
		return
	}

	info, exists := streams[userStrID]
	if !exists {
		fmt.Println("Stream not found")
		return
	}

	fmt.Print("\nEnter message to send: ")
	message, _ := reader.ReadString('\n')
	message = strings.TrimSpace(message)

	if message == "" {
		fmt.Println("Empty message")
		return
	}

	fmt.Printf("\nSending message through stream #%d...\n", userStrID)
	client := nodes[0]
	err = client.SendStreamData(info.circuitID, info.streamID, []byte(message))
	if err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
		return
	}

	fmt.Println("Message sent successfully!")
	time.Sleep(300 * time.Millisecond)

	fmt.Println("\nChecking for response from exit node...")
	receivedPackets, err := client.GetReceivedStreamPackets(info.circuitID, info.streamID)
	if err == nil && len(receivedPackets) > 0 {
		fmt.Println("Received responses:")
		for i, packet := range receivedPackets {
			fmt.Printf("\tResponse %d: %s\n", i+1, string(packet))
		}
	} else {
		fmt.Println("No response received!")
	}
}

func handleCloseStream() {
	fmt.Println("\n--- CLOSE STREAM ---")

	if len(streams) == 0 {
		fmt.Println("No streams available")
		return
	}

	fmt.Println("\nAvailable streams:")
	for userID, info := range streams {
		fmt.Printf("\tStream #%d (Circuit #%d, Internal Stream ID: %d)\n",
			userID, info.userCircID, info.streamID)
	}

	fmt.Print("\nEnter stream number to close: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userStrID, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("Invalid stream number")
		return
	}

	info, exists := streams[userStrID]
	if !exists {
		fmt.Println("Stream not found")
		return
	}

	fmt.Printf("\nClosing stream #%d...\n", userStrID)
	client := nodes[0]
	err = client.CloseStream(info.circuitID, info.streamID)
	if err != nil {
		fmt.Printf("Failed to close stream: %v\n", err)
		return
	}

	delete(streams, userStrID)
	fmt.Printf("Stream #%d closed successfully!\n", userStrID)

	time.Sleep(200 * time.Millisecond)
}

func handleCloseCircuit() {
	fmt.Println("\n--- CLOSE CIRCUIT ---")

	if len(circuits) == 0 {
		fmt.Println("No circuits available")
		return
	}

	fmt.Println("\nAvailable circuits:")
	for userID, circID := range circuits {
		fmt.Printf("\tCircuit #%d (Internal ID: %d)\n", userID, circID)
	}

	fmt.Print("\nEnter circuit number to close: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userCircID, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("Invalid circuit number")
		return
	}

	circID, exists := circuits[userCircID]
	if !exists {
		fmt.Println("Circuit not found")
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
		fmt.Printf("Warning: Circuit #%d has %d open stream(s)\n", userCircID, len(streamsOnCircuit))
		fmt.Print("Close them first? (y/n): ")
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(strings.ToLower(confirm))

		if confirm == "y" || confirm == "yes" {
			for _, strID := range streamsOnCircuit {
				info := streams[strID]
				client := nodes[0]
				client.CloseStream(info.circuitID, info.streamID)
				delete(streams, strID)
				fmt.Printf("  ✓ Closed stream #%d\n", strID)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	fmt.Printf("\nDestroying circuit #%d...\n", userCircID)
	client := nodes[0]
	err = client.DestroyCircuit(circID)
	if err != nil {
		fmt.Printf("Failed to destroy circuit: %v\n", err)
		return
	}

	delete(circuits, userCircID)
	fmt.Printf("Circuit #%d destroyed successfully!\n", userCircID)

	time.Sleep(200 * time.Millisecond)
}

func handleShowStatus() {
	fmt.Println("\n--- SYSTEM STATUS ---")
	fmt.Printf("Total nodes: %d\n", len(nodes))
	fmt.Printf("Active circuits: %d\n", len(circuits))
	fmt.Printf("Active streams: %d\n", len(streams))

	if len(circuits) > 0 {
		fmt.Println("\nCircuits:")
		for userID, circID := range circuits {
			fmt.Printf("\tCircuit #%d (Internal ID: %d)\n", userID, circID)
		}
	}

	if len(streams) > 0 {
		fmt.Println("\nStreams:")
		for userID, info := range streams {
			fmt.Printf("\tStream #%d (Circuit #%d, Internal Stream ID: %d)\n",
				userID, info.userCircID, info.streamID)
		}
	}
}

func cleanupNodes() {
	for i, node := range nodes {
		err := node.Stop()
		if err != nil {
			fmt.Printf("Warning: Failed to stop node %d: %v\n", i+1, err)
		}
	}
}
