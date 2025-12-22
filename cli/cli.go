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
	circuits   map[int]circuitInfo // map from circuit number to circuit info
	streams    map[int]streamInfo
	servers    map[int]serverInfo // map from server number to server info
	nextCircID = 1
	nextStrID  = 1
	nextServID = 1
	log        zerolog.Logger
	reader     *bufio.Reader
)

type streamInfo struct {
	circuitID  uint16
	streamID   uint16
	userCircID int
	targetAddr string
}

type circuitInfo struct {
	circID uint16
	hops   []string // Guard, Middle, Exit addresses
}

type serverInfo struct {
	nodeIdx      int
	exitNodeAddr string
	targetAddr   string
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
	log.Info().Msg("================================================")
	log.Info().Msg(" Welcome To OnionPeer! Let's Keep You Anonymous!")
	log.Info().Msg("================================================")
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
	circuits = make(map[int]circuitInfo)
	streams = make(map[int]streamInfo)
	servers = make(map[int]serverInfo)

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

	hops := []string{
		nodeAddrs[relayIndices[0]],
		nodeAddrs[relayIndices[1]],
		nodeAddrs[relayIndices[2]],
	}

	log.Info().Msgf("\tClient: Node 1 (%s)", nodeAddrs[clientIdx])
	log.Info().Msgf("\tGuard:  Node %d (%s)", relayIndices[0]+1, hops[0])
	log.Info().Msgf("\tMiddle: Node %d (%s)", relayIndices[1]+1, hops[1])
	log.Info().Msgf("\tExit:   Node %d (%s)", relayIndices[2]+1, hops[2])

	log.Info().Msg("\nBuilding circuit...")
	circID, err := client.BuildCircuit(hops, 10*time.Second)
	if err != nil {
		log.Error().Msgf("Failed to build circuit: %v", err)
		return
	}

	circuits[nextCircID] = circuitInfo{
		circID: circID,
		hops:   hops,
	}
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
		log.Info().Msg("3. Send a message (client)")
		log.Info().Msg("4. Register a server node")
		log.Info().Msg("5. Send a message (server)")
		log.Info().Msg("6. View client messages")
		log.Info().Msg("7. View server messages")
		log.Info().Msg("8. Close a stream")
		log.Info().Msg("9. Close a circuit")
		log.Info().Msg("10. Unregister a server")
		log.Info().Msg("11. Show status")
		log.Info().Msg("12. Exit")
		log.Info().Msg("==============================================")
		log.Info().Msg("Choose an option (1-12): ")

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
			handleRegisterServer()
		case "5":
			handleServerSendMessage()
		case "6":
			handleViewClientMessages()
		case "7":
			handleViewServerMessages()
		case "8":
			handleCloseStream()
		case "9":
			handleCloseCircuit()
		case "10":
			handleUnregisterServer()
		case "11":
			handleShowStatus()
		case "12":
			return
		default:
			log.Info().Msg("Invalid option. Please choose 1-12.")
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

	hops := []string{
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

	circuits[nextCircID] = circuitInfo{
		circID: circID,
		hops:   hops,
	}
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
	for userID, circInfo := range circuits {
		log.Info().Msgf("\tCircuit #%d (Internal ID: %d)", userID, circInfo.circID)
	}

	log.Info().Msg("\nEnter circuit number to use: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userCircID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid circuit number")
		return
	}

	circInfo, exists := circuits[userCircID]
	if !exists {
		log.Info().Msg("Circuit not found")
		return
	}

	log.Info().Msg("Enter target address (e.g., target:8080): ")
	targetAddr, _ := reader.ReadString('\n')
	targetAddr = strings.TrimSpace(targetAddr)

	log.Info().Msgf("\nOpening stream to %s...", targetAddr)
	client := nodes[0] // Always use first node as client
	streamID, err := client.OpenStream(circInfo.circID, targetAddr)
	if err != nil {
		log.Error().Msgf("Failed to open stream: %v", err)
		return
	}

	streams[nextStrID] = streamInfo{
		circuitID:  circInfo.circID,
		streamID:   streamID,
		userCircID: userCircID,
		targetAddr: targetAddr,
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
	time.Sleep(500 * time.Millisecond)

	log.Info().Msg("\nChecking for echo response from server...")
	receivedPackets, err := client.GetReceivedStreamPackets(info.circuitID, info.streamID)
	if err == nil && len(receivedPackets) > 0 {
		log.Info().Msg("Received echo:")
		for i, packet := range receivedPackets {
			log.Info().Msgf("\tEcho %d: %s", i+1, string(packet))
		}
		log.Info().Msg("\nTwo-way communication established!")
		log.Info().Msg("\tThe server can now send messages back to you using option 5.")
	} else {
		log.Info().Msg("No echo received yet. The server might not be registered.")
	}
}

func handleRegisterServer() {
	log.Info().Msg("\n--- REGISTER SERVER NODE ---")

	if len(nodes) < 2 {
		log.Info().Msg("Need at least 2 nodes (1 exit node + 1 server)")
		return
	}

	log.Info().Msg("\nAvailable nodes:")
	for i, addr := range nodeAddrs {
		log.Info().Msgf("\tNode %d: %s", i+1, addr)
	}

	log.Info().Msg("\nEnter server node number (not node 1 - the client): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	serverIdx, err := strconv.Atoi(input)
	if err != nil || serverIdx < 1 || serverIdx > len(nodes) {
		log.Info().Msg("Invalid node number")
		return
	}
	serverIdx--

	if serverIdx == 0 {
		log.Info().Msg("Cannot use node 1 as server (it's the client)")
		return
	}

	log.Info().Msg("\nEnter exit node number: ")
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	exitIdx, err := strconv.Atoi(input)
	if err != nil || exitIdx < 1 || exitIdx > len(nodes) {
		log.Info().Msg("Invalid node number")
		return
	}
	exitIdx-- // Convert to 0-based index

	if exitIdx == serverIdx {
		log.Info().Msg("Exit node and server node must be different")
		return
	}

	log.Info().Msg("\nEnter target address to serve (e.g., onion.com:80): ")
	targetAddr, _ := reader.ReadString('\n')
	targetAddr = strings.TrimSpace(targetAddr)

	if targetAddr == "" {
		log.Info().Msg("Empty target address")
		return
	}

	log.Info().Msgf("\nRegistering Node %d as server for %s via Exit Node %d...",
		serverIdx+1, targetAddr, exitIdx+1)

	serverNode := nodes[serverIdx]
	exitNodeAddr := nodeAddrs[exitIdx]

	err = serverNode.RegisterAsServer(exitNodeAddr, targetAddr)
	if err != nil {
		log.Error().Msgf("Failed to register server: %v", err)
		return
	}

	servers[nextServID] = serverInfo{
		nodeIdx:      serverIdx,
		exitNodeAddr: exitNodeAddr,
		targetAddr:   targetAddr,
	}

	log.Info().Msgf("Server #%d registered successfully!", nextServID)
	log.Info().Msgf("  Node %d will now receive messages sent to %s", serverIdx+1, targetAddr)
	nextServID++

	time.Sleep(200 * time.Millisecond)
}

func handleViewClientMessages() {
	log.Info().Msg("\n--- VIEW CLIENT MESSAGES ---")

	if len(streams) == 0 {
		log.Info().Msg("No streams available. Create a stream first.")
		return
	}

	log.Info().Msg("\nAvailable streams:")
	for userID, info := range streams {
		log.Info().Msgf("\tStream #%d -> %s (Circuit #%d)",
			userID, info.targetAddr, info.userCircID)
	}

	log.Info().Msg("\nEnter stream number to view messages: ")
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

	client := nodes[0]

	// Get sent packets
	log.Info().Msg("\nMessages sent by client:")
	sentPackets, err := client.GetStreamPackets(info.circuitID, info.streamID)
	if err != nil {
		log.Error().Msgf("Failed to get sent packets: %v", err)
	} else if len(sentPackets) == 0 {
		log.Info().Msg("  (No messages sent yet)")
	} else {
		for i, packet := range sentPackets {
			log.Info().Msgf("  %d. %s", i+1, string(packet))
		}
	}

	// Get received packets
	log.Info().Msg("\nMessages received by client:")
	receivedPackets, err := client.GetReceivedStreamPackets(info.circuitID, info.streamID)
	if err != nil {
		log.Error().Msgf("Failed to get received packets: %v", err)
	} else if len(receivedPackets) == 0 {
		log.Info().Msg("  (No messages received yet)")
	} else {
		for i, packet := range receivedPackets {
			log.Info().Msgf("  %d. %s", i+1, string(packet))
		}
	}
}

func handleViewServerMessages() {
	log.Info().Msg("\n--- VIEW SERVER MESSAGES ---")

	if len(servers) == 0 {
		log.Info().Msg("No servers registered. Use option 4 to register a server first.")
		return
	}

	log.Info().Msg("\nRegistered servers:")
	for userID, info := range servers {
		log.Info().Msgf("\tServer #%d: Node %d serving %s (Exit: %s)",
			userID, info.nodeIdx+1, info.targetAddr, info.exitNodeAddr)
	}

	log.Info().Msg("\nEnter server number to view messages: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userServID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid server number")
		return
	}

	info, exists := servers[userServID]
	if !exists {
		log.Info().Msg("Server not found")
		return
	}

	serverNode := nodes[info.nodeIdx]

	// Get received data from clients
	log.Info().Msg("\nMessages received by server from clients:")
	receivedData, err := serverNode.GetServerReceivedData(info.exitNodeAddr)
	if err != nil {
		log.Error().Msgf("Failed to get received data: %v", err)
	} else if len(receivedData) == 0 {
		log.Info().Msg("  (No messages received yet)")
	} else {
		for i, data := range receivedData {
			log.Info().Msgf("  %d. %s", i+1, string(data))
		}
	}
}

func handleServerSendMessage() {
	log.Info().Msg("\n--- SEND MESSAGE AS SERVER ---")

	if len(servers) == 0 {
		log.Info().Msg("No servers registered. Use option 4 to register a server first.")
		return
	}

	log.Info().Msg("\nRegistered servers:")
	for userID, info := range servers {
		log.Info().Msgf("\tServer #%d: Node %d serving %s (Exit: %s)",
			userID, info.nodeIdx+1, info.targetAddr, info.exitNodeAddr)
	}

	log.Info().Msg("\nEnter server number to send from: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userServID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid server number")
		return
	}

	info, exists := servers[userServID]
	if !exists {
		log.Info().Msg("Server not found")
		return
	}

	serverNode := nodes[info.nodeIdx]

	// First check if server has received any data
	log.Info().Msg("\nChecking for received client messages...")
	receivedData, err := serverNode.GetServerReceivedData(info.exitNodeAddr)
	if err != nil {
		log.Error().Msgf("Failed to get received data: %v", err)
		return
	}

	if len(receivedData) == 0 {
		log.Info().Msg("No messages received from clients yet.")
		log.Info().Msg("The client must send a message first (option 3) to establish the connection.")
		return
	}

	log.Info().Msg("Received messages from client:")
	for i, data := range receivedData {
		log.Info().Msgf("\tMessage %d: %s", i+1, string(data))
	}

	log.Info().Msg("\nEnter message to send back to client: ")
	message, _ := reader.ReadString('\n')
	message = strings.TrimSpace(message)

	if message == "" {
		log.Info().Msg("Empty message")
		return
	}

	log.Info().Msgf("\nSending message from Server #%d...", userServID)
	err = serverNode.ServerSendData(info.exitNodeAddr, []byte(message))
	if err != nil {
		log.Error().Msgf("Failed to send message: %v", err)
		return
	}

	log.Info().Msg("Message sent successfully!")
	log.Info().Msg("\nTwo-way communication complete!")
	log.Info().Msg("  The client should now see this message when they check stream packets.")

	time.Sleep(300 * time.Millisecond)
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
	for userID, circInfo := range circuits {
		log.Info().Msgf("\tCircuit #%d (Internal ID: %d)", userID, circInfo.circID)
	}

	log.Info().Msg("\nEnter circuit number to close: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userCircID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid circuit number")
		return
	}

	circInfo, exists := circuits[userCircID]
	if !exists {
		log.Info().Msg("Circuit not found")
		return
	}

	// Close streams and unregister servers if needed
	closeStreamsAndServersForCircuit(userCircID, circInfo)

	// Destroy the circuit
	log.Info().Msgf("\nDestroying circuit #%d...", userCircID)
	client := nodes[0]
	err = client.DestroyCircuit(circInfo.circID)
	if err != nil {
		log.Error().Msgf("Failed to destroy circuit: %v", err)
		return
	}

	delete(circuits, userCircID)
	log.Info().Msgf("Circuit #%d destroyed successfully!", userCircID)

	time.Sleep(200 * time.Millisecond)
}

func closeStreamsAndServersForCircuit(userCircID int, circInfo circuitInfo) {
	// Check if there are streams on this circuit
	streamsOnCircuit := findStreamsOnCircuit(userCircID)
	closeStreamsIfConfirmed(userCircID, streamsOnCircuit)

	// Check if there are servers using this circuit's exit node
	exitNodeAddr := circInfo.hops[2]
	serversOnExit := findServersOnExitNode(exitNodeAddr)
	unregisterServersIfConfirmed(exitNodeAddr, serversOnExit)
}

func findStreamsOnCircuit(userCircID int) []int {
	streamsOnCircuit := []int{}
	for strID, info := range streams {
		if info.userCircID == userCircID {
			streamsOnCircuit = append(streamsOnCircuit, strID)
		}
	}
	return streamsOnCircuit
}

func findServersOnExitNode(exitNodeAddr string) []int {
	serversOnExit := []int{}
	for servID, info := range servers {
		if info.exitNodeAddr == exitNodeAddr {
			serversOnExit = append(serversOnExit, servID)
		}
	}
	return serversOnExit
}

func closeStreamsIfConfirmed(userCircID int, streamsOnCircuit []int) {
	if len(streamsOnCircuit) == 0 {
		return
	}

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
				log.Info().Msgf("Closed stream #%d", strID)
			}
			delete(streams, strID)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func unregisterServersIfConfirmed(exitNodeAddr string, serversOnExit []int) {
	if len(serversOnExit) == 0 {
		return
	}

	log.Warn().Msgf("Warning: %d server(s) are registered with Exit Node %d",
		len(serversOnExit), getNodeNumber(exitNodeAddr))
	log.Info().Msg("Unregister them? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm == "y" || confirm == "yes" {
		for _, servID := range serversOnExit {
			info := servers[servID]
			log.Info().Msgf("Unregistering Server #%d (Node %d serving %s)",
				servID, info.nodeIdx+1, info.targetAddr)
			delete(servers, servID)
		}
		log.Info().Msg("Servers unregistered from local tracking.")
		time.Sleep(200 * time.Millisecond)
	}
}

func getNodeNumber(addr string) int {
	for i, nodeAddr := range nodeAddrs {
		if nodeAddr == addr {
			return i + 1 // Node numbering starts from 1
		}
	}
	return -1 // Should not happen
}

func handleShowStatus() {
	log.Info().Msg("\n--- SYSTEM STATUS ---")
	log.Info().Msgf("Total nodes: %d", len(nodes))
	log.Info().Msgf("Active circuits: %d", len(circuits))
	log.Info().Msgf("Active streams: %d", len(streams))
	log.Info().Msgf("Registered servers: %d", len(servers))

	if len(circuits) > 0 {
		log.Info().Msg("\nCircuits:")
		for userID, circInfo := range circuits {
			guardNode := getNodeNumber(circInfo.hops[0])
			middleNode := getNodeNumber(circInfo.hops[1])
			exitNode := getNodeNumber(circInfo.hops[2])
			log.Info().Msgf("\tCircuit #%d: Client → Node %d → Node %d → Node %d (Internal ID: %d)",
				userID, guardNode, middleNode, exitNode, circInfo.circID)
		}
	}

	if len(streams) > 0 {
		log.Info().Msg("\nStreams:")
		for userID, info := range streams {
			log.Info().Msgf("\tStream #%d -> %s (Circuit #%d, Internal Stream ID: %d)",
				userID, info.targetAddr, info.userCircID, info.streamID)
		}
	}

	if len(servers) > 0 {
		log.Info().Msg("\nServers:")
		for userID, info := range servers {
			exitNodeNum := getNodeNumber(info.exitNodeAddr)
			log.Info().Msgf("\tServer #%d: Exit Node %d ← Server Node %d serving %s",
				userID, exitNodeNum, info.nodeIdx+1, info.targetAddr)
		}
	}
}

func handleUnregisterServer() {
	log.Info().Msg("\n--- UNREGISTER SERVER ---")

	if len(servers) == 0 {
		log.Info().Msg("No servers registered.")
		return
	}

	log.Info().Msg("\nRegistered servers:")
	for userID, info := range servers {
		exitNodeNum := getNodeNumber(info.exitNodeAddr)
		log.Info().Msgf("\tServer #%d: Node %d serving %s (Exit: Node %d)",
			userID, info.nodeIdx+1, info.targetAddr, exitNodeNum)
	}

	log.Info().Msg("\nEnter server number to unregister: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	userServID, err := strconv.Atoi(input)
	if err != nil {
		log.Info().Msg("Invalid server number")
		return
	}

	info, exists := servers[userServID]
	if !exists {
		log.Info().Msg("Server not found")
		return
	}

	log.Info().Msgf("\nUnregistering Server #%d (Node %d serving %s via Exit Node %d)...",
		userServID, info.nodeIdx+1, info.targetAddr, getNodeNumber(info.exitNodeAddr))

	delete(servers, userServID)
	log.Info().Msgf("Server #%d unregistered successfully!", userServID)
	log.Info().Msg("Note: This only removes the local tracking. " +
		"The server node may continue to receive traffic from the exit node.")

	time.Sleep(200 * time.Millisecond)
}

func cleanupNodes() {
	for i, node := range nodes {
		err := node.Stop()
		if err != nil {
			log.Warn().Msgf("Warning: Failed to stop node %d: %v", i+1, err)
		}
	}
}
