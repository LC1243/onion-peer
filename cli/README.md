# Tor-like Onion Routing System - CLI

An interactive command-line interface for demonstrating the Tor-like onion routing system.

## Features

- **Interactive Node Creation**: Create multiple nodes dynamically
- **Automatic Key Distribution**: Onion keys are automatically distributed across all nodes
- **Circuit Building**: Create 3-hop circuits with randomly selected relays
- **Stream Management**: Open and manage streams over circuits
- **Data Transfer**: Send messages through circuits and view responses
- **Interactive Menu**: Easy-to-use menu for all operations

## Building and Runnning

```bash
make cli-run
```

## Usage Flow

### 1. Initial Setup
When you start the CLI, you'll be prompted to:
1. Enter the number of nodes (minimum 4)
2. The system will automatically:
   - Create all nodes
   - Establish routing
   - Distribute onion keys
   - Build an initial 3-hop circuit

### 2. Interactive Menu
After setup, you'll see a menu with the following options:

#### Option 1: Create a new circuit
- Automatically selects 3 random relay nodes
- Builds a 3-hop circuit (Guard → Middle → Exit)
- Returns a circuit ID for future reference
- Shows circuit handshake messages in real-time

#### Option 2: Create a new stream
- Lists all available circuits
- Prompts for circuit selection
- Asks for target address (e.g., `service:8080`)
- Opens a stream over the selected circuit
- Returns a stream ID
- Shows stream opening messages

#### Option 3: Send a message (client)
- Lists all available streams
- Prompts for stream selection
- Asks for message text
- Sends the message through the onion circuit
- Waits for and displays echo response from the server
- Shows data transfer messages
- Confirms two-way communication is established

#### Option 4: Register a server node
- Lists all available nodes
- Prompts for server node selection (cannot use node 1 - the client)
- Asks for exit node selection
- Prompts for target address to serve (e.g., `example.com:80`)
- Registers the server with the exit node
- Server will receive messages sent to the target address
- Shows registration confirmation

#### Option 5: Send a message (server)
- Lists all registered servers
- Prompts for server selection
- Shows messages received from clients
- Asks for message to send back
- Sends message back through exit node to client
- Demonstrates two-way communication
- Client can see this message by checking stream packets

#### Option 6: View client messages
- Lists all available streams
- Prompts for stream selection
- Shows messages sent by the client
- Shows messages received by the client (from server)
- Useful for verifying two-way communication

#### Option 7: View server messages
- Lists all registered servers
- Prompts for server selection
- Shows messages received by the server from clients
- Useful for debugging and monitoring server traffic

#### Option 8: Close a stream
- Lists all open streams
- Prompts for stream selection
- Closes the stream cleanly
- Shows stream teardown messages

#### Option 9: Close a circuit
- Lists all active circuits
- Prompts for circuit selection
- Optionally closes all streams on the circuit first
- Checks for servers registered with the circuit's exit node
- Prompts whether to unregister those servers
- Destroys the circuit
- Shows circuit destruction messages

#### Option 10: Unregister a server
- Lists all registered servers
- Prompts for server selection
- Removes server from local tracking
- Note: The server node may continue to receive traffic from the exit node until the exit node is notified

#### Option 11: Show status
- Displays total number of nodes
- Shows active circuits with their complete paths (Client → Guard → Middle → Exit)
- Lists open streams and their associated circuits
- Shows registered servers and their exit nodes

#### Option 12: Exit
- Cleans up all resources
- Stops all nodes
- Exits the application

## Example Session

Here is a complete walkthrough of a typical session:

1. **Start the CLI**
   Run `make cli-run`.

2. **Initialize System**
   - Prompt: `Enter number of nodes to create (minimum 4):`
   - Action: Enter `4`
   - Result: 4 nodes are created. An initial circuit is built automatically.
   - **Note**: Pay attention to the "Exit: Node X" line in the output. Let's assume **Node 4** is the Exit node for this example.

3. **Create a Stream**
   - Select Option `2` (Create a new stream).
   - Select Circuit `1`.
   - Enter target address: `service:8080`.
   - Result: Stream #1 is created.

4. **Register a Server**
   - Select Option `4` (Register server node).
   - Select a node to act as the server (e.g., **Node 2**). *Do not select Node 1 (Client).*
   - Enter the Exit node number (e.g., **4**, based on step 2).
   - Enter target address: `service:8080` (must match the stream target).
   - Result: Node 2 is registered as a server for `service:8080` via Exit Node 4.

5. **Send Message (Client -> Server)**
   - Select Option `3` (Send a message).
   - Select Stream `1`.
   - Enter message: `Hello Server!`.
   - Result: Message is sent through the circuit. If the server is set up correctly, you might see an echo or confirmation.

6. **Send Message (Server -> Client)**
   - Select Option `5` (Send a message as server).
   - Select Server `1`.
   - Enter message: `Hello Client!`.
   - Result: Message is sent back to the client.

7. **View Messages**
   - Select Option `6` (View client messages) to see what the client sent and received.
   - Select Option `7` (View server messages) to see what the server received.

8. **Check Status**
   - Select Option `11` (Show status) to see the overall system state.

9. **Cleanup**
   - Select Option `8` (Close a stream).
   - Select Option `9` (Close a circuit).
   - When closing the circuit, you'll be prompted whether to unregister servers using that exit node.
   - Alternatively, use Option `10` (Unregister a server) to manually remove server registrations.
   - Select Option `12` (Exit).


## Architecture

### Node Roles
- **Client Node**: Always Node 1, initiates circuits and streams
- **Guard Node**: First hop in the circuit, receives CREATE cells
- **Middle Node**: Second hop, relays EXTEND cells
- **Exit Node**: Third hop, opens streams to target services, forwards data to/from servers
- **Server Node**: Any node that registers to receive traffic for a target address

### Circuit Structure
Each circuit consists of:
- Circuit ID (unique per node pair)
- 3 hops (Guard → Middle → Exit)
- Encrypted layers (onion routing)
- Flow control windows

### Stream Structure
Each stream consists of:
- Stream ID (unique per circuit)
- Associated circuit
- Target address
- Data buffers

### Server Architecture
The server feature demonstrates two-way communication:
1. **Registration**: Server nodes register with exit nodes for specific target addresses
2. **Client → Server**: Messages travel through circuit, exit node forwards to server
3. **Server Echo**: Server automatically echoes received messages back
4. **Server → Client**: Server can send additional messages back through the exit node
5. **Bidirectional Flow**: Both client and server can initiate communication after initial connection

## Troubleshooting

### "Need at least 4 nodes"
You need a minimum of 4 nodes: 1 client + 3 relays for a 3-hop circuit.

### Circuit build timeout
Increase the timeout or check that all nodes are running properly.

### "Cannot use node 1 as server (it's the client)"
Node 1 is reserved as the client. Choose any other node (2-N) as the server.

### "No messages received from clients yet"
The client must send a message first (option 3) before the server can reply. This establishes the connection mapping at the exit node.

### Server echo not appearing
Wait a moment (500ms) after sending the client message. The server automatically echoes messages back. If still not appearing, ensure the server is registered for the same target address used in the stream.
