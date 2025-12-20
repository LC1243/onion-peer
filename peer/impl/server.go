package impl

import (
	"fmt"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// Server feature addition done mostly using copilot

// RegisterAsServer registers this node as a server for the specified target address.
func (n *node) RegisterAsServer(exitNodeAddr, targetAddr string) error {
	n.log.Info().
		Str("exitNode", exitNodeAddr).
		Str("targetAddr", targetAddr).
		Msg("Registering as server")

	msg := types.ServerData{
		Type:       "register",
		TargetAddr: targetAddr,
		ServerAddr: n.conf.Socket.GetAddress(),
	}

	transpMsg, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %w", err)
	}

	myAddr := n.conf.Socket.GetAddress()
	pktHeader := transport.NewHeader(myAddr, myAddr, exitNodeAddr)
	pkt := transport.Packet{Header: &pktHeader, Msg: &transpMsg}

	return n.conf.Socket.Send(exitNodeAddr, pkt, 0)
}

// ServerSendData sends data back to the exit node that contacted this server.
func (n *node) ServerSendData(exitNodeAddr string, data []byte) error {
	n.log.Info().
		Str("exitNode", exitNodeAddr).
		Int("dataLen", len(data)).
		Msg("Server sending data")

	// Get the most recent connectionID for this exit node
	n.serverDataMu.RLock()
	connectionID, hasConnID := n.serverConnectionIDs[exitNodeAddr]
	n.serverDataMu.RUnlock()

	if !hasConnID {
		return fmt.Errorf("no connection ID found for exit node %s", exitNodeAddr)
	}

	msg := types.ServerData{
		Type:         "reply",
		ConnectionID: connectionID,
		Data:         data,
	}

	transpMsg, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	myAddr := n.conf.Socket.GetAddress()
	pktHeader := transport.NewHeader(myAddr, myAddr, exitNodeAddr)
	pkt := transport.Packet{Header: &pktHeader, Msg: &transpMsg}

	return n.conf.Socket.Send(exitNodeAddr, pkt, 0)
}

// GetServerReceivedData returns data received from an exit node.
func (n *node) GetServerReceivedData(exitNodeAddr string) ([][]byte, error) {
	n.serverDataMu.RLock()
	defer n.serverDataMu.RUnlock()

	data, exists := n.serverReceivedData[exitNodeAddr]
	if !exists {
		return [][]byte{}, nil
	}

	result := make([][]byte, len(data))
	copy(result, data)
	return result, nil
}

// forwardDataToServer forwards data to the registered server.
func (n *node) forwardDataToServer(circID, streamID uint16, targetAddr string, data []byte, serverAddr string) error {
	n.log.Info().
		Str("targetAddr", targetAddr).
		Str("serverAddr", serverAddr).
		Uint16("circID", circID).
		Uint16("streamID", streamID).
		Int("dataLen", len(data)).
		Msg("Forwarding data to server")

	// Store mapping so we can route replies back
	connectionID := fmt.Sprintf("%s:%d:%d", serverAddr, circID, streamID)
	n.serverStreamMapMu.Lock()
	n.serverStreamMap[connectionID] = &serverStreamMapping{
		circID:   circID,
		streamID: streamID,
	}
	n.serverStreamMapMu.Unlock()

	msg := types.ServerData{
		Type:         "forward",
		ConnectionID: connectionID,
		Data:         data,
	}

	transpMsg, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		return err
	}

	myAddr := n.conf.Socket.GetAddress()
	pktHeader := transport.NewHeader(myAddr, myAddr, serverAddr)
	pkt := transport.Packet{Header: &pktHeader, Msg: &transpMsg}

	return n.conf.Socket.Send(serverAddr, pkt, 0)
}

// execServerData handles ServerData messages
func (n *node) execServerData(msg types.Message, pkt transport.Packet) error {
	sd, ok := msg.(*types.ServerData)
	if !ok {
		return fmt.Errorf("invalid message type")
	}

	switch sd.Type {
	case "register":
		// Handle registration at exit node
		n.serverConnectionsMu.Lock()
		n.serverConnections[sd.TargetAddr] = sd.ServerAddr
		n.serverConnectionsMu.Unlock()

		n.log.Info().
			Str("targetAddr", sd.TargetAddr).
			Str("serverAddr", sd.ServerAddr).
			Msg("Server registered at exit node")

	case "forward":
		// Handle data received by server from exit node
		n.serverDataMu.Lock()
		n.serverReceivedData[pkt.Header.Source] = append(n.serverReceivedData[pkt.Header.Source], sd.Data)
		n.serverConnectionIDs[pkt.Header.Source] = sd.ConnectionID
		n.serverDataMu.Unlock()

		n.log.Info().
			Str("exitNode", pkt.Header.Source).
			Str("connectionID", sd.ConnectionID).
			Int("dataLen", len(sd.Data)).
			Msg("Server received data from exit node")

	case "reply":
		// Handle reply from server to forward to client
		n.serverStreamMapMu.RLock()
		mapping, exists := n.serverStreamMap[sd.ConnectionID]
		n.serverStreamMapMu.RUnlock()

		if !exists {
			n.log.Warn().Str("connectionID", sd.ConnectionID).Msg("Connection ID not found")
			return nil
		}

		// Forward the reply to the client
		err := n.handleServerReplyData(mapping.circID, mapping.streamID, sd.Data)
		if err != nil {
			n.log.Error().Err(err).Msg("Failed to forward server reply")
		}
	}

	return nil
}

// handleServerReplyData handles reply data from server to forward to client.
func (n *node) handleServerReplyData(circID uint16, streamID uint16, data []byte) error {
	n.circuitsMu.RLock()
	var circ *Circuit
	for key, c := range n.circuits {
		if key.InCircID == circID {
			circ = c
			break
		}
	}
	n.circuitsMu.RUnlock()

	if circ == nil {
		return fmt.Errorf("circuit %d not found", circID)
	}

	stream, err := n.validateStreamForData(circ.InCircID, streamID)
	if err != nil {
		return err
	}

	// Send reply with flow control
	go func() {
		if n.congestionControl {
			n.circuitsMu.Lock()
			for circ.PackageWindow <= 0 {
				circ.WindowCond.Wait()
			}
			circ.PackageWindow--
			n.circuitsMu.Unlock()

			stream.mu.Lock()
			for stream.PackageWindow <= 0 {
				stream.WindowCond.Wait()
			}
			stream.PackageWindow--
			stream.mu.Unlock()
		}

		circ.CryptoMu.Lock()
		exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
		crypto := n.circuitCryptoStates[circ.InCircID][exitIdx]
		err := n.encryptAndSendReply(circ.InCircID, streamID, data, crypto, circ.PrevHop)
		circ.CryptoMu.Unlock()

		if err != nil {
			n.log.Error().Err(err).Msg("Failed to send server reply")
		}
	}()

	return nil
}
