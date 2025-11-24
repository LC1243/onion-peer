package impl

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"go.dedis.ch/cs438/types"
)

const (
	CellSize       = 512
	CellPayloadLen = 509

	RelayHeaderLen  = 11 // streamID + digest + length + command
	RelayPayloadLen = 498
)

// Tor Commands (Control cell)
const (
	Padding = 1
	Create  = 2
	Created = 3
	Destroy = 4
	Relay   = 5
)

// Relay Commands
const (
	RelayData      = 1
	RelayBegin     = 2
	RelayEnd       = 3
	RelayTeardown  = 4
	RelayConnected = 5
	RelayExtend    = 6
	RelayExtended  = 7
	RelayTruncate  = 8
	RelayTruncated = 9
	RelaySendme    = 10
	RelayDrop      = 11
)

type Cell struct {
	CircID  uint16
	Command uint8
	Payload [CellPayloadLen]byte
}

type RelayCell struct {
	CircID   uint16 // equal to CircID of the outer cell
	StreamID uint16
	Digest   [6]byte
	Length   uint16
	Command  uint8
	Data     []byte // <= RelayPayloadLen
}

func (n *node) EncodeCell(c Cell) ([CellSize]byte, error) {
	var out [CellSize]byte
	buf := bytes.NewBuffer(out[:0])

	err := binary.Write(buf, binary.BigEndian, c.CircID)
	if err != nil {
		err := fmt.Errorf("failed to write circID: %w", err)
		return [512]byte{}, err
	}

	err = binary.Write(buf, binary.BigEndian, c.Command)
	if err != nil {
		err := fmt.Errorf("failed to write Command: %w", err)
		return [512]byte{}, err
	}
	buf.Write(c.Payload[:])

	copy(out[:], buf.Bytes())
	return out, nil
}

func (n *node) DecodeCell(b [CellSize]byte) (Cell, error) {
	var c Cell

	buf := bytes.NewReader(b[:])

	// CircID
	err := binary.Read(buf, binary.BigEndian, &c.CircID)
	if err != nil {
		return Cell{}, fmt.Errorf("failed to read circID: %w", err)
	}

	// Command
	err = binary.Read(buf, binary.BigEndian, &c.Command)
	if err != nil {
		return Cell{}, fmt.Errorf("failed to read command: %w", err)
	}

	// Payload
	nRead, err := buf.Read(c.Payload[:])
	if err != nil || nRead != CellPayloadLen {
		return Cell{}, fmt.Errorf("failed to read payload: %w", err)
	}

	return c, nil
}

func (n *node) EncodeRelayCell(r RelayCell) (Cell, error) {
	if len(r.Data) > RelayPayloadLen {
		return Cell{}, fmt.Errorf("relay payload too large: %d", len(r.Data))
	}

	var c Cell
	c.CircID = r.CircID
	c.Command = Relay

	buf := bytes.NewBuffer(c.Payload[:0])

	// Relay header: StreamID + Digest + Len + Command
	err := binary.Write(buf, binary.BigEndian, r.StreamID)
	if err != nil {
		return Cell{}, fmt.Errorf("write relay streamID: %w", err)
	}

	buf.Write(r.Digest[:])
	err = binary.Write(buf, binary.BigEndian, r.Length)
	if err != nil {
		return Cell{}, fmt.Errorf("write length: %w", err)
	}

	buf.WriteByte(r.Command)

	buf.Write(r.Data)
	copy(c.Payload[:], buf.Bytes())
	return c, nil
}

func (n *node) DecodeRelayCell(c Cell) (RelayCell, error) {
	var r RelayCell
	r.CircID = c.CircID

	buf := bytes.NewReader(c.Payload[:])

	err := binary.Read(buf, binary.BigEndian, &r.StreamID)
	if err != nil {
		return r, fmt.Errorf("read streamID: %w", err)
	}

	_, err = buf.Read(r.Digest[:])
	if err != nil {
		return r, fmt.Errorf("read digest: %w", err)
	}

	err = binary.Read(buf, binary.BigEndian, &r.Length)
	if err != nil {
		return r, fmt.Errorf("read length: %w", err)
	}

	cmd, err := buf.ReadByte()
	if err != nil {
		return r, fmt.Errorf("read relay command: %w", err)
	}
	r.Command = cmd

	if r.Length > RelayPayloadLen {
		return r, fmt.Errorf("invalid relay payload length %d", r.Length)
	}

	r.Data = make([]byte, r.Length)
	if _, err := buf.Read(r.Data); err != nil {
		return r, fmt.Errorf("read relay payload: %w", err)
	}

	return r, nil
}

type TorCellMessage struct {
	Raw [512]byte
}

func (TorCellMessage) NewEmpty() types.Message { return &TorCellMessage{} }

func (TorCellMessage) Name() string { return "torcell" }

func (t TorCellMessage) String() string { return fmt.Sprintf("{torcell %d bytes}", len(t.Raw)) }

func (t TorCellMessage) HTML() string {
	return t.String()
}
