// Almost all of the code for the UDP socket implementation was written with the help of GitHub Copilot and GPT-5
package udp

import (
	"errors"
	"net"
	"sync"
	"time"

	"go.dedis.ch/cs438/transport"
)

// It is advised to define a constant (max) size for all relevant byte buffers, e.g:
// const bufSize = 65000
const bufSize = 65000

// NewUDP returns a new udp transport implementation.
func NewUDP() transport.Transport {
	return &UDP{}
}

// UDP implements a transport layer using UDP
//
// - implements transport.Transport
type UDP struct {
}

// CreateSocket implements transport.Transport
func (n *UDP) CreateSocket(address string) (transport.ClosableSocket, error) {

	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	// Listen on UDP; if port is 0 the OS picks a free port.
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}

	s := &Socket{
		conn:   conn,
		myAddr: conn.LocalAddr().String(),
	}
	return s, nil
}

// Socket implements a network socket using UDP.
//
// - implements transport.Socket
// - implements transport.ClosableSocket
type Socket struct {
	conn   *net.UDPConn
	myAddr string

	// track closure state
	closed bool

	// track in/out packets
	ins  packets
	outs packets
}

// Close implements transport.Socket. It returns an error if already closed.
func (s *Socket) Close() error {
	if s.closed {
		return errors.New("socket already closed")
	}
	s.closed = true
	return s.conn.Close()
}

// Send implements transport.Socket
func (s *Socket) Send(dest string, pkt transport.Packet, timeout time.Duration) error {
	raddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return err
	}

	// Set deadline only when timeout > 0; check errors
	if timeout > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
	} else {
		if err := s.conn.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
	}

	buf, err := pkt.Marshal()
	if err != nil {
		return err
	}

	_, err = s.conn.WriteToUDP(buf, raddr)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return transport.TimeoutError(timeout)
		}
		return err
	}

	// record the outgoing packet
	s.outs.add(pkt)
	return nil
}

// Recv implements transport.Socket. It blocks until a packet is received, or
// the timeout is reached. In the case the timeout is reached, return a
// TimeoutErr.
func (s *Socket) Recv(timeout time.Duration) (transport.Packet, error) {
	// Set deadline only when timeout > 0; check errors
	if timeout > 0 {
		if err := s.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return transport.Packet{}, err
		}
	} else {
		if err := s.conn.SetReadDeadline(time.Time{}); err != nil {
			return transport.Packet{}, err
		}
	}

	buf := make([]byte, bufSize)
	n, _, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return transport.Packet{}, transport.TimeoutError(timeout)
		}
		return transport.Packet{}, err
	}

	var pkt transport.Packet
	if err := pkt.Unmarshal(buf[:n]); err != nil {
		return transport.Packet{}, err
	}

	// record incoming packet
	s.ins.add(pkt)
	return pkt, nil
}

// GetAddress implements transport.Socket. It returns the address assigned. Can
// be useful in the case one provided a :0 address, which makes the system use a
// random free port.
func (s *Socket) GetAddress() string {
	return s.myAddr
}

// GetIns implements transport.Socket
func (s *Socket) GetIns() []transport.Packet {
	return s.ins.getAll()
}

// GetOuts implements transport.Socket
func (s *Socket) GetOuts() []transport.Packet {
	return s.outs.getAll()
}

// packets is a small helper to store copies of packets safely.
// Use a standard mutex to avoid races and lazy-init issues.
type packets struct {
	mu   sync.Mutex
	data []transport.Packet
}

func (p *packets) add(pkt transport.Packet) {
	p.mu.Lock()
	p.data = append(p.data, pkt.Copy())
	p.mu.Unlock()
}

func (p *packets) getAll() []transport.Packet {
	p.mu.Lock()
	defer p.mu.Unlock()
	res := make([]transport.Packet, len(p.data))
	for i, pkt := range p.data {
		res[i] = pkt.Copy()
	}
	return res
}
