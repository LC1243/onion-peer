package impl

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
)

type HiddenService struct {
	ID          string // hash(pubkey)
	KeyPair     *OnionKeyPair
	IntroPoints []IntroPoint
	Descriptor  *ServiceDescriptor
}

type IntroPoint struct {
	RouterAddr string // OR address (first hop of Bob’s circuit)
	CircID     uint16 // circuit from Bob to that OR
}

type IntroPointState struct {
	ServiceID  string
	ServicePub *rsa.PublicKey
	BobAddr    string
	BobCircID  uint16
}

// ServiceDescriptor used for the Lookup service
type ServiceDescriptor struct {
	ServiceID     string   // hash(pubkey)
	ServicePubKey []byte   // pubkey
	IntroPoints   []string // list of OR addresses
	ExpiresAt     time.Time
	Signature     []byte // DS(ServiceID || ExpiresAt || IntroPoints || ServicePubKey)
}

type FragmentHeader struct {
	MsgID uint16
	Index uint16 // fragment index
	Total uint16 // total fragments
}

const FragmentHeaderLen = 2 + 2 + 2 // (uint16 each)

type IPIntroduceMessage struct {
	ServiceID     string
	EncryptedBlob []byte // encrypted ServiceIntroduceMessage with service pubkey
}

type ServiceIntroduceMessage struct {
	Cookie      [CookieSize]byte
	RPAddr      string
	ClientDHPub []byte
}

type DhRendezvousState struct {
	CircID     uint16
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateServiceKeyPair generates a new RSA keypair for use as keys for a service
func GenerateServiceKeyPair() (*OnionKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &OnionKeyPair{
		Public:  &privateKey.PublicKey,
		Private: privateKey,
	}, nil
}

// GenerateHiddenServiceID implements peer.TorHiddenServices
func (n *node) GenerateHiddenServiceID() (string, error) {
	key, err := GenerateServiceKeyPair()
	if err != nil {
		return "", err
	}

	pub := x509.MarshalPKCS1PublicKey(key.Public)
	h := sha256.Sum256(pub)
	serviceID := fmt.Sprintf("%x", h[:])

	hs := &HiddenService{
		ID:      serviceID,
		KeyPair: key,
	}

	n.hiddenServiceMu.RLock()
	n.hiddenServices[serviceID] = hs
	n.hiddenServiceMu.RUnlock()

	return serviceID, nil
}

// EstablishIntroPoint implements Tor.HiddenServices
func (n *node) EstablishIntroPoint(serviceID string, circID uint16, timeout time.Duration) error {
	n.hiddenServiceMu.RLock()
	hs, ok := n.hiddenServices[serviceID]
	n.hiddenServiceMu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown serviceID: %s", serviceID)
	}

	pubBytes := x509.MarshalPKCS1PublicKey(hs.KeyPair.Public)
	payload := pubBytes

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[circID]
	n.cryptoStatesMu.Unlock()
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto state for circ %d", circID)
	}

	cc, ok := n.clientCircuits[circID]
	if !ok {
		return fmt.Errorf("not a client circuit %d", circID)
	}

	cc.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, payload)
	cc.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	relay := RelayCell{
		CircID:   circID,
		StreamID: 0,
		Command:  RelayEstablishIntro,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}
	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return err
	}

	return n.SendAndWaitForIntroReply(circID, serviceID, cell, timeout)
}

// SendAndWaitForIntroReply tries to create an Introduction Point and waits for the corresponding confirmation
func (n *node) SendAndWaitForIntroReply(circID uint16, serviceID string, cell Cell, timeout time.Duration) error {
	n.hiddenServiceMu.RLock()
	hs := n.hiddenServices[serviceID]
	n.hiddenServiceMu.RUnlock()

	cc := n.clientCircuits[circID]

	ch := make(chan struct{})

	n.introWaitMu.Lock()
	n.introWait[circID] = ch
	n.introWaitMu.Unlock()

	// Send it via guard of this circuit
	err := n.SendCell(cc.Hops[0], cell, cc)
	if err != nil {
		return err
	}

	select {
	case <-ch:
		hs.IntroPoints = append(hs.IntroPoints, IntroPoint{
			RouterAddr: cc.Hops[len(cc.Hops)-1],
			CircID:     circID,
		})
		return nil

	case <-time.After(timeout):
		return fmt.Errorf("intro point establishment timed out on circ %d", circID)
	}
}

// HandleRelayEstablishIntro provides the OR with Bob public key to identify his service
func (n *node) HandleRelayEstablishIntro(relay RelayCell, circ *Circuit) error {
	pub, err := x509.ParsePKCS1PublicKey(relay.Data)
	if err != nil {
		return fmt.Errorf("parse service pubkey at intro point: %w", err)
	}

	// service ID = hash(pubkey)
	h := sha256.Sum256(relay.Data)
	serviceID := fmt.Sprintf("%x", h[:])

	n.log.Info().
		Str("serviceID", serviceID).
		Uint16("circID", circ.InCircID).
		Msg("Establishing introduction point for service")

	state := &IntroPointState{
		ServiceID:  serviceID,
		ServicePub: pub,
		BobAddr:    circ.PrevHop,
		BobCircID:  circ.InCircID,
	}

	n.introPointsMu.Lock()
	n.introPoints[serviceID] = append(n.introPoints[serviceID], state)
	n.introPointsMu.Unlock()
	return n.SendRelayIntroEstablished(circ)
}

// SendRelayIntroEstablished sends an acknowledgment to Bob saying is ready to receive traffic
func (n *node) SendRelayIntroEstablished(circ *Circuit) error {
	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[circ.InCircID]
	n.cryptoStatesMu.Unlock()
	exitIdx := len(cryptoStates) - 1
	cryptoState := cryptoStates[exitIdx]

	circ.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayPayload(
		cryptoState,
		DirectionBackward,
		[]byte{}, // empty payload
	)
	circ.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	relay := RelayCell{
		CircID:   circ.InCircID,
		StreamID: 0,
		Command:  RelayIntroEstablished,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}

	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return err
	}

	return n.SendCell(circ.PrevHop, cell, circ)
}

// HandleRelayIntroEstablished handles the ACK from the OR saying he's ready to receive traffic
func (n *node) HandleRelayIntroEstablished(relay RelayCell) error {
	n.introWaitMu.Lock()
	ch := n.introWait[relay.CircID]
	delete(n.introWait, relay.CircID)
	n.introWaitMu.Unlock()

	if ch != nil {
		close(ch)
	}

	n.log.Info().
		Uint16("circID", relay.CircID).
		Msg("Introduction point established (ACK received)")

	return nil
}

// ----------------------------
// For Lookup services
// ----------------------------

// SetPeerAsHSDir implements peer.TorHiddenServices
func (n *node) SetPeerAsHSDir(value bool) {
	n.IsHiddenServiceDir = value
}

func (n *node) GenerateMsgID() (uint16, error) {
	var b [2]byte // uint16
	_, err := rand.Read(b[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// EncodeFragment encodes a FragmentHeader and a chunk of data into a relay payload
func EncodeFragment(h FragmentHeader, chunk []byte) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, FragmentHeaderLen+len(chunk)))
	if err := binary.Write(buf, binary.BigEndian, h.MsgID); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Index); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Total); err != nil {
		return nil, err
	}
	_, err := buf.Write(chunk)
	return buf.Bytes(), err
}

// DecodeFragment decodes a relay payload into a FragmentHeader and a chunk of data
func DecodeFragment(b []byte) (FragmentHeader, []byte, error) {
	if len(b) < FragmentHeaderLen {
		return FragmentHeader{}, nil, fmt.Errorf("fragment too short")
	}
	r := bytes.NewReader(b)
	var h FragmentHeader
	if err := binary.Read(r, binary.BigEndian, &h.MsgID); err != nil {
		return FragmentHeader{}, nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &h.Index); err != nil {
		return FragmentHeader{}, nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &h.Total); err != nil {
		return FragmentHeader{}, nil, err
	}
	rest, err := io.ReadAll(r)
	return h, rest, err
}

// SplitPayload splits a payload into chunks of a given size
func SplitPayload(payload []byte, maxChunk int) [][]byte {
	if maxChunk <= 0 {
		return nil
	}
	var out [][]byte
	for off := 0; off < len(payload); off += maxChunk {
		end := off + maxChunk
		if end > len(payload) {
			end = len(payload)
		}
		out = append(out, payload[off:end])
	}
	return out
}

// AddFragment adds a chunk of data to a fragment buffer
func (n *node) AddFragment(circID, msgID, idx, total uint16, chunk []byte) ([]byte, bool, error) {
	n.hsdirFragMu.Lock()
	defer n.hsdirFragMu.Unlock()

	key := fragKey{CircID: circID, MsgID: msgID}

	frag := n.hsdirFrags[key]
	if frag == nil {
		frag = &fragBuf{total: total, parts: make(map[uint16][]byte, total)}
		n.hsdirFrags[key] = frag
	}

	if frag.total != total || idx >= total {
		return nil, false, fmt.Errorf("fragment index out of range")
	}

	// store if new
	_, exists := frag.parts[idx]
	if !exists {
		frag.parts[idx] = append([]byte(nil), chunk...)
	}

	if uint16(len(frag.parts)) != frag.total {
		return nil, false, nil // not complete yet
	}

	// reassemble
	var full bytes.Buffer
	for i := uint16(0); i < frag.total; i++ {
		part, ok := frag.parts[i]
		if !ok {
			return nil, false, fmt.Errorf("missing fragment %d", i)
		}
		full.Write(part)
	}

	delete(n.hsdirFrags, key)
	return full.Bytes(), true, nil
}

// SendFragmentsBackward sends fragments one by one in a loop in a backwards direction
func (n *node) SendFragmentsBackward(frags [][]byte,
	msgID uint16, circ *Circuit,
	cryptoState *CircuitCryptoState,
	command uint8) error {

	for i, chunk := range frags {

		framed, err := EncodeFragment(FragmentHeader{
			MsgID: msgID,
			Index: uint16(i),
			Total: uint16(len(frags)),
		}, chunk)

		if err != nil {
			return err
		}

		circ.CryptoMu.Lock()
		encrypted, digest, err := EncryptRelayPayload(
			cryptoState,
			DirectionBackward,
			framed,
		)
		circ.CryptoMu.Unlock()

		if err != nil {
			return err
		}

		relay := RelayCell{
			CircID:   circ.InCircID,
			StreamID: 0,
			Command:  command,
			Digest:   digest,
			Length:   uint16(len(encrypted)),
			Data:     encrypted,
		}

		cell, err := n.EncodeRelayCell(relay)
		if err != nil {
			return err
		}

		err = n.SendCell(circ.PrevHop, cell, circ)
		if err != nil {
			return err
		}
	}
	return nil
}

// SendFragments sends fragments one by one in a loop in a forwards direction
func (n *node) SendFragments(frags [][]byte,
	msgID uint16,
	circID uint16,
	cc *ClientCircuit,
	cryptoStates []*CircuitCryptoState,
	command uint8) error {

	for i, chunk := range frags {

		framed, err := EncodeFragment(FragmentHeader{
			MsgID: msgID,
			Index: uint16(i),
			Total: uint16(len(frags)),
		}, chunk)

		if err != nil {
			return err
		}

		encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, framed)
		if err != nil {
			return err
		}

		relay := RelayCell{
			CircID:   circID,
			StreamID: 0,
			Command:  command,
			Digest:   digest,
			Length:   uint16(len(encrypted)),
			Data:     encrypted,
		}

		cell, err := n.EncodeRelayCell(relay)
		if err != nil {
			return err
		}

		err = n.SendCell(cc.Hops[0], cell, cc)
		if err != nil {
			return err
		}
	}

	return nil
}

// EncodeServiceDescriptor encodes a service descriptor into a relay payload
func EncodeServiceDescriptor(desc *ServiceDescriptor) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	// ServiceID
	sid := []byte(desc.ServiceID)
	err := binary.Write(buf, binary.BigEndian, uint16(len(sid)))
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(sid)
	if err != nil {
		return nil, err
	}

	// Public key
	err = binary.Write(buf, binary.BigEndian, uint16(len(desc.ServicePubKey)))
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(desc.ServicePubKey)
	if err != nil {
		return nil, err
	}

	// Introduction points
	if len(desc.IntroPoints) > 255 {
		return nil, fmt.Errorf("too many intro points")
	}
	buf.WriteByte(byte(len(desc.IntroPoints)))

	for _, ip := range desc.IntroPoints {
		ipb := []byte(ip)
		if len(ipb) > 255 {
			return nil, fmt.Errorf("intro point address too long")
		}
		buf.WriteByte(byte(len(ipb)))
		_, err = buf.Write(ipb)
		if err != nil {
			return nil, err
		}
	}

	// Expiration
	expires := desc.ExpiresAt.Unix()
	err = binary.Write(buf, binary.BigEndian, expires)
	if err != nil {
		return nil, err
	}

	// Signature
	err = binary.Write(buf, binary.BigEndian, uint16(len(desc.Signature)))
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(desc.Signature)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeServiceDescriptor decodes a relay payload into a service descriptor
func DecodeServiceDescriptor(b []byte) (*ServiceDescriptor, error) {
	r := bytes.NewReader(b)
	desc := &ServiceDescriptor{}

	// ServiceID
	var sidLen uint16
	err := binary.Read(r, binary.BigEndian, &sidLen)
	if err != nil {
		return nil, err
	}

	sid := make([]byte, sidLen)
	_, err = r.Read(sid)
	if err != nil {
		return nil, err
	}
	desc.ServiceID = string(sid)

	// Public key
	var pkLen uint16
	err = binary.Read(r, binary.BigEndian, &pkLen)
	if err != nil {
		return nil, err
	}
	pk := make([]byte, pkLen)
	_, err = r.Read(pk)
	if err != nil {
		return nil, err
	}
	desc.ServicePubKey = pk

	// Introduction points
	count, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	desc.IntroPoints = make([]string, 0, count)
	for i := 0; i < int(count); i++ {
		l, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		addr := make([]byte, l)
		_, err = r.Read(addr)
		if err != nil {
			return nil, err
		}
		desc.IntroPoints = append(desc.IntroPoints, string(addr))
	}

	// Expiration
	var expires int64
	err = binary.Read(r, binary.BigEndian, &expires)
	if err != nil {
		return nil, err
	}
	desc.ExpiresAt = time.Unix(expires, 0)

	// Signature
	var sigLen uint16
	err = binary.Read(r, binary.BigEndian, &sigLen)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, sigLen)

	_, err = r.Read(sig)
	if err != nil {
		return nil, err
	}
	desc.Signature = sig

	return desc, nil
}

// HandleRelayHSDirPublish handles relay cells sent to publish a service descriptor to the HSDir
func (n *node) HandleRelayHSDirPublish(relay RelayCell, circ *Circuit) error {
	if !n.IsHiddenServiceDir {
		return nil // ignore
	}

	hdr, chunk, err := DecodeFragment(relay.Data)
	if err != nil {
		return err
	}

	full, done, err := n.AddFragment(circ.InCircID, hdr.MsgID, hdr.Index, hdr.Total, chunk)

	if err != nil {
		return err
	}
	if !done {
		return nil // wait for more fragments
	}

	desc, err := DecodeServiceDescriptor(full)
	if err != nil {
		return err
	}

	err = n.VerifyServiceDescriptor(desc)
	if err != nil {
		n.log.Error().Err(err).Msg("HSDir received invalid descriptor")
		return err
	}

	n.log.Info().
		Str("serviceID", desc.ServiceID).
		Time("expiresAt", desc.ExpiresAt).
		Msg("HSDir received descriptor publish")

	n.hsDirMu.Lock()
	n.hsDirStore[desc.ServiceID] = desc
	n.hsDirMu.Unlock()

	n.log.Info().
		Str("serviceID", desc.ServiceID).
		Msg("HSDir stored descriptor")

	return n.SendHSDirReply(circ, nil)
}

// HandleRelayHSDirLookup handles relay cells sent to look up a service descriptor from the HSDir
func (n *node) HandleRelayHSDirLookup(relay RelayCell, circ *Circuit) error {
	if !n.IsHiddenServiceDir {
		return n.SendHSDirReply(circ, nil)
	}

	serviceID := string(relay.Data)

	n.log.Info().
		Str("serviceID", serviceID).
		Msg("HSDir lookup request received")

	n.hsDirMu.RLock()
	desc := n.hsDirStore[serviceID]
	n.hsDirMu.RUnlock()

	if desc == nil {
		n.log.Info().
			Str("serviceID", serviceID).
			Msg("HSDir lookup: descriptor not found")
		return n.SendHSDirReply(circ, nil)
	}

	n.log.Info().
		Str("serviceID", serviceID).
		Time("expiresAt", desc.ExpiresAt).
		Time("now", time.Now()).
		Msg("HSDir checking descriptor expiration")

	// expired -> delete from hsDirStore
	if time.Now().After(desc.ExpiresAt) {
		n.log.Info().
			Str("serviceID", serviceID).
			Time("expiresAt", desc.ExpiresAt).
			Time("now", time.Now()).
			Msg("HSDir descriptor expired, deleting")

		n.hsDirMu.Lock()
		delete(n.hsDirStore, serviceID)
		n.hsDirMu.Unlock()
		return n.SendHSDirReply(circ, nil)
	}

	payload, err := EncodeServiceDescriptor(desc)
	if err != nil {
		return err
	}

	n.log.Info().
		Str("serviceID", serviceID).
		Msg("HSDir descriptor valid, replying to lookup")

	return n.SendHSDirReply(circ, payload)
}

// SendHSDirReply sends a reply to a lookup or publish request to the HSDir
func (n *node) SendHSDirReply(circ *Circuit, payload []byte) error {
	msgID, err := n.GenerateMsgID()
	if err != nil {
		return err
	}

	maxChunk := RelayPayloadLen - FragmentHeaderLen
	frags := SplitPayload(payload, maxChunk)

	if len(frags) == 0 {
		frags = [][]byte{{}}
	}

	n.cryptoStatesMu.Lock()
	cryptoState := n.circuitCryptoStates[circ.InCircID][len(n.circuitCryptoStates[circ.InCircID])-1]
	n.cryptoStatesMu.Unlock()

	return n.SendFragmentsBackward(frags, msgID, circ, cryptoState, RelayHSDirReply)
}

// PublishDescriptorToHSDir implement peer.TorHiddenServices
func (n *node) PublishDescriptorToHSDir(serviceID string,
	introORs []string,
	lifetime time.Duration,
	circID uint16,
	timeout time.Duration) error {

	desc, err := n.BuildServiceDescriptor(serviceID, introORs, lifetime)
	if err != nil {
		return err
	}

	payload, err := EncodeServiceDescriptor(desc)
	if err != nil {
		return err
	}

	maxChunk := RelayPayloadLen - FragmentHeaderLen
	frags := SplitPayload(payload, maxChunk)

	if len(frags) == 0 {
		return fmt.Errorf("empty descriptor payload")
	}

	msgID, err := n.GenerateMsgID()
	if err != nil {
		return err
	}

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[circID]
	n.cryptoStatesMu.Unlock()

	cc := n.clientCircuits[circID]

	cc.CryptoMu.Lock()
	err = n.SendFragments(frags, msgID, circID, cc, cryptoStates, RelayHSDirPublish)
	cc.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	replyCh := make(chan *ServiceDescriptor, 1)

	n.hsdirWaitMu.Lock()
	n.hsdirWait[circID] = replyCh
	n.hsdirWaitMu.Unlock()

	n.log.Info().Msgf("Sending %d fragments to HSDir", len(frags))

	n.log.Info().
		Str("serviceID", serviceID).
		Uint16("circID", circID).
		Msg("Client publishing descriptor to HSDir")

	select {
	case <-replyCh:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("HSDir publish timed out")
	}

}

// LookupDescriptorViaHSDir looks up a service descriptor from the HSDir
func (n *node) LookupDescriptorViaHSDir(circID uint16, serviceID string, timeout time.Duration,
) (*ServiceDescriptor, error) {

	cc, ok := n.clientCircuits[circID]
	if !ok {
		return nil, fmt.Errorf("not a client circuit %d", circID)
	}

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[circID]
	n.cryptoStatesMu.Unlock()

	if len(cryptoStates) == 0 {
		return nil, fmt.Errorf("no crypto states for circuit %d", circID)
	}

	cc.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayCellThroughCircuit(
		cryptoStates,
		[]byte(serviceID),
	)
	cc.CryptoMu.Unlock()
	if err != nil {
		return nil, err
	}

	relay := RelayCell{
		CircID:   circID,
		StreamID: 0,
		Command:  RelayHSDirLookup,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}

	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return nil, err
	}

	replyCh := make(chan *ServiceDescriptor, 1)

	n.hsdirWaitMu.Lock()
	n.hsdirWait[circID] = replyCh
	n.hsdirWaitMu.Unlock()

	err = n.SendCell(cc.Hops[0], cell, cc)
	if err != nil {
		return nil, err
	}

	select {
	case desc := <-replyCh:
		return desc, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("HSDir lookup timed out")
	}
}

// LookupDescriptor implements peer.TorHiddenServices
func (n *node) LookupDescriptor(circID uint16, serviceID string, timeout time.Duration) (bool, []string, []byte) {
	n.log.Info().
		Str("serviceID", serviceID).
		Uint16("circID", circID).
		Msg("Client performing HSDir lookup")

	descriptor, err := n.LookupDescriptorViaHSDir(circID, serviceID, timeout)
	if err != nil {
		return false, nil, []byte{}
	}

	// not found or expired
	if descriptor == nil {
		n.log.Info().
			Str("serviceID", serviceID).
			Msg("Client lookup: descriptor not found or expired")
		return false, nil, []byte{}
	}

	n.log.Info().
		Str("serviceID", serviceID).
		Int("introPoints", len(descriptor.IntroPoints)).
		Msg("Client lookup: descriptor received")
	return true, descriptor.IntroPoints, descriptor.ServicePubKey
}

// HandleRelayHSDirReply handles relay cells sent by the HSDir to reply to a lookup or publish request
func (n *node) HandleRelayHSDirReply(relay RelayCell) error {
	n.hsdirWaitMu.Lock()
	ch := n.hsdirWait[relay.CircID]
	n.hsdirWaitMu.Unlock()

	if ch == nil {
		return nil
	}

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[relay.CircID]
	n.cryptoStatesMu.Unlock()

	plaintext := decryptRelayDataAtClient(cryptoStates, relay.Data)

	hdr, chunk, err := DecodeFragment(plaintext)
	if err != nil {
		return err
	}

	full, done, err := n.AddFragment(relay.CircID, hdr.MsgID, hdr.Index, hdr.Total, chunk)
	if err != nil {
		return err
	}
	if !done {
		return nil
	}

	n.hsdirWaitMu.Lock()
	delete(n.hsdirWait, relay.CircID)
	n.hsdirWaitMu.Unlock()

	if len(full) == 0 {
		ch <- nil
		return nil //reply for building a service descriptor
	}

	desc, err := DecodeServiceDescriptor(full)
	if err != nil {
		return err
	}

	err = n.VerifyServiceDescriptor(desc)
	if err != nil {
		return err
	}

	ch <- desc
	return nil
}

// BuildServiceDescriptor implements peer.TorHiddenServices
func (n *node) BuildServiceDescriptor(serviceID string,
	introORs []string,
	lifetime time.Duration) (*ServiceDescriptor, error) {

	n.hiddenServiceMu.RLock()
	hs, ok := n.hiddenServices[serviceID]
	n.hiddenServiceMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("hidden service %s not found", serviceID)
	}

	pubBytes := x509.MarshalPKCS1PublicKey(hs.KeyPair.Public)
	serviceID = hs.ID

	desc := &ServiceDescriptor{
		ServiceID:     serviceID,
		ServicePubKey: pubBytes,
		IntroPoints:   append([]string(nil), introORs...),
		ExpiresAt:     time.Now().Add(lifetime),
	}

	// fields to sign: ServiceID || ExpiresAt || IntroPoints || ServicePubKey
	buf := bytes.Buffer{}
	buf.Write([]byte(serviceID))

	err := binary.Write(&buf, binary.BigEndian, desc.ExpiresAt.Unix())
	if err != nil {
		return nil, err
	}

	for _, ip := range introORs {
		buf.WriteString(ip)
	}
	buf.Write(pubBytes)

	// Sign with Bob's private key (digital signature)
	hash := sha256.Sum256(buf.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, hs.KeyPair.Private, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	desc.Signature = sig

	n.log.Info().
		Str("serviceID", serviceID).
		Time("expiresAt", desc.ExpiresAt).
		Dur("lifetime", lifetime).
		Int("introPoints", len(introORs)).
		Msg("Built hidden service descriptor")

	return desc, nil
}

// VerifyServiceDescriptor verifies the signature of a service descriptor
func (n *node) VerifyServiceDescriptor(desc *ServiceDescriptor) error {
	// ServiceID from the public key
	h := sha256.Sum256(desc.ServicePubKey)
	expectedID := fmt.Sprintf("%x", h[:])
	if desc.ServiceID != expectedID {
		return fmt.Errorf("serviceID does not match public key")
	}

	// Rebuild signed payload
	var buf bytes.Buffer
	buf.Write([]byte(desc.ServiceID))

	err := binary.Write(&buf, binary.BigEndian, desc.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("marshal expiresAt: %w", err)
	}

	for _, ip := range desc.IntroPoints {
		buf.WriteString(ip)
	}

	buf.Write(desc.ServicePubKey)

	// Hash payload
	hash := sha256.Sum256(buf.Bytes())

	// Parse public key
	pub, err := x509.ParsePKCS1PublicKey(desc.ServicePubKey)
	if err != nil {
		return fmt.Errorf("parse service public key: %w", err)
	}

	// Verify signature
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], desc.Signature)
	if err != nil {
		return fmt.Errorf("invalid descriptor signature")
	}

	return nil
}

// GetServiceIntroPoints implements peer.TorHiddenServices
func (n *node) GetServiceIntroPoints(serviceID string) []string {
	n.hiddenServiceMu.RLock()
	hs, ok := n.hiddenServices[serviceID]
	n.hiddenServiceMu.RUnlock()

	if !ok {
		return nil
	}
	out := make([]string, len(hs.IntroPoints))
	for i, p := range hs.IntroPoints {
		out[i] = p.RouterAddr
	}
	return out
}

// GetIntroPointCount implements peer.TorHiddenServices
func (n *node) GetIntroPointCount(serviceID string) int {
	n.hiddenServiceMu.RLock()
	defer n.hiddenServiceMu.RUnlock()
	return len(n.hiddenServices[serviceID].IntroPoints)
}

// GetIntroPointStateCount implements peer.TorHiddenServices
func (n *node) GetIntroPointStateCount(serviceID string) int {
	n.introPointsMu.Lock()
	defer n.introPointsMu.Unlock()
	list := n.introPoints[serviceID]
	return len(list)
}

// CreateHiddenService implements peer.TorHiddenServices
func (n *node) CreateHiddenService(introPoints [][3]string,
	timeout time.Duration,
	lifetime time.Duration,
	IntroCircID uint16) (string, []uint16, error) {

	if len(introPoints) == 0 {
		return "", nil, fmt.Errorf("at least one intro path is required")
	}

	// Create Hidden Service Locally
	serviceID, err := n.GenerateHiddenServiceID()
	if err != nil {
		return "", nil, err
	}

	circuits := make([]uint16, 0, len(introPoints))
	// auxiliar function to destroy circuits on error
	cleanup := func() {
		for _, cid := range circuits {
			_ = n.DestroyCircuit(cid)
		}
	}

	// Build circuits and establish intro points
	for i, hops := range introPoints {
		circID, err := n.BuildCircuit(hops, timeout)

		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("build circuit %d failed: %w", i, err)
		}

		err = n.EstablishIntroPoint(serviceID, circID, timeout)
		if err != nil {
			_ = n.DestroyCircuit(circID)
			cleanup()
			return "", nil, fmt.Errorf("establish intro point on circuit %d failed: %w", circID, err)
		}

		circuits = append(circuits, circID)
	}

	// Publish descriptor
	introORs := n.GetServiceIntroPoints(serviceID)

	err = n.PublishDescriptorToHSDir(serviceID, introORs, lifetime, IntroCircID, timeout)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("publish descriptor failed: %w", err)
	}

	n.log.Info().
		Str("serviceID", serviceID).
		Int("introPoints", len(introORs)).
		Msg("Hidden service created with explicit circuits")

	return serviceID, circuits, nil
}

// HandleRelayHSDirDelete handles relay cells sent to delete a service descriptor to the HSDir
func (n *node) HandleRelayHSDirDelete(relay RelayCell, circ *Circuit) error {
	if !n.IsHiddenServiceDir {
		return nil // ignore
	}

	hdr, chunk, err := DecodeFragment(relay.Data)
	if err != nil {
		return err
	}

	full, done, err := n.AddFragment(relay.CircID, hdr.MsgID, hdr.Index, hdr.Total, chunk)

	if err != nil {
		return err
	}
	if !done {
		return nil // wait for more fragments
	}

	desc, err := DecodeServiceDescriptor(full)
	if err != nil {
		return err
	}

	err = n.VerifyServiceDescriptor(desc)
	if err != nil {
		n.log.Error().Err(err).Msg("HSDir received invalid descriptor")
		return err
	}

	n.log.Info().
		Str("serviceID", desc.ServiceID).
		Msg("HSDir received delete request for service")

	n.hsDirMu.Lock()
	delete(n.hsDirStore, desc.ServiceID)
	n.hsDirMu.Unlock()

	n.log.Info().
		Str("serviceID", desc.ServiceID).
		Msg("HSDir deleted service")

	return n.SendHSDirReply(circ, nil)
}

// DeleteDescriptorFromHSDir sends a request to the HSDir to delete a service descriptor from the lookup service
func (n *node) DeleteDescriptorFromHSDir(serviceID string, circID uint16, timeout time.Duration) error {
	cc, ok := n.clientCircuits[circID]
	if !ok {
		return fmt.Errorf("not a client circuit %d", circID)
	}

	introORs := n.GetServiceIntroPoints(serviceID)
	desc, err := n.BuildServiceDescriptor(serviceID, introORs, 1*time.Minute)
	if err != nil {
		return err
	}

	payload, err := EncodeServiceDescriptor(desc)
	if err != nil {
		return err
	}

	maxChunk := RelayPayloadLen - FragmentHeaderLen
	frags := SplitPayload(payload, maxChunk)

	if len(frags) == 0 {
		return fmt.Errorf("empty descriptor payload")
	}

	msgID, err := n.GenerateMsgID()
	if err != nil {
		return err
	}

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[circID]
	n.cryptoStatesMu.Unlock()

	replyCh := make(chan *ServiceDescriptor, 1)

	n.hsdirWaitMu.Lock()
	n.hsdirWait[circID] = replyCh
	n.hsdirWaitMu.Unlock()

	n.log.Info().Msgf("Sending %d fragments to HSDir", len(frags))

	cc.CryptoMu.Lock()
	err = n.SendFragments(frags, msgID, circID, cc, cryptoStates, RelayHSDirDelete)
	cc.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	n.log.Info().
		Str("serviceID", serviceID).
		Uint16("circID", circID).
		Msg("Client deleting descriptor to HSDir")

	select {
	case <-replyCh:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("HSDir delete timed out")
	}
}

// DeleteHiddenService implements peer.TorHiddenServices
func (n *node) DeleteHiddenService(serviceID string, circID uint16) error {
	n.hiddenServiceMu.RLock()
	hs, ok := n.hiddenServices[serviceID]
	n.hiddenServiceMu.RUnlock()

	if !ok {
		return fmt.Errorf("hidden service %s not found", serviceID)
	}

	// the lifetime doesn't matter, since we are deleting the descriptor from the lookup service
	err := n.DeleteDescriptorFromHSDir(serviceID, circID, 5*time.Second)
	if err != nil {
		return err
	}

	// Destroy introduction point circuits
	for _, ip := range hs.IntroPoints {
		_ = n.DestroyCircuit(ip.CircID)
	}

	// Remove the local hidden service
	n.hiddenServiceMu.Lock()
	delete(n.hiddenServices, serviceID)
	n.hiddenServiceMu.Unlock()

	n.log.Info().
		Str("serviceID", serviceID).
		Msg("Hidden service deleted")

	return nil
}

// PrepareRendezvousPoint implements peer.TorRendezvous
func (n *node) PrepareRendezvousPoint(circID uint16, timeout time.Duration) (cookie [CookieSize]byte, err error) {
	rendezvousCookie := make([]byte, CookieSize)
	_, err = rand.Read(rendezvousCookie) // generate a random cookie
	if err != nil {
		return [CookieSize]byte{}, fmt.Errorf("failed to generate rendezvous cookie: %w", err)
	}

	n.log.Info().
		Uint16("circID", circID).
		Str("cookie", fmt.Sprintf("%x", rendezvousCookie)).
		Msg("Rendezvous cookie generated")

	// Generate ephemeral DH keypair for the rendezvous handshake
	var privateKey, publicKey [32]byte
	_, err = rand.Read(privateKey[:])
	if err != nil {
		return [CookieSize]byte{}, err
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Bind cookie → RP circuit
	n.cryptoStatesMu.Lock()
	n.rendezvousStates[string(rendezvousCookie[:])] = &DhRendezvousState{
		CircID:     circID, // RP circuit
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
	n.cryptoStatesMu.Unlock()

	replyCh := make(chan struct{})
	n.cookieAckMu.Lock()
	n.cookieAck[circID] = replyCh
	n.cookieAckMu.Unlock()

	err = n.SendRelayEstablishRP(circID, [CookieSize]byte(rendezvousCookie))
	if err != nil {
		n.cookieAckMu.Lock()
		delete(n.cookieAck, circID)
		n.cookieAckMu.Unlock()
		return [CookieSize]byte{}, fmt.Errorf("failed to send establish rendezvous point: %w", err)
	}

	n.log.Info().
		Uint16("circID", circID).
		Str("cookie", fmt.Sprintf("%x", rendezvousCookie)).
		Msg("Establish rendezvous point message sent, waiting for ACK")

	select {
	case <-replyCh:
		n.log.Info().
			Uint16("circID", circID).
			Str("cookie", fmt.Sprintf("%x", rendezvousCookie)).
			Msg("ACK received for rendezvous point establishment")
		return [CookieSize]byte(rendezvousCookie), nil
	case <-time.After(timeout):
		return [CookieSize]byte{}, fmt.Errorf("established rendezvous ack timed out")
	}
}

// SendRelayEstablishRP sends an establish rendezvous point relay cell to the selected OR
func (n *node) SendRelayEstablishRP(circID uint16, cookie [CookieSize]byte) error {
	n.clientCircuitsMu.RLock()
	cc, exists := n.clientCircuits[circID]
	n.clientCircuitsMu.RUnlock()
	if !exists {
		return fmt.Errorf("circuit %d not found", circID)
	}
	if cc.State != CircuitStateReady {
		return fmt.Errorf("circuit %d not ready", circID)
	}

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[circID]
	n.cryptoStatesMu.Unlock()

	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", circID)
	}

	cc.CryptoMu.Lock()
	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, cookie[:])
	cc.CryptoMu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to encrypt establish rendezvous cell: %w", err)
	}

	relayCell := RelayCell{
		CircID:   circID,
		StreamID: 0,
		Command:  RelayEstablishRP,
		Digest:   digest,
		Data:     encryptedPayload,
		Length:   uint16(len(encryptedPayload)),
	}

	cell, err := n.EncodeRelayCell(relayCell)
	if err != nil {
		return err
	}

	return n.SendCell(cc.Hops[0], cell, cc)
}

// HandleRelayRPEstablished handles the ACK from the OR confirming the rendezvous point establishment
func (n *node) HandleRelayRPEstablished(relay RelayCell) error {
	n.cookieAckMu.Lock()
	ackCh := n.cookieAck[relay.CircID]
	delete(n.cookieAck, relay.CircID)
	n.cookieAckMu.Unlock()

	if ackCh == nil {
		return nil // no one is waiting for this ACK, ignore
	}
	close(ackCh)
	return nil
}

// SendRPEstablished sends an ACK relay cell to confirm the rendezvous point establishment
func (n *node) SendRPEstablished(circ *Circuit) error {
	n.cryptoStatesMu.Lock()
	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	cryptoState := n.circuitCryptoStates[circ.InCircID][exitIdx]
	n.cryptoStatesMu.Unlock()

	// no payload for ACK, still need to compute digest
	circ.CryptoMu.Lock()
	emptyPayload, digest, err := EncryptRelayPayload(cryptoState, DirectionBackward, []byte{})
	circ.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	relay := RelayCell{
		CircID:   circ.InCircID,
		StreamID: 0,
		Command:  RelayRPEstablished,
		Digest:   digest,
		Length:   uint16(len(emptyPayload)),
		Data:     emptyPayload,
	}
	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return err
	}
	return n.SendCell(circ.PrevHop, cell, circ)
}

// HandleRelayEstablishRP handles the establishment of a rendezvous point by storing the cookie
func (n *node) HandleRelayEstablishRP(relay RelayCell, circ *Circuit) error {
	if relay.Length != CookieSize {
		return fmt.Errorf("invalid rendezvous cookie size: %d", relay.Length)
	}

	cookie := string(relay.Data[:CookieSize])
	n.rendezvousEntryMu.Lock()
	_, exist := n.rendezvousEntries[cookie]
	if exist {
		n.rendezvousEntryMu.Unlock()
		return nil // cookie already exists, ignore it
	}
	n.rendezvousEntries[cookie] = relay.CircID
	n.rendezvousEntryMu.Unlock()

	err := n.SendRPEstablished(circ)
	if err != nil {
		n.rendezvousEntryMu.Lock()
		delete(n.rendezvousEntries, cookie) // rollback the stored cookie
		n.rendezvousEntryMu.Unlock()
		return fmt.Errorf("failed to send RP established ACK: %w", err)
	}

	n.log.Info().
		Uint16("circID", circ.InCircID).
		Str("cookie", fmt.Sprintf("%x", cookie)).
		Msg("Rendezvous point established and ACK sent")

	return nil
}

// GetRendezvousEntriesCount implements peer.TorRendezvous
func (n *node) GetRendezvousEntriesCount() int {
	n.rendezvousEntryMu.Lock()
	defer n.rendezvousEntryMu.Unlock()
	return len(n.rendezvousEntries)
}

// SendIntroduceAck sends an Introduce ACK relay cell to the client indicating success or failure of the introduction
func (n *node) SendIntroduceAck(circ *Circuit, success bool) error {
	n.cryptoStatesMu.Lock()
	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	cryptoState := n.circuitCryptoStates[circ.InCircID][exitIdx]
	n.cryptoStatesMu.Unlock()

	var flag byte
	if success {
		flag = IntroduceACKSuccess
	} else {
		flag = IntroduceACKFail
	}
	circ.CryptoMu.Lock()
	flagPayload, digest, err := EncryptRelayPayload(cryptoState, DirectionBackward, []byte{flag})
	circ.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	relay := RelayCell{
		CircID:   circ.InCircID,
		StreamID: 0,
		Command:  RelayIntroduceACK,
		Digest:   digest,
		Length:   uint16(len(flagPayload)),
		Data:     flagPayload,
	}
	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return err
	}
	return n.SendCell(circ.PrevHop, cell, circ)
}

// HandleRelayIntroduceACK handles the Introduce ACK relay cell sent by the IP to the client
func (n *node) HandleRelayIntroduceACK(relay RelayCell) error {
	if relay.Data == nil || len(relay.Data) < 1 {
		return fmt.Errorf("invalid introduce ACK payload")
	}

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[relay.CircID]
	n.cryptoStatesMu.Unlock()
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", relay.CircID)
	}

	// Check if the introduction was successful
	flag := decryptRelayDataAtClient(cryptoStates, relay.Data)[0]
	var success bool
	switch flag {
	case IntroduceACKSuccess:
		success = true
	case IntroduceACKFail:
		success = false
	default:
		return fmt.Errorf("unknown introduce ACK flag %d", flag)
	}

	n.introAckMu.Lock()
	ackCh := n.introAckCh[relay.CircID]
	if ackCh == nil {
		n.introAckMu.Unlock()
		return nil // no one is waiting for this ACK, ignore
	}
	n.introAckSuccess[relay.CircID] = success
	close(ackCh)
	delete(n.introAckCh, relay.CircID)
	n.introAckMu.Unlock()

	n.log.Info().
		Uint16("circID", relay.CircID).
		Bool("success", success).
		Msg("Introduce ACK received")

	return nil
}

// EncodeServiceIntroduceMessage encodes a ServiceIntroduceMessage into a relay payload
func EncodeServiceIntroduceMessage(msg *ServiceIntroduceMessage) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	// Cookie (fixed size)
	_, err := buf.Write(msg.Cookie[:])
	if err != nil {
		return nil, err
	}

	// RPAddr (length-prefixed)
	rpb := []byte(msg.RPAddr)
	err = binary.Write(buf, binary.BigEndian, uint16(len(rpb)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(rpb)
	if err != nil {
		return nil, err
	}

	// ClientDHPub (length-prefixed)
	err = binary.Write(buf, binary.BigEndian, uint16(len(msg.ClientDHPub)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(msg.ClientDHPub)
	if err != nil {
		return nil, err
	}

	if buf.Len() > RelayPayloadLen {
		return nil, fmt.Errorf("service introduce message too large (%d bytes)", buf.Len())
	}

	return buf.Bytes(), nil
}

// DecodeServiceIntroduceMessage decodes a relay payload into a ServiceIntroduceMessage
func DecodeServiceIntroduceMessage(data []byte) (*ServiceIntroduceMessage, error) {
	buf := bytes.NewReader(data)
	msg := &ServiceIntroduceMessage{}

	// Cookie (fixed size)
	_, err := buf.Read(msg.Cookie[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read cookie: %w", err)
	}

	// RPAddr (length-prefixed)
	var rpLen uint16
	err = binary.Read(buf, binary.BigEndian, &rpLen)
	if err != nil {
		return nil, fmt.Errorf("failed to read RPAddr length: %w", err)
	}
	rpb := make([]byte, rpLen)
	_, err = buf.Read(rpb)
	if err != nil {
		return nil, fmt.Errorf("failed to read RPAddr: %w", err)
	}
	msg.RPAddr = string(rpb)

	// ClientDHPub (length-prefixed)
	var dhLen uint16
	err = binary.Read(buf, binary.BigEndian, &dhLen)
	if err != nil {
		return nil, fmt.Errorf("failed to read ClientDHPub length: %w", err)
	}
	msg.ClientDHPub = make([]byte, dhLen)
	_, err = buf.Read(msg.ClientDHPub)
	if err != nil {
		return nil, fmt.Errorf("failed to read ClientDHPub: %w", err)
	}

	return msg, nil
}

// EncodeIPIntroduceMessage encodes an IPIntroduceMessage into a relay payload
func EncodeIPIntroduceMessage(msg *IPIntroduceMessage) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	// ServiceID (length-prefixed)
	sidBytes := []byte(msg.ServiceID)
	err := binary.Write(buf, binary.BigEndian, uint16(len(sidBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(sidBytes)
	if err != nil {
		return nil, err
	}

	// encryptedBlob (length-prefixed)
	err = binary.Write(buf, binary.BigEndian, uint16(len(msg.EncryptedBlob)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(msg.EncryptedBlob)
	if err != nil {
		return nil, err
	}

	if buf.Len() > RelayPayloadLen {
		return nil, fmt.Errorf("IP introduce message too large (%d bytes)", buf.Len())
	}

	return buf.Bytes(), nil
}

// DecodeIPIntroduceMessage decodes an IPIntroduceMessage from a relay payload
func DecodeIPIntroduceMessage(data []byte) (*IPIntroduceMessage, error) {
	buf := bytes.NewReader(data)

	// ServiceID (length-prefixed)
	var sidLen uint16
	err := binary.Read(buf, binary.BigEndian, &sidLen)
	if err != nil {
		return nil, fmt.Errorf("read ServiceID length: %w", err)
	}
	sidBytes := make([]byte, sidLen)
	_, err = buf.Read(sidBytes)
	if err != nil {
		return nil, fmt.Errorf("read ServiceID: %w", err)
	}

	// encryptedBlob (length-prefixed)
	var blobLen uint16
	err = binary.Read(buf, binary.BigEndian, &blobLen)
	if err != nil {
		return nil, fmt.Errorf("read encryptedBlob length: %w", err)
	}
	encryptedBlob := make([]byte, blobLen)
	_, err = buf.Read(encryptedBlob)
	if err != nil {
		return nil, fmt.Errorf("read encryptedBlob: %w", err)
	}

	return &IPIntroduceMessage{
		ServiceID:     string(sidBytes),
		EncryptedBlob: encryptedBlob,
	}, nil
}

// SendIntroduce1Message sends an introduce1 message to the introduction point for the specified service
func (n *node) SendIntroduce1Message(circID uint16, serviceID string,
	servicePubKey []byte, cookie [CookieSize]byte, rendezvousAddr string) error {
	if len(servicePubKey) == 0 {
		return fmt.Errorf("service public key is required")
	}
	if len(serviceID) == 0 {
		return fmt.Errorf("service ID is required")
	}

	// Check that the circuit is ready
	n.clientCircuitsMu.Lock()
	cc, exists := n.clientCircuits[circID]
	if !exists {
		n.clientCircuitsMu.Unlock()
		return fmt.Errorf("unknown client circuit %d", circID)
	}
	if cc.State != CircuitStateReady {
		n.clientCircuitsMu.Unlock()
		return fmt.Errorf("circuit %d not ready (state: %d)", circID, cc.State)
	}
	n.clientCircuitsMu.Unlock()

	// Get crypto states for the circuit
	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[circID]
	n.cryptoStatesMu.Unlock()
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", circID)
	}

	n.cryptoStatesMu.Lock()
	st := n.rendezvousStates[string(cookie[:])]
	n.cryptoStatesMu.Unlock()

	if st == nil {
		return fmt.Errorf("no rendezvous state for cookie")
	}

	// Prepare the ServiceIntroduceMessage for the service
	serviceIntroMsg := &ServiceIntroduceMessage{
		Cookie:      cookie,
		RPAddr:      rendezvousAddr,
		ClientDHPub: st.PublicKey[:],
	}

	servicePayload, err := EncodeServiceIntroduceMessage(serviceIntroMsg)
	if err != nil {
		return fmt.Errorf("failed to encode service introduce message: %w", err)
	}

	// Encrypt the ServiceIntroduceMessage with the service public key
	rsaServicePubKey, err := x509.ParsePKCS1PublicKey(servicePubKey)
	if err != nil {
		return fmt.Errorf("failed to parse service public key: %w", err)
	}
	encryptedPayload, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaServicePubKey, servicePayload, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %w", err)
	}

	// Prepare the IPIntroduceMessage for the introduction point
	ipIntroMsg := &IPIntroduceMessage{
		ServiceID:     serviceID,
		EncryptedBlob: encryptedPayload,
	}
	ipPayload, err := EncodeIPIntroduceMessage(ipIntroMsg)
	if err != nil {
		return fmt.Errorf("failed to encode IP introduce message: %w", err)
	}

	cc.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, ipPayload)
	cc.CryptoMu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to encrypt relay cell: %w", err)
	}

	relay := RelayCell{
		CircID:   circID,
		StreamID: 0,
		Command:  RelayIntroduce1,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}
	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return fmt.Errorf("failed to encode relay cell: %w", err)
	}

	err = n.SendCell(cc.Hops[0], cell, cc)
	if err != nil {
		return fmt.Errorf("failed to send cell: %w", err)
	}

	n.log.Info().
		Uint16("circID", circID).
		Str("serviceID", serviceID).
		Msg("Sent introduce1 message to introduction point")

	return nil
}

// SendIntroduce2Message sends an introduce2 message to the hidden service from the introduction point
func (n *node) SendIntroduce2Message(circ *Circuit, encryptedBlob []byte) error {
	n.cryptoStatesMu.Lock()
	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	cryptoState := n.circuitCryptoStates[circ.InCircID][exitIdx]
	n.cryptoStatesMu.Unlock()

	circ.CryptoMu.Lock()
	payload, digest, err := EncryptRelayPayload(cryptoState, DirectionBackward, encryptedBlob)
	circ.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	relay := RelayCell{
		CircID:   circ.InCircID,
		StreamID: 0,
		Command:  RelayIntroduce2,
		Digest:   digest,
		Length:   uint16(len(payload)),
		Data:     payload,
	}
	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return err
	}
	return n.SendCell(circ.PrevHop, cell, circ)
}

// HandleRelayIntroduce1 handles an introduce1 relay cell received at the introduction point
func (n *node) HandleRelayIntroduce1(relay RelayCell, circ *Circuit) error {
	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[relay.CircID]
	n.cryptoStatesMu.Unlock()
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", relay.CircID)
	}

	ipIntroMsg, err := DecodeIPIntroduceMessage(relay.Data)

	if err != nil {
		return fmt.Errorf("failed to decode IP introduce message: %w", err)
	}

	n.log.Info().
		Uint16("circID", relay.CircID).
		Str("serviceID", ipIntroMsg.ServiceID).
		Msg("Received introduce1 message at introduction point")

	n.introPointsMu.Lock()
	introList, found := n.introPoints[ipIntroMsg.ServiceID]
	n.introPointsMu.Unlock()

	// No introduction points found for the service ID, send failure ACK
	if !found || len(introList) == 0 {
		n.log.Info().
			Str("serviceID", ipIntroMsg.ServiceID).
			Msg("No introduction points found for service ID")
		return n.SendIntroduceAck(circ, false)
	}

	// Introduction point found, send introduce2 to the hidden service and ACK to the client
	introState := introList[0]
	var targetCirc *Circuit
	n.circuitsMu.Lock()
	for _, c := range n.circuits {
		if c.InCircID == introState.BobCircID {
			targetCirc = c
			break
		}
	}
	n.circuitsMu.Unlock()

	if targetCirc == nil {
		err = n.SendIntroduceAck(circ, false)
		if err != nil {
			return fmt.Errorf("failed to send introduce ACK: %w", err)
		}
		n.log.Info().
			Uint16("bobCircID", introState.BobCircID).
			Msg("No circuit found for BobCircID, sent failure ACK to client")
		return fmt.Errorf("no circuit found for BobCircID")
	}

	payload, err := EncodeIPIntroduceMessage(ipIntroMsg)
	if err != nil {
		return fmt.Errorf("failed to encode IP introduce message: %w", err)
	}
	err = n.SendIntroduce2Message(targetCirc, payload)
	if err != nil {
		return fmt.Errorf("failed to send introduce2 message: %w", err)
	}

	n.log.Info().
		Uint16("inCircID", relay.CircID).
		Uint16("outCircID", introState.BobCircID).
		Str("serviceID", ipIntroMsg.ServiceID).
		Msg("Sent introduce2 message to hidden service")

	err = n.SendIntroduceAck(circ, true)
	if err != nil {
		return fmt.Errorf("failed to send introduce ACK: %w", err)
	}

	n.log.Info().
		Uint16("circID", relay.CircID).
		Str("serviceID", ipIntroMsg.ServiceID).
		Msg("Sent introduce ACK to client")
	return nil
}

// IntroduceToHiddenService implements peer.TorClientIntroduction
func (n *node) IntroduceToHiddenService(circID uint16, serviceID string,
	servicePubKey []byte, cookie [CookieSize]byte, rendezvousAddr string, timeout time.Duration) error {
	n.introAckMu.Lock()
	ackCh := make(chan struct{})
	n.introAckCh[circID] = ackCh
	n.introAckSuccess[circID] = false
	n.introAckMu.Unlock()

	err := n.SendIntroduce1Message(circID, serviceID, servicePubKey, cookie, rendezvousAddr)
	if err != nil {
		n.introAckMu.Lock()
		delete(n.introAckCh, circID)
		delete(n.introAckSuccess, circID)
		n.introAckMu.Unlock()
		return fmt.Errorf("failed to send introduce1 message: %w", err)
	}

	select {
	case <-ackCh:
		n.introAckMu.Lock()
		success := n.introAckSuccess[circID]
		delete(n.introAckSuccess, circID)
		n.introAckMu.Unlock()
		if success {
			n.log.Info().
				Uint16("circID", circID).
				Str("serviceID", serviceID).
				Msg("Introduce ACK received: success")
			return nil
		} else {
			n.log.Info().
				Uint16("circID", circID).
				Str("serviceID", serviceID).
				Msg("Introduce ACK received: failure")
			return fmt.Errorf("introduction failed according to ACK")
		}
	case <-time.After(timeout):
		n.introAckMu.Lock()
		delete(n.introAckCh, circID)
		delete(n.introAckSuccess, circID)
		n.introAckMu.Unlock()
		return fmt.Errorf("introduce ACK timed out")
	}
}

// HandleRelayIntroduce2 handles an introduce2 relay cell received at the node who owns the hidden service
func (n *node) HandleRelayIntroduce2(relay RelayCell) error {
	n.log.Info().
		Uint16("circID", relay.CircID).
		Msg("Received introduce2 message at hidden service")

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[relay.CircID]
	n.cryptoStatesMu.Unlock()

	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", relay.CircID)
	}

	// Decode outer message
	plaintext := decryptRelayDataAtClient(cryptoStates, relay.Data)
	ipIntroMsg, err := DecodeIPIntroduceMessage(plaintext)
	if err != nil {
		return fmt.Errorf("failed to decode IP introduce message: %w", err)
	}

	n.hiddenServiceMu.RLock()
	hs, ok := n.hiddenServices[ipIntroMsg.ServiceID]
	n.hiddenServiceMu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown hidden service %s", ipIntroMsg.ServiceID)
	}

	// Decrypt inner blob using the service private key
	decrypted, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		hs.KeyPair.Private,
		ipIntroMsg.EncryptedBlob,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to decrypt introduce2 blob: %w", err)
	}

	// Decode ServiceIntroduceMessage
	serviceIntro, err := DecodeServiceIntroduceMessage(decrypted)
	if err != nil {
		return fmt.Errorf("failed to decode service introduce message: %w", err)
	}

	if len(serviceIntro.ClientDHPub) != 32 {
		return fmt.Errorf("invalid client DH public key length")
	}

	var alicePub [32]byte
	copy(alicePub[:], serviceIntro.ClientDHPub)

	// Store Alice DH state for rendezvous
	n.cryptoStatesMu.Lock()
	n.diffieHellmanHandshakePairs[relay.CircID] = &DiffieHellmanHandshakePairs{
		PublicKey: alicePub,
	}
	n.cryptoStatesMu.Unlock()

	go func() {
		err := n.SendRelayRendezvous1(relay.CircID, serviceIntro.Cookie, serviceIntro.RPAddr)
		if err != nil {
			n.log.Error().Err(err).
				Uint16("introCircID", relay.CircID).
				Str("rpAddr", serviceIntro.RPAddr).
				Msg("failed to build/send rendezvous1")
		}
	}()

	n.log.Info().
		Str("serviceID", ipIntroMsg.ServiceID).
		Str("rpAddr", serviceIntro.RPAddr).
		Msg("Introduce2 received, starting rendezvous")

	return nil
}

// SendRelayRendezvous1 builds a circuit to Alice RP, sending the Rendezvous cookie, and the second half of the DH
// handshake and a hash of the session key
func (n *node) SendRelayRendezvous1(circID uint16, cookie [CookieSize]byte, rendezvousAddr string) error {
	n.log.Info().
		Uint16("introCircID", circID).
		Str("rpAddr", rendezvousAddr).
		Msg("Building circuit to rendezvous point")

	// Retrieve DH state from INTRODUCE1
	n.cryptoStatesMu.Lock()
	dhState, ok := n.diffieHellmanHandshakePairs[circID]
	n.cryptoStatesMu.Unlock()

	if !ok {
		return fmt.Errorf("no DH state for rendezvous on circ %d", circID)
	}

	// Build circuit to the rendezvous point
	middleHops, err := n.BuildRandomPath(2, rendezvousAddr)
	if err != nil {
		return fmt.Errorf("failed to build random path: %w", err)
	}

	n.log.Info().
		Str("rpAddr", rendezvousAddr).
		Msg("Building circuit to rendezvous point")

	rpCircID, err := n.BuildCircuit([3]string{
		middleHops[0],
		middleHops[1],
		rendezvousAddr,
	}, 5*time.Second)

	if err != nil {
		return fmt.Errorf("failed to build circuit to RP: %w", err)
	}

	n.log.Info().
		Uint16("rpCircID", rpCircID).
		Msg("Circuit to rendezvous point built")

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[rpCircID]
	n.cryptoStatesMu.Unlock()

	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for RP circuit")
	}

	n.clientCircuitsMu.RLock()
	cc := n.clientCircuits[rpCircID]
	n.clientCircuitsMu.RUnlock()

	// Generate Bob’s DH keypair
	var bobPriv, bobPub [32]byte
	_, err = rand.Read(bobPriv[:])
	if err != nil {
		return err
	}
	curve25519.ScalarBaseMult(&bobPub, &bobPriv)

	// Compute secret between Alice and Bob
	sharedSecret, err := curve25519.X25519(bobPriv[:], dhState.PublicKey[:])
	if err != nil {
		return err
	}

	// Compute handshake hash
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write([]byte("handshake"))
	handshakeHash := h.Sum(nil)

	// Build payload
	payload := bytes.NewBuffer(nil)
	payload.Write(cookie[:])
	payload.Write(bobPub[:])
	payload.Write(handshakeHash)

	cc.CryptoMu.Lock()
	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, payload.Bytes())
	cc.CryptoMu.Unlock()
	if err != nil {
		return err
	}

	relay := RelayCell{
		CircID:   rpCircID,
		StreamID: 0,
		Command:  RelayRendezvous1,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}

	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return err
	}

	n.log.Info().
		Uint16("rpCircID", rpCircID).
		Msg("Sending Rendezvous1 to rendezvous point")

	return n.SendCell(cc.Hops[0], cell, cc)
}

func (n *node) HandleRelayRendezvous1(relay RelayCell, circ *Circuit) error {
	n.log.Info().
		Uint16("circID", relay.CircID).
		Msg("Rendezvous1 received at rendezvous point")

	data := relay.Data

	n.rendezvousEntryMu.Lock()
	aliceCircID, ok := n.rendezvousEntries[string(data[:CookieSize])]
	n.rendezvousEntryMu.Unlock()

	if !ok {
		return fmt.Errorf("unknown rendezvous cookie")
	}

	// Find Alice circuit
	n.circuitsMu.Lock()
	var aliceCirc *Circuit
	for _, c := range n.circuits {
		if c.InCircID == aliceCircID {
			aliceCirc = c
			break
		}
	}
	n.circuitsMu.Unlock()

	if aliceCirc == nil {
		return fmt.Errorf("alice circuit not found for rendezvous")
	}

	n.log.Info().
		Uint16("aliceCircID", aliceCircID).
		Msg("Forwarding Rendezvous2 to Alice")
	return n.SendRelayRendezvous2(data, aliceCircID, aliceCirc)
}

// SendRelayRendezvous2 sends a message from RP to Alice with Bob's second half of the DH handshake, the hash and cookie
func (n *node) SendRelayRendezvous2(data []byte, circID uint16, circ *Circuit) error {

	// Forward Rendezvous1 payload backward to Alice
	n.cryptoStatesMu.Lock()
	exitIdx := len(n.circuitCryptoStates[circID]) - 1
	cryptoState := n.circuitCryptoStates[circID][exitIdx]
	n.cryptoStatesMu.Unlock()

	circ.CryptoMu.Lock()
	payload, digest, err := EncryptRelayPayload(cryptoState, DirectionBackward, data)
	circ.CryptoMu.Unlock()

	if err != nil {
		return err
	}

	relayOut := RelayCell{
		CircID:   circID,
		StreamID: 0,
		Command:  RelayRendezvous2,
		Digest:   digest,
		Length:   uint16(len(payload)),
		Data:     payload,
	}

	cell, err := n.EncodeRelayCell(relayOut)
	if err != nil {
		return err
	}

	return n.SendCell(circ.PrevHop, cell, circ)
}

// HandleRelayRendezvous2 receives the following message: Cookie | second half of DH | H(session_key)
// from Bob, which was forwarded from RP to Alice.
func (n *node) HandleRelayRendezvous2(relay RelayCell) error {
	n.log.Info().
		Uint16("circID", relay.CircID).
		Msg("Received Rendezvous2 from rendezvous point")

	n.cryptoStatesMu.Lock()
	cryptoStates := n.circuitCryptoStates[relay.CircID]
	n.cryptoStatesMu.Unlock()
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", relay.CircID)
	}

	data := decryptRelayDataAtClient(cryptoStates, relay.Data)

	cookie := data[:CookieSize]
	bobPub := data[CookieSize : CookieSize+32]
	recvHash := data[CookieSize+32 : CookieSize+64]

	n.cryptoStatesMu.Lock()
	st := n.rendezvousStates[string(cookie)]
	delete(n.rendezvousStates, string(cookie))
	n.cryptoStatesMu.Unlock()

	if st == nil {
		return fmt.Errorf("no DH state for rendezvous")
	}

	// Compute shared secret
	shared, err := curve25519.X25519(st.PrivateKey[:], bobPub)
	if err != nil {
		return err
	}

	// Verify hash H(K)
	h := sha256.New()
	h.Write(shared)
	h.Write([]byte("handshake"))
	expected := h.Sum(nil)

	if !bytes.Equal(expected, recvHash) {
		return fmt.Errorf("rendezvous handshake hash mismatch")
	}

	// Derive circuit crypto keys
	cryptoState, err := generateCircuitKeys(shared)
	if err != nil {
		return err
	}

	n.cryptoStatesMu.Lock()
	n.circuitCryptoStates[st.CircID] = append(n.circuitCryptoStates[st.CircID], cryptoState)
	n.cryptoStatesMu.Unlock()

	n.log.Info().
		Uint16("circID", relay.CircID).
		Msg("Rendezvous handshake complete, circuit joined")

	return nil
}

// GetCircuitCryptoStatesCount implements peer.TorRendezvous
func (n *node) GetCircuitCryptoStatesCount(circID uint16) int {
	n.cryptoStatesMu.Lock()
	defer n.cryptoStatesMu.Unlock()
	return len(n.circuitCryptoStates[circID])
}

// GetServicePublicKey implements peer.TorRendezvous
func (n *node) GetServicePublicKey(serviceID string) []byte {
	n.hiddenServiceMu.RLock()
	defer n.hiddenServiceMu.RUnlock()
	return x509.MarshalPKCS1PublicKey(n.hiddenServices[serviceID].KeyPair.Public)
}
