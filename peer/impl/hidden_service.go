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
	"time"
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

// GenerateHiddenServiceID implements peer.TorHiddenServices
func (n *node) GenerateHiddenServiceID() (string, error) {
	key, err := GenerateOnionKeyPair()
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

	n.hiddenServices[serviceID] = hs
	return serviceID, nil
}

// EstablishIntroPoint implements Tor.HiddenServices
func (n *node) EstablishIntroPoint(serviceID string, circID uint16, timeout time.Duration) error {
	hs, ok := n.hiddenServices[serviceID]
	if !ok {
		return fmt.Errorf("unknown serviceID: %s", serviceID)
	}

	pubBytes := x509.MarshalPKCS1PublicKey(hs.KeyPair.Public)
	payload := pubBytes

	cryptoStates := n.circuitCryptoStates[circID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto state for circ %d", circID)
	}

	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, payload)
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

	_, ok = n.clientCircuits[circID]
	if !ok {
		return fmt.Errorf("not a client circuit %d", circID)
	}

	ch := make(chan struct{})

	n.introWaitMu.Lock()
	n.introWait[circID] = ch
	n.introWaitMu.Unlock()

	return n.SendAndWaitForIntroReply(circID, serviceID, cell, timeout)
}

// SendAndWaitForIntroReply tries to create an Introduction Point and waits for the corresponding confirmation
func (n *node) SendAndWaitForIntroReply(circID uint16, serviceID string, cell Cell, timeout time.Duration) error {
	hs := n.hiddenServices[serviceID]
	cc := n.clientCircuits[circID]

	ch := make(chan struct{})

	n.introWaitMu.Lock()
	n.introWait[circID] = ch
	n.introWaitMu.Unlock()

	// Send it via guard of this circuit
	err := n.SendCell(cc.Hops[0], cell)
	if err != nil {
		return err
	}

	select {
	case <-ch:
		//TODO: Simplified, Bob can choose the OR that acts as a introduction point
		hs.IntroPoints = append(hs.IntroPoints, IntroPoint{
			RouterAddr: cc.Hops[2],
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
	cryptoStates := n.circuitCryptoStates[circ.InCircID]
	exitIdx := len(cryptoStates) - 1
	cryptoState := cryptoStates[exitIdx]

	encrypted, digest, err := EncryptRelayPayload(
		cryptoState,
		DirectionBackward,
		[]byte{}, // empty payload
	)
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

	return n.SendCell(circ.PrevHop, cell)
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

// SetPeerAsHSDir sets the flag to indicate if the peer should act as a lookup server
func (n *node) SetPeerAsHSDir(value bool) {
	n.IsHiddenServiceDir = value
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

	if buf.Len() > RelayPayloadLen {
		return nil, fmt.Errorf("service descriptor too large (%d bytes)", buf.Len())
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

func (n *node) HandleRelayHSDirPublish(relay RelayCell, circ *Circuit) error {
	if !n.IsHiddenServiceDir {
		return nil // ignore
	}

	desc, err := DecodeServiceDescriptor(relay.Data)
	if err != nil {
		return err
	}

	n.hsDirMu.Lock()
	n.hsDirStore[desc.ServiceID] = desc
	n.hsDirMu.Unlock()

	return n.SendHSDirReply(circ, nil)
}

func (n *node) HandleRelayHSDirLookup(relay RelayCell, circ *Circuit) error {
	if !n.IsHiddenServiceDir {
		return n.SendHSDirReply(circ, nil)
	}

	serviceID := string(relay.Data)

	n.hsDirMu.RLock()
	desc := n.hsDirStore[serviceID]
	n.hsDirMu.RUnlock()

	if desc == nil || time.Now().After(desc.ExpiresAt) {
		return n.SendHSDirReply(circ, nil)
	}

	payload, err := EncodeServiceDescriptor(desc)
	if err != nil {
		return err
	}

	return n.SendHSDirReply(circ, payload)
}

func (n *node) SendHSDirReply(circ *Circuit, payload []byte) error {
	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	cryptoState := n.circuitCryptoStates[circ.InCircID][exitIdx]

	encrypted, digest, err := EncryptRelayPayload(cryptoState, DirectionBackward, payload)
	if err != nil {
		return err
	}

	relay := RelayCell{
		CircID:   circ.InCircID,
		StreamID: 0,
		Command:  RelayHSDirReply,
		Digest:   digest,
		Length:   uint16(len(encrypted)),
		Data:     encrypted,
	}
	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return err
	}
	return n.SendCell(circ.PrevHop, cell)
}

func (n *node) PublishDescriptorToHSDir(desc *ServiceDescriptor, circID uint16, timeout time.Duration) error {
	payload, err := EncodeServiceDescriptor(desc)
	if err != nil {
		return err
	}

	cryptoStates := n.circuitCryptoStates[circID]
	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, payload)
	if err != nil {
		return err
	}

	relay := RelayCell{
		CircID: circID, StreamID: 0,
		Command: RelayHSDirPublish,
		Digest:  digest, Length: uint16(len(encrypted)),
		Data: encrypted,
	}
	cell, err := n.EncodeRelayCell(relay)
	if err != nil {
		return err
	}

	cc := n.clientCircuits[circID]
	return n.SendCell(cc.Hops[0], cell)
}

func (n *node) LookupDescriptorViaHSDir(circID uint16, serviceID string, timeout time.Duration,
) (*ServiceDescriptor, error) {

	cc, ok := n.clientCircuits[circID]
	if !ok {
		return nil, fmt.Errorf("not a client circuit %d", circID)
	}

	cryptoStates := n.circuitCryptoStates[circID]
	if len(cryptoStates) == 0 {
		return nil, fmt.Errorf("no crypto states for circuit %d", circID)
	}

	encrypted, digest, err := EncryptRelayCellThroughCircuit(
		cryptoStates,
		[]byte(serviceID),
	)
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

	err = n.SendCell(cc.Hops[0], cell)
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

func (n *node) HandleRelayHSDirReply(relay RelayCell) error {
	n.hsdirWaitMu.Lock()
	ch := n.hsdirWait[relay.CircID]
	delete(n.hsdirWait, relay.CircID)
	n.hsdirWaitMu.Unlock()

	if ch == nil {
		return nil
	}

	if len(relay.Data) == 0 {
		ch <- nil
		return nil
	}

	desc, err := DecodeServiceDescriptor(relay.Data)
	if err != nil {
		return err
	}

	// TODO: VerifyServiceDescriptor(desc)
	ch <- desc
	return nil
}

// BuildServiceDescriptor implements peer.TorHiddenServices
func (n *node) BuildServiceDescriptor(serviceID string, introORs []string, lifetime time.Duration) ServiceDescriptor {
	hs, ok := n.hiddenServices[serviceID]
	if !ok {
		return ServiceDescriptor{}
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
	b, _ := desc.ExpiresAt.MarshalBinary()
	buf.Write(b)
	for _, ip := range introORs {
		buf.WriteString(ip)
	}
	buf.Write(pubBytes)

	// Sign with Bob's private key (digital signature)
	hash := sha256.Sum256(buf.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, hs.KeyPair.Private, crypto.SHA256, hash[:])
	if err != nil {
		return ServiceDescriptor{}
	}
	desc.Signature = sig

	return *desc
}

// GetServiceIntroPoints implements peer.TorHiddenServices
func (n *node) GetServiceIntroPoints(serviceID string) []string {
	hs, ok := n.hiddenServices[serviceID]
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
	return len(n.hiddenServices[serviceID].IntroPoints)
}

// GetIntroPointStateCount implements peer.TorHiddenServices
func (n *node) GetIntroPointStateCount(serviceID string) int {
	n.introPointsMu.Lock()
	defer n.introPointsMu.Unlock()
	list := n.introPoints[serviceID]
	return len(list)
}

func (n *node) CreateHiddenService(introPoints [][3]string,
	timeout time.Duration,
	lifetime time.Duration) (string, []uint16, error) {

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
	serviceDesc := n.BuildServiceDescriptor(serviceID, introORs, lifetime) //FIXME

	if serviceDesc.ServiceID == "" {
		cleanup()
		return "", nil, fmt.Errorf("failed to build service descriptor")
	}

	err = n.PublishDescriptorToHSDir(&serviceDesc, circuits[0], timeout)
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
