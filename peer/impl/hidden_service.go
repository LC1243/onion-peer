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

type IPIntroduceMessage struct {
	ServiceID     string
	EncryptedBlob []byte // encrypted ServiceIntroduceMessage with service pubkey
}

type ServiceIntroduceMessage struct {
	Cookie      [CookieSize]byte
	RPAddr      string
	ClientDHPub []byte
}

// GenerateServiceKeyPair generates a new RSA keypair for use as keys for a service
// NOTE: We intentionally use 1024-bit RSA keys here.
// In real Tor, hidden services keys and descriptors are fragmented
// across multiple cells. In this simplified implementation, service descriptors
// must fit within a single relay cell (RelayPayloadLen = 498 bytes).
func GenerateServiceKeyPair() (*OnionKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
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

// SetPeerAsHSDir implements peer.TorHiddenServices
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

// HandleRelayHSDirPublish handles relay cells sent to publish a service descriptor to the HSDir
func (n *node) HandleRelayHSDirPublish(relay RelayCell, circ *Circuit) error {
	if !n.IsHiddenServiceDir {
		return nil // ignore
	}

	desc, err := DecodeServiceDescriptor(relay.Data)
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

	n.log.Info().
		Str("serviceID", serviceID).
		Uint16("circID", circID).
		Msg("Client publishing descriptor to HSDir")

	replyCh := make(chan *ServiceDescriptor, 1)

	n.hsdirWaitMu.Lock()
	n.hsdirWait[circID] = replyCh
	n.hsdirWaitMu.Unlock()

	err = n.SendCell(cc.Hops[0], cell)
	if err != nil {
		return err
	}

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

// LookupDescriptor implements peer.TorHiddenServices
func (n *node) LookupDescriptor(circID uint16, serviceID string, timeout time.Duration) (bool, []string) {
	n.log.Info().
		Str("serviceID", serviceID).
		Uint16("circID", circID).
		Msg("Client performing HSDir lookup")

	descriptor, err := n.LookupDescriptorViaHSDir(circID, serviceID, timeout)
	if err != nil {
		return false, nil
	}

	// not found or expired
	if descriptor == nil {
		n.log.Info().
			Str("serviceID", serviceID).
			Msg("Client lookup: descriptor not found or expired")
		return false, nil
	}

	n.log.Info().
		Str("serviceID", serviceID).
		Int("introPoints", len(descriptor.IntroPoints)).
		Msg("Client lookup: descriptor received")
	return true, descriptor.IntroPoints
}

// HandleRelayHSDirReply handles relay cells sent by the HSDir to reply to a lookup or publish request
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
		return nil //reply for building a service descriptor
	}

	cryptoStates := n.circuitCryptoStates[relay.CircID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", relay.CircID)
	}

	plaintext := decryptRelayDataAtClient(cryptoStates, relay.Data, relay.Digest)

	desc, err := DecodeServiceDescriptor(plaintext)
	if err != nil {
		n.log.Info().Msgf("7")
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

	hs, ok := n.hiddenServices[serviceID]
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

// CreateHiddenService implements peer.TorHiddenServices
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

	err = n.PublishDescriptorToHSDir(serviceID, introORs, lifetime, circuits[0], timeout)
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

// DeleteHiddenService implements peer.TorHiddenServices
func (n *node) DeleteHiddenService(serviceID string) error {
	hs, ok := n.hiddenServices[serviceID]
	if !ok {
		return fmt.Errorf("hidden service %s not found", serviceID)
	}

	// Destroy introduction point circuits
	for _, ip := range hs.IntroPoints {
		_ = n.DestroyCircuit(ip.CircID)
	}

	// Remove the local hidden service
	delete(n.hiddenServices, serviceID)

	n.log.Info().
		Str("serviceID", serviceID).
		Msg("Hidden service deleted locally")

	return nil
}

// PrepareRendezvousPoint implements peer.TorHiddenServices
func (n *node) PrepareRendezvousPoint(serviceID, circID uint16,
	timeout time.Duration) (cookie [CookieSize]byte, err error) {
	rendezvousCookie := make([]byte, CookieSize)
	_, err = rand.Read(rendezvousCookie) // generate a random cookie
	if err != nil {
		return [CookieSize]byte{}, fmt.Errorf("failed to generate rendezvous cookie: %w", err)
	}

	n.log.Info().
		Uint16("serviceID", serviceID).
		Uint16("circID", circID).
		Str("cookie", fmt.Sprintf("%x", rendezvousCookie)).
		Msg("Rendezvous cookie generated")

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
		Uint16("serviceID", serviceID).
		Uint16("circID", circID).
		Str("cookie", fmt.Sprintf("%x", rendezvousCookie)).
		Msg("Establish rendezvous point message sent, waiting for ACK")

	select {
	case <-replyCh:
		n.log.Info().
			Uint16("serviceID", serviceID).
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

	cryptoStates := n.circuitCryptoStates[circID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", circID)
	}

	encryptedPayload, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, cookie[:])
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

	return n.SendCell(cc.Hops[0], cell)
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
	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	cryptoState := n.circuitCryptoStates[circ.InCircID][exitIdx]

	// no payload for ACK, still need to compute digest
	emptyPayload, digest, err := EncryptRelayPayload(cryptoState, DirectionBackward, []byte{})
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
	return n.SendCell(circ.PrevHop, cell)
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

// GetRendezvousEntriesCount implements peer.TorHiddenServices
func (n *node) GetRendezvousEntriesCount() int {
	n.rendezvousEntryMu.Lock()
	defer n.rendezvousEntryMu.Unlock()
	return len(n.rendezvousEntries)
}

// SendIntroduceAck sends an Introduce ACK relay cell to the client indicating success or failure of the introduction
func (n *node) SendIntroduceAck(circ *Circuit, success bool) error {
	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	cryptoState := n.circuitCryptoStates[circ.InCircID][exitIdx]

	var flag byte
	if success {
		flag = IntroduceACKSuccess
	} else {
		flag = IntroduceACKFail
	}
	flagPayload, digest, err := EncryptRelayPayload(cryptoState, DirectionBackward, []byte{flag})
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
	return n.SendCell(circ.PrevHop, cell)
}

// HandleRelayIntroduceACK handles the Introduce ACK relay cell sent by the IP to the client
func (n *node) HandleRelayIntroduceACK(relay RelayCell) error {
	if relay.Data == nil || len(relay.Data) < 1 {
		return fmt.Errorf("invalid introduce ACK payload")
	}

	cryptoStates := n.circuitCryptoStates[relay.CircID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", relay.CircID)
	}
	flag := decryptRelayDataAtClient(cryptoStates, relay.Data, relay.Digest)[0]

	// Check if the introduction was successful
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
	cryptoStates := n.circuitCryptoStates[circID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", circID)
	}

	// Prepare the ServiceIntroduceMessage for the service
	selfPubKey := n.onionKey.Public
	stringSelfPubKey := x509.MarshalPKCS1PublicKey(selfPubKey)
	serviceIntroMsg := &ServiceIntroduceMessage{
		Cookie:      cookie,
		RPAddr:      rendezvousAddr,
		ClientDHPub: stringSelfPubKey,
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

	encrypted, digest, err := EncryptRelayCellThroughCircuit(cryptoStates, ipPayload)
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

	err = n.SendCell(n.clientCircuits[circID].Hops[0], cell)
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
	exitIdx := len(n.circuitCryptoStates[circ.InCircID]) - 1
	cryptoState := n.circuitCryptoStates[circ.InCircID][exitIdx]

	payload, digest, err := EncryptRelayPayload(cryptoState, DirectionBackward, encryptedBlob)
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
	return n.SendCell(circ.PrevHop, cell)
}

// HandleRelayIntroduce1 handles an introduce1 relay cell received at the introduction point
func (n *node) HandleRelayIntroduce1(relay RelayCell, circ *Circuit) error {
	cryptoStates := n.circuitCryptoStates[relay.CircID]
	if len(cryptoStates) == 0 {
		return fmt.Errorf("no crypto states for circuit %d", relay.CircID)
	}

	plaintext := decryptRelayDataAtClient(cryptoStates, relay.Data, relay.Digest)
	ipIntroMsg, err := DecodeIPIntroduceMessage(plaintext)
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

	err = n.SendIntroduce2Message(targetCirc, ipIntroMsg.EncryptedBlob)
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

// SendIntroduce1AndWaitForACK sends an introduce1 message and waits for the ACK response
func (n *node) SendIntroduce1AndWaitForACK(circID uint16, serviceID string,
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
