package impl

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sync"
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

var (
	hsRegistryMu sync.RWMutex
	hsRegistry   = make(map[string]*ServiceDescriptor)
)

// CreateHiddenService implements peer.TorHiddenServices
func (n *node) CreateHiddenService() (string, error) {
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
func (n *node) EstablishIntroPoint(serviceID string, circID uint16) error {
	hs, ok := n.hiddenServices[serviceID]
	if !ok {
		return fmt.Errorf("unknown serviceID: %s", serviceID)
	}

	pubBytes := x509.MarshalPKCS1PublicKey(hs.KeyPair.Public)
	payload := pubBytes

	cryptoStates := n.circuitCryptoStates[circID]
	if len(cryptoStates) == 0 {
		n.log.Info().Msgf("client has circuits: %s", n.GetCircuitIDs())
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

	// Send it via guard of this circuit
	cc, ok := n.clientCircuits[circID]
	if !ok {
		return fmt.Errorf("not a client circuit %d", circID)
	}

	//TODO: Simplified, Bob can choose the OR that acts as a introduction point
	hs.IntroPoints = append(hs.IntroPoints, IntroPoint{
		RouterAddr: cc.Hops[2], // exit hop
		CircID:     circID,
	})

	return n.SendCell(cc.Hops[0], cell)
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
	return nil
}

// BuildServiceDescriptor implements peer.TorHiddenServices
func (n *node) BuildServiceDescriptor(serviceID string, introORs []string, lifetime time.Duration) error {
	hs, ok := n.hiddenServices[serviceID]
	if !ok {
		return fmt.Errorf("unknown serviceID %s", serviceID)
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
		return fmt.Errorf("sign service descriptor: %w", err)
	}
	desc.Signature = sig

	PublishServiceDescriptor(desc)
	return nil
}

// PublishServiceDescriptor registers a service descriptor for the Lookup service
func PublishServiceDescriptor(desc *ServiceDescriptor) {
	hsRegistryMu.Lock()
	hsRegistry[desc.ServiceID] = desc
	hsRegistryMu.Unlock()
}

// LookupServiceDescriptor returns a service descriptor if it exists and hasn't expired yet
func LookupServiceDescriptor(serviceID string) (*ServiceDescriptor, bool) {
	hsRegistryMu.RLock()
	defer hsRegistryMu.RUnlock()
	desc, ok := hsRegistry[serviceID]
	if !ok {
		return nil, false
	}
	if time.Now().After(desc.ExpiresAt) {
		return nil, false
	}
	return desc, true
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

// LookupDescriptor implements peer.TorHiddenServices
func (n *node) LookupDescriptor(serviceID string) (bool, []string) {
	desc, ok := LookupServiceDescriptor(serviceID)
	if !ok {
		return false, nil
	}
	return true, append([]string(nil), desc.IntroPoints...)
}

// GetIntroPointStateCount implements peer.TorHiddenServices
func (n *node) GetIntroPointStateCount(serviceID string) int {
	n.introPointsMu.Lock()
	defer n.introPointsMu.Unlock()
	list := n.introPoints[serviceID]
	return len(list)
}
