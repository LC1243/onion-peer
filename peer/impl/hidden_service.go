package impl

import (
	"crypto/rsa"
	"fmt"
	"sync"
	"time"
)

type HiddenService struct {
	ID          string // hex(SHA-256(pubkey))
	PublicKey   *rsa.PublicKey
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
	BobAddr    string // where Bob's OP lives (Bob’s Tor node)
	BobCircID  uint16 // circuit ID towards Bob
}

// EnsureServiceKey generates a new keypair if none exists yet
func (n *node) EnsureServiceKey() error {
	if n.serviceKey != nil {
		return nil
	}
	key, err := GenerateOnionKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate service keypair: %w", err)
	}
	n.serviceKey = key
	return nil
}

// GetServicePublicKey returns the public key of the hidden service
func (n *node) GetServicePublicKey() *rsa.PublicKey {
	if n.serviceKey == nil {
		return nil
	}
	return n.serviceKey.Public
}

type ServiceDescriptor struct {
	ServiceID     string   // hash(pubkey)
	ServicePubKey []byte   // serialized RSA pubkey
	IntroPoints   []string // list of OR addresses (not circuits)
	ExpiresAt     time.Time
	Signature     []byte // over (ServiceID || ExpiresAt || IntroPoints || ServicePubKey)
}

// a very simple in-memory registry (can be on directory nodes)
var (
	hsRegistryMu sync.RWMutex
	hsRegistry   = make(map[string]*ServiceDescriptor)
)
