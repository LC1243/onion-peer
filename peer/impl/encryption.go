package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec	// Used for Tor digest as per spec
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Outline of steps required for circuit Creation:
// A map of shared secrets and encryption state is maintained per hop in the circuit.

// 1. Generation of an RSA Key Pair for agreeing to shared secrets during circuit creation.
// 2. Handshake between two nodes (Alice and OR1) to establish a shared secret
//		a. Origin node (Alice)
// 			i. Generates first half of DH keypair
//			ii. Encrypts it with the next hop's public onion key
//			iii. Sends the CREATE cell to the next hop
// 		b. Responder node (OR1):
// 			i. Decrypts the first half using its private onion key
//			ii. Generates second half of DH keypair
//			iii. Computes shared secret
//			iv. Responds with the second half + hash (CREATED)
//		c. Origin node verifies hash and computes shared secret

// Steps required for Circuit Extension:
// Extension from Alice to OR2 through OR1
// Mechanism remains similar to circuit creation
// 1. The origin node (Alice):
// 		i. Generates first half of DH keypair (Between Alice and OR2)
// 		ii. Encrypts it with OR2's public onion key
// 		iii. Prepares Un-encrypted RELAY EXTEND payload with address of OR2 and the encrypted first half
// 		iv. Encrypts the RELAY EXTEND payload using shared secret with OR1 s
// 		v. Sends RELAY EXTEND cell to OR1
// 2. The intermediate node (OR1):
// 		i. Decrypts the RELAY EXTEND payload using shared secret with Alice
//		ii. Forwards the encrypted first half to OR2 in a CREATE cell
// 3. The responder node (OR2):
// 		i. Decrypts the first half using its private onion key
//		ii. Generates second half of DH keypair
//		iii. Computes shared secret
//		iv. Responds to OR1 with the second half + hash (CREATED)
// 4. The intermediate node (OR1):
// 		i. Prepares an Un-encrypted RELAY EXTENDED payload with the second half + hash
//		ii. Encrypts the RELAY EXTENDED payload using shared secret with Alice
//		iii. Sends RELAY EXTENDED cell to Alice

// RSA key pair for agreeing to shared secrets during circuit creation
// Used in CREATE and EXTEND cells
type OnionKeyPair struct {
	Public  *rsa.PublicKey
	Private *rsa.PrivateKey
}

// DiffieHellmanHandshakePairs hold the halves of the DH keypair used during handshake
type DiffieHellmanHandshakePairs struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// CircuitCryptoState holds the symmetric keys and cipher state for one hop.
// Each circuit hop maintains forward and backward encryption/decryption state.
type CircuitCryptoState struct {
	// Forward direction
	ForwardKey         []byte
	ForwardCipher      cipher.Stream
	ForwardDigestState hash.Hash // Running SHA-1 digest state
	ForwardDigestKey   []byte    // Key used to initialize the digest

	// Backward direction (Exit -> OP)
	BackwardKey         []byte
	BackwardCipher      cipher.Stream
	BackwardDigestState hash.Hash // Running SHA-1 digest state
	BackwardDigestKey   []byte    // Key used to initialize the digest

	// Mutex to protect concurrent access to digest states
	mu sync.Mutex
}

// Direction indicates the direction of data flow in the circuit
type Direction int

const (
	DirectionForward  Direction = 0 // Origin to Exit
	DirectionBackward Direction = 1 // Exit to Origin
)

// GenerateOnionKeyPair generates a new RSA keypair for use as an onion key
func GenerateOnionKeyPair() (*OnionKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // Written using copilot
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &OnionKeyPair{
		Public:  &privateKey.PublicKey,
		Private: privateKey,
	}, nil
}

// Initiates the handshake from the initiator side
// Called by the origin node when sending a CREATE/EXTEND cell
func (n *node) BeginHandshake(
	publicOnionKey *rsa.PublicKey,
) (
	outgoingPayload []byte,
	state *DiffieHellmanHandshakePairs,
	err error,
) {
	var privateKey, publicKey [32]byte

	// Generate private key
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate the public key: First Half of DH keypair (g^x1)
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	state = &DiffieHellmanHandshakePairs{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	// Encrypt the public key with the public onion key
	// E(g^x1)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicOnionKey, publicKey[:], nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt handshake: %w", err)
	}

	return ciphertext, state, nil
}

// Completes the handshake from the responder side
// Called by the relay node after receiving a CREATE/EXTEND cell.
func (n *node) CompleteHandshakeAsResponder(
	privateOnionKey *OnionKeyPair,
	incomingPayload []byte,
) (
	responsePayload []byte,
	crypto *CircuitCryptoState,
	err error,
) {
	// Extract only the actual ciphertext
	const rsaCiphertextSize = 256
	if len(incomingPayload) < rsaCiphertextSize {
		n.log.Error().Msgf("Payload too short: %d bytes", len(incomingPayload))
		return nil, nil, fmt.Errorf("payload too short: %d bytes", len(incomingPayload))
	}

	// Decrypt the first half of DH keypair E(g^x1) using our private onion key
	remotePublicKeyBytes, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateOnionKey.Private,
		incomingPayload[:rsaCiphertextSize],
		nil,
	)
	if err != nil {
		n.log.Error().Err(err).Msg("Failed to decrypt handshake")
		return nil, nil, fmt.Errorf("failed to decrypt handshake: %w", err)
	}

	if len(remotePublicKeyBytes) != 32 {
		return nil, nil, fmt.Errorf("invalid peer public key length: %d", len(remotePublicKeyBytes))
	}

	var remotePublicKey [32]byte
	copy(remotePublicKey[:], remotePublicKeyBytes)

	// Second Half of DH keypair generation
	var privateKey, publicKey [32]byte

	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate the public key: Second Half of DH keypair (g^y)
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Compute shared secret K = DH(our_private, remote_public)
	sharedSecretBytes, err := curve25519.X25519(privateKey[:], remotePublicKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	var sharedSecret [32]byte
	copy(sharedSecret[:], sharedSecretBytes)

	// Generate AES ciphers and digests from shared secret
	crypto, err = generateCircuitKeys(sharedSecret[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Build response: publicKey + H(K || "handshake")
	responsePayload = make([]byte, 32+32) // 32 bytes public key + 32 bytes hash
	copy(responsePayload[0:32], publicKey[:])

	// Compute handshake confirmation hash
	h := sha256.New()
	h.Write(sharedSecret[:])
	h.Write([]byte("handshake"))
	copy(responsePayload[32:64], h.Sum(nil))

	return responsePayload, crypto, nil
}

// Completes the handshake from the initiator side.
// Called by the origin node after receiving a CREATED/EXTENDED cell.
func (n *node) FinishHandshakeAsInitiator(
	state *DiffieHellmanHandshakePairs,
	responsePayload []byte,
) (
	*CircuitCryptoState,
	error,
) {
	if len(responsePayload) < 64 {
		return nil, fmt.Errorf("invalid response payload length: %d", len(responsePayload))
	}

	// Extract remote public key and handshake hash
	var remotePublicKey [32]byte
	copy(remotePublicKey[:], responsePayload[0:32])
	receivedHash := responsePayload[32:64]

	// Compute shared secret K = DH(our_private, remote_public)
	sharedSecretBytes, err := curve25519.X25519(state.PrivateKey[:], remotePublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	var sharedSecret [32]byte
	copy(sharedSecret[:], sharedSecretBytes)

	// Verify handshake hash
	h := sha256.New()
	h.Write(sharedSecret[:])
	h.Write([]byte("handshake"))
	expectedHash := h.Sum(nil)

	if !bytes.Equal(expectedHash, receivedHash) {
		return nil, errors.New("handshake verification failed: hash mismatch")
	}

	// Derive keys from shared secret
	crypto, err := generateCircuitKeys(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	return crypto, nil
}

// AES Cipher and Digest Generation
// Generate forward and backward AES ciphers and digest keys from shared secret
func generateCircuitKeys(sharedSecret []byte) (*CircuitCryptoState, error) {
	// Use HKDF to derive key material
	// We need: forward key (32), backward key (32), forward digest (32), backward digest (32)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("tor-circuit-keys"))

	keyMaterial := make([]byte, 128) // 32*4 = 128 bytes
	if _, err := io.ReadFull(kdf, keyMaterial); err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	forwardKey := keyMaterial[0:32]
	backwardKey := keyMaterial[32:64]
	forwardDigestKey := keyMaterial[64:96]
	backwardDigestKey := keyMaterial[96:128]

	// Initialize AES-CTR cipher streams
	forwardCipher, err := newAESCTRStream(forwardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create forward cipher: %w", err)
	}

	backwardCipher, err := newAESCTRStream(backwardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create backward cipher: %w", err)
	}

	// Initialize running digest states with the digest keys
	forwardDigest := sha1.New() //nolint:gosec // SHA-1 used for Tor protocol compatibility
	forwardDigest.Write(forwardDigestKey)

	backwardDigest := sha1.New() //nolint:gosec // SHA-1 used for Tor protocol compatibility
	backwardDigest.Write(backwardDigestKey)

	return &CircuitCryptoState{
		ForwardKey:          forwardKey,
		ForwardCipher:       forwardCipher,
		ForwardDigestState:  forwardDigest,
		ForwardDigestKey:    forwardDigestKey,
		BackwardKey:         backwardKey,
		BackwardCipher:      backwardCipher,
		BackwardDigestState: backwardDigest,
		BackwardDigestKey:   backwardDigestKey,
	}, nil
}

// newAESCTRStream creates a new AES-CTR cipher stream
func newAESCTRStream(key []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	return cipher.NewCTR(block, iv), nil
}

// Encrypts a relay cell payload
// Called when sending data through a circuit
// Incrementally update the running digest with cell contents
func EncryptRelayPayload(
	crypto *CircuitCryptoState,
	direction Direction,
	payload []byte,
) (
	ciphertext []byte,
	digest [6]byte,
	err error,
) {
	if crypto == nil {
		return nil, digest, errors.New("crypto state is nil")
	}

	// Select cipher and digest state based on direction
	var stream cipher.Stream
	var digestState hash.Hash

	if direction == DirectionForward {
		stream = crypto.ForwardCipher
		digestState = crypto.ForwardDigestState
	} else {
		stream = crypto.BackwardCipher
		digestState = crypto.BackwardDigestState
	}

	// Lock to protect concurrent access to digest state
	crypto.mu.Lock()
	defer crypto.mu.Unlock()

	// Incrementally add payload to the running digest
	// ToR spec requires SHA-1 digest
	digestState.Write(payload)

	// Get current digest value (first 6 bytes of SHA-1 hash)
	currentHash := digestState.Sum(nil)
	copy(digest[:], currentHash[:6])

	// Encrypt the payload using the stateful cipher stream
	ciphertext = make([]byte, len(payload))
	stream.XORKeyStream(ciphertext, payload)

	return ciphertext, digest, nil
}

// Decrypts a relay cell payload
// Called when receiving data through a circuit
// Checks digest against running digest state to determine if cell is for us
func DecryptRelayPayload(
	crypto *CircuitCryptoState,
	direction Direction,
	ciphertext []byte,
	expectedDigest [6]byte,
) (
	plaintext []byte,
	err error,
) {
	if crypto == nil {
		return nil, errors.New("crypto state is nil")
	}

	// Select cipher and digest state based on direction
	var stream cipher.Stream
	var digestState hash.Hash

	if direction == DirectionForward {
		stream = crypto.ForwardCipher
		digestState = crypto.ForwardDigestState
	} else {
		stream = crypto.BackwardCipher
		digestState = crypto.BackwardDigestState
	}

	// Decrypt the payload using the stateful cipher stream
	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	// Lock to protect concurrent access to digest state
	crypto.mu.Lock()
	defer crypto.mu.Unlock()

	// Check if this cell is for us by verifying the digest
	// We maintain a running digest of received data
	// First, compute what the digest would be if we add this plaintext
	digestState.Write(plaintext)
	currentHash := digestState.Sum(nil)
	var actualDigest [6]byte
	copy(actualDigest[:], currentHash[:6])

	if !bytes.Equal(expectedDigest[:], actualDigest[:]) {
		// Fixed using copilot
		// Digest mismatch: Need to restore digest state since this cell isn't for us
		// Re-initialize and replay all cells except this one
		// For now, we return an error and let DecryptRelayCellAtHop handle it
		return nil, errors.New("digest mismatch")
	}

	return plaintext, nil
}

// Applies multiple layers of encryption to a relay cell payload
// Called by the origin node when sending a relay cell through a circuit
func EncryptRelayCellThroughCircuit(
	cryptoStates []*CircuitCryptoState,
	payload []byte,
) (
	ciphertext []byte,
	digest [6]byte,
	err error,
) {
	if len(cryptoStates) == 0 {
		return nil, digest, errors.New("no crypto states provided")
	}

	// Start with the original payload
	current := payload

	// Apply encryption layers in reverse order from inner to outer
	for i := len(cryptoStates) - 1; i >= 0; i-- {
		var layerDigest [6]byte
		current, layerDigest, err = EncryptRelayPayload(cryptoStates[i], DirectionForward, current)
		if err != nil {
			return nil, digest, fmt.Errorf("failed to encrypt layer %d: %w", i, err)
		}

		// The digest from the innermost layer is what we use
		if i == len(cryptoStates)-1 {
			digest = layerDigest
		}
	}

	return current, digest, nil
}

// DecryptRelayCellAtHop decrypts a relay cell and checks if it's intended for this hop.
// Returns the decrypted data and whether the digest matched (indicating this hop is the destination).
// If digest doesn't match, the cell should be forwarded to the next hop.
// If expectedDigest is all zeros, digest verification is skipped (for backward direction intermediate hops).
func DecryptRelayCellAtHop(
	crypto *CircuitCryptoState,
	direction Direction,
	ciphertext []byte,
	expectedDigest [6]byte,
) (
	plaintext []byte,
	isForUs bool,
) {
	if crypto == nil {
		return ciphertext, false
	}

	// Check if digest verification should be skipped (all zeros = skip)
	// Debugged using copilot
	var zeroDigest [6]byte
	skipDigestCheck := bytes.Equal(expectedDigest[:], zeroDigest[:])

	// Select cipher and digest state based on direction
	var stream cipher.Stream
	var digestState hash.Hash

	if direction == DirectionForward {
		stream = crypto.ForwardCipher
		digestState = crypto.ForwardDigestState
	} else {
		stream = crypto.BackwardCipher
		digestState = crypto.BackwardDigestState
	}

	// Decrypt the payload using the stateful cipher stream
	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	if skipDigestCheck {
		// No digest verification needed
		return plaintext, false
	}

	// Lock to protect concurrent access to digest state
	crypto.mu.Lock()
	defer crypto.mu.Unlock()

	// Verify digest: Check if this cell is for us
	// We maintain a running digest of received data
	// Update the running digest with this plaintext
	digestState.Write(plaintext)
	currentHash := digestState.Sum(nil)
	var actualDigest [6]byte
	copy(actualDigest[:], currentHash[:6])

	if !bytes.Equal(expectedDigest[:], actualDigest[:]) {
		// Digest mismatch: this cell is not for us
		return plaintext, false
	}

	// Digest matched: this cell is for us
	return plaintext, true
}
