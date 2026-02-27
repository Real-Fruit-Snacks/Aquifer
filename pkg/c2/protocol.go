package c2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// EncodeBeacon serializes a Beacon to JSON and encrypts it with AES-GCM
// using the provided session key. The returned ciphertext is:
//
//	nonce (12 bytes) || ciphertext || tag (16 bytes)
func EncodeBeacon(beacon *config.Beacon, sessionKey []byte) ([]byte, error) {
	plaintext, err := json.Marshal(beacon)
	if err != nil {
		return nil, fmt.Errorf("marshal beacon: %w", err)
	}
	return aesGCMEncrypt(plaintext, sessionKey)
}

// DecodeResponse decrypts an AES-GCM encrypted payload and deserializes
// the resulting JSON into a BeaconResponse.
func DecodeResponse(data []byte, sessionKey []byte) (*config.BeaconResponse, error) {
	plaintext, err := aesGCMDecrypt(data, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}
	var resp config.BeaconResponse
	if err := json.Unmarshal(plaintext, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &resp, nil
}

// PerformKeyExchange executes an ECDH P-256 key exchange with the server.
// It generates an ephemeral client key pair, computes the shared secret
// from the server's public key, and returns the 32-byte session key along
// with the client's compressed public key bytes for transmission.
func PerformKeyExchange(serverPubKey []byte) (sessionKey []byte, clientPubKeyBytes []byte, err error) {
	curve := ecdh.P256()

	// Parse server's public key.
	serverKey, err := curve.NewPublicKey(serverPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server public key: %w", err)
	}

	// Generate ephemeral client key pair.
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client key: %w", err)
	}

	// Derive shared secret.
	shared, err := clientPriv.ECDH(serverKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH exchange: %w", err)
	}

	// Derive session key via SHA-256 with domain separation to prevent
	// cross-protocol attacks from reusing the same shared secret.
	// Both public keys are included in the transcript to bind the session
	// key to the specific key exchange, preventing key reuse attacks.
	clientPub := clientPriv.PublicKey()
	h := sha256.New()
	h.Write([]byte("aquifer-c2-session-v1"))
	h.Write(clientPub.Bytes()) // our public key
	h.Write(serverPubKey)      // peer's public key
	h.Write(shared)
	for i := range shared {
		shared[i] = 0
	}
	digest := h.Sum(nil)
	sessionKey = make([]byte, 32)
	copy(sessionKey, digest)
	for i := range digest {
		digest[i] = 0
	}
	return sessionKey, clientPub.Bytes(), nil
}

// aesGCMEncrypt encrypts plaintext with AES-256-GCM.
// Output format: nonce (12 bytes) || ciphertext+tag.
func aesGCMEncrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption: invalid key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag after the nonce.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts an AES-256-GCM payload (exported for use by other packages).
// Expected input format: nonce (12 bytes) || ciphertext+tag.
func DecryptAESGCM(data, key []byte) ([]byte, error) {
	return aesGCMDecrypt(data, key)
}

// aesGCMDecrypt decrypts an AES-256-GCM payload.
// Expected input format: nonce (12 bytes) || ciphertext+tag.
func aesGCMDecrypt(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("decryption failed")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm decrypt: %w", err)
	}

	return plaintext, nil
}
