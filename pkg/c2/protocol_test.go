package c2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// validKey returns a deterministic 32-byte AES-256 key for testing.
func validKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// wrongKey returns a valid-length key that differs from validKey.
func wrongKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i ^ 0xff)
	}
	return key
}

// generateP256ServerKey creates a fresh ECDH P-256 key pair and returns
// the private key and the uncompressed public key bytes.
func generateP256ServerKey(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	return priv, priv.PublicKey().Bytes()
}

// ---------------------------------------------------------------
// 1. aesGCMEncrypt / aesGCMDecrypt (unexported)
// ---------------------------------------------------------------
func TestAesGCMRoundTrip(t *testing.T) {
	t.Run("basic round-trip", func(t *testing.T) {
		plaintext := []byte("hello, aquifer")
		key := validKey()

		ct, err := aesGCMEncrypt(plaintext, key)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		got, err := aesGCMDecrypt(ct, key)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
		}
	})

	t.Run("wrong key fails decryption", func(t *testing.T) {
		plaintext := []byte("secret data")
		ct, err := aesGCMEncrypt(plaintext, validKey())
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		_, err = aesGCMDecrypt(ct, wrongKey())
		if err == nil {
			t.Fatal("expected decryption to fail with wrong key")
		}
	})

	t.Run("tampered ciphertext fails", func(t *testing.T) {
		plaintext := []byte("integrity check")
		ct, err := aesGCMEncrypt(plaintext, validKey())
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		// Flip a byte in the ciphertext body (past the 12-byte nonce).
		tampered := make([]byte, len(ct))
		copy(tampered, ct)
		tampered[len(tampered)-1] ^= 0x01

		_, err = aesGCMDecrypt(tampered, validKey())
		if err == nil {
			t.Fatal("expected decryption to fail on tampered ciphertext")
		}
	})

	t.Run("short ciphertext fails", func(t *testing.T) {
		// Less than 12 bytes (GCM nonce size).
		_, err := aesGCMDecrypt([]byte{1, 2, 3}, validKey())
		if err == nil {
			t.Fatal("expected error for short ciphertext")
		}
	})

	t.Run("invalid key length fails encrypt", func(t *testing.T) {
		_, err := aesGCMEncrypt([]byte("data"), []byte("short"))
		if err == nil {
			t.Fatal("expected error for invalid key length on encrypt")
		}
	})

	t.Run("invalid key length fails decrypt", func(t *testing.T) {
		_, err := aesGCMDecrypt([]byte("some ciphertext data here!"), []byte("short"))
		if err == nil {
			t.Fatal("expected error for invalid key length on decrypt")
		}
	})
}

// ---------------------------------------------------------------
// 2. DecryptAESGCM (exported wrapper)
// ---------------------------------------------------------------
func TestDecryptAESGCM(t *testing.T) {
	t.Run("round-trip via exported API", func(t *testing.T) {
		plaintext := []byte("exported round-trip")
		key := validKey()

		ct, err := aesGCMEncrypt(plaintext, key)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		got, err := DecryptAESGCM(ct, key)
		if err != nil {
			t.Fatalf("DecryptAESGCM: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("mismatch: got %q, want %q", got, plaintext)
		}
	})

	t.Run("wrong key fails", func(t *testing.T) {
		ct, err := aesGCMEncrypt([]byte("payload"), validKey())
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		_, err = DecryptAESGCM(ct, wrongKey())
		if err == nil {
			t.Fatal("expected failure with wrong key")
		}
	})

	t.Run("tampered ciphertext fails", func(t *testing.T) {
		ct, err := aesGCMEncrypt([]byte("tamper test"), validKey())
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		tampered := make([]byte, len(ct))
		copy(tampered, ct)
		tampered[14] ^= 0xff

		_, err = DecryptAESGCM(tampered, validKey())
		if err == nil {
			t.Fatal("expected failure on tampered ciphertext")
		}
	})

	t.Run("short ciphertext fails", func(t *testing.T) {
		_, err := DecryptAESGCM([]byte{0x00}, validKey())
		if err == nil {
			t.Fatal("expected error for short ciphertext")
		}
	})

	t.Run("invalid key length fails", func(t *testing.T) {
		_, err := DecryptAESGCM([]byte("some data over twelve bytes long"), []byte("16-byte-key!!!!"))
		if err == nil {
			t.Fatal("expected error for invalid key length")
		}
	})
}

// ---------------------------------------------------------------
// 3. EncodeBeacon / DecodeResponse round-trip
// ---------------------------------------------------------------
func TestEncodeBeaconDecodeResponse(t *testing.T) {
	t.Run("EncodeBeacon round-trip", func(t *testing.T) {
		key := validKey()
		beacon := &config.Beacon{
			ImplantID: "test-implant-001",
			Hostname:  "victim-host",
			Username:  "root",
			UID:       0,
			PID:       1234,
			OS:        "linux",
			Arch:      "amd64",
			InNS:      true,
		}

		ct, err := EncodeBeacon(beacon, key)
		if err != nil {
			t.Fatalf("EncodeBeacon: %v", err)
		}

		// Manually decrypt and unmarshal to verify the round-trip.
		plaintext, err := aesGCMDecrypt(ct, key)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}

		var decoded config.Beacon
		if err := json.Unmarshal(plaintext, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if decoded.ImplantID != beacon.ImplantID {
			t.Errorf("ImplantID: got %q, want %q", decoded.ImplantID, beacon.ImplantID)
		}
		if decoded.Hostname != beacon.Hostname {
			t.Errorf("Hostname: got %q, want %q", decoded.Hostname, beacon.Hostname)
		}
		if decoded.InNS != beacon.InNS {
			t.Errorf("InNS: got %v, want %v", decoded.InNS, beacon.InNS)
		}
	})

	t.Run("EncodeBeacon with invalid key fails", func(t *testing.T) {
		beacon := &config.Beacon{ImplantID: "x"}
		_, err := EncodeBeacon(beacon, []byte("bad"))
		if err == nil {
			t.Fatal("expected error for invalid key")
		}
	})

	t.Run("DecodeResponse round-trip", func(t *testing.T) {
		key := validKey()
		resp := &config.BeaconResponse{
			Tasks: []config.Task{
				{ID: "task-1", Type: "exec", Args: map[string]string{"cmd": "id"}},
				{ID: "task-2", Type: "upload", Args: map[string]string{"path": "/tmp/payload"}},
			},
			Sleep:    60,
			Jitter:   0.3,
			Shutdown: false,
		}

		plaintext, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		ct, err := aesGCMEncrypt(plaintext, key)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		decoded, err := DecodeResponse(ct, key)
		if err != nil {
			t.Fatalf("DecodeResponse: %v", err)
		}

		if len(decoded.Tasks) != 2 {
			t.Fatalf("tasks count: got %d, want 2", len(decoded.Tasks))
		}
		if decoded.Tasks[0].ID != "task-1" {
			t.Errorf("task 0 ID: got %q, want %q", decoded.Tasks[0].ID, "task-1")
		}
		if decoded.Tasks[1].Type != "upload" {
			t.Errorf("task 1 Type: got %q, want %q", decoded.Tasks[1].Type, "upload")
		}
		if decoded.Sleep != 60 {
			t.Errorf("Sleep: got %d, want 60", decoded.Sleep)
		}
		if decoded.Jitter != 0.3 {
			t.Errorf("Jitter: got %f, want 0.3", decoded.Jitter)
		}
	})

	t.Run("DecodeResponse with wrong key fails", func(t *testing.T) {
		key := validKey()
		resp := &config.BeaconResponse{Sleep: 10}
		plaintext, _ := json.Marshal(resp)
		ct, _ := aesGCMEncrypt(plaintext, key)

		_, err := DecodeResponse(ct, wrongKey())
		if err == nil {
			t.Fatal("expected error decoding with wrong key")
		}
	})

	t.Run("DecodeResponse with invalid JSON fails", func(t *testing.T) {
		key := validKey()
		ct, _ := aesGCMEncrypt([]byte("{invalid json!!!"), key)

		_, err := DecodeResponse(ct, key)
		if err == nil {
			t.Fatal("expected error for invalid JSON payload")
		}
	})
}

// ---------------------------------------------------------------
// 4. PerformKeyExchange
// ---------------------------------------------------------------
func TestPerformKeyExchange(t *testing.T) {
	t.Run("returns 32-byte session key", func(t *testing.T) {
		_, serverPub := generateP256ServerKey(t)

		sessionKey, _, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("PerformKeyExchange: %v", err)
		}
		if len(sessionKey) != 32 {
			t.Fatalf("session key length: got %d, want 32", len(sessionKey))
		}
	})

	t.Run("returns non-nil client public key", func(t *testing.T) {
		_, serverPub := generateP256ServerKey(t)

		_, clientPub, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("PerformKeyExchange: %v", err)
		}
		if clientPub == nil {
			t.Fatal("client public key is nil")
		}
		if len(clientPub) == 0 {
			t.Fatal("client public key is empty")
		}
	})

	t.Run("client public key is a valid P-256 point", func(t *testing.T) {
		_, serverPub := generateP256ServerKey(t)

		_, clientPubBytes, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("PerformKeyExchange: %v", err)
		}

		// Parsing must succeed for a valid P-256 public key.
		_, err = ecdh.P256().NewPublicKey(clientPubBytes)
		if err != nil {
			t.Fatalf("client pub key is not a valid P-256 point: %v", err)
		}
	})

	t.Run("session key is usable for AES-GCM", func(t *testing.T) {
		_, serverPub := generateP256ServerKey(t)

		sessionKey, _, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("PerformKeyExchange: %v", err)
		}

		// The derived session key must work as an AES-256 key.
		plaintext := []byte("key exchange validation")
		ct, err := aesGCMEncrypt(plaintext, sessionKey)
		if err != nil {
			t.Fatalf("encrypt with session key: %v", err)
		}
		got, err := aesGCMDecrypt(ct, sessionKey)
		if err != nil {
			t.Fatalf("decrypt with session key: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("round-trip with derived session key failed")
		}
	})

	t.Run("shared secret is zeroed after derivation", func(t *testing.T) {
		// We cannot directly observe the zeroing of the local `shared` variable
		// from outside the function. Instead, we verify that the function
		// successfully returns (the zeroing doesn't corrupt the session key)
		// and that the session key itself is non-zero (i.e., the hash was
		// computed before zeroing).
		_, serverPub := generateP256ServerKey(t)

		sessionKey, _, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("PerformKeyExchange: %v", err)
		}

		allZero := true
		for _, b := range sessionKey {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatal("session key is all zeros; shared secret may have been zeroed prematurely")
		}
	})

	t.Run("two exchanges produce different session keys", func(t *testing.T) {
		_, serverPub := generateP256ServerKey(t)

		key1, _, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("first exchange: %v", err)
		}

		key2, _, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("second exchange: %v", err)
		}

		if bytes.Equal(key1, key2) {
			t.Fatal("two independent key exchanges produced identical session keys")
		}
	})

	t.Run("two exchanges produce different client public keys", func(t *testing.T) {
		_, serverPub := generateP256ServerKey(t)

		_, pub1, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("first exchange: %v", err)
		}

		_, pub2, err := PerformKeyExchange(serverPub)
		if err != nil {
			t.Fatalf("second exchange: %v", err)
		}

		if bytes.Equal(pub1, pub2) {
			t.Fatal("two exchanges produced identical client public keys")
		}
	})

	t.Run("invalid server public key fails", func(t *testing.T) {
		_, _, err := PerformKeyExchange([]byte{0x04, 0x01, 0x02})
		if err == nil {
			t.Fatal("expected error for invalid server public key")
		}
	})

	t.Run("nil server public key fails", func(t *testing.T) {
		_, _, err := PerformKeyExchange(nil)
		if err == nil {
			t.Fatal("expected error for nil server public key")
		}
	})
}

// ---------------------------------------------------------------
// 5. Edge cases
// ---------------------------------------------------------------
func TestEdgeCases(t *testing.T) {
	t.Run("nil plaintext encrypts and decrypts", func(t *testing.T) {
		key := validKey()
		ct, err := aesGCMEncrypt(nil, key)
		if err != nil {
			t.Fatalf("encrypt nil: %v", err)
		}

		got, err := aesGCMDecrypt(ct, key)
		if err != nil {
			t.Fatalf("decrypt nil-origin: %v", err)
		}

		// AES-GCM with nil plaintext produces an empty (or nil) decrypted slice.
		if len(got) != 0 {
			t.Fatalf("expected empty plaintext, got %d bytes", len(got))
		}
	})

	t.Run("empty plaintext encrypts and decrypts", func(t *testing.T) {
		key := validKey()
		ct, err := aesGCMEncrypt([]byte{}, key)
		if err != nil {
			t.Fatalf("encrypt empty: %v", err)
		}

		got, err := aesGCMDecrypt(ct, key)
		if err != nil {
			t.Fatalf("decrypt empty-origin: %v", err)
		}

		if len(got) != 0 {
			t.Fatalf("expected empty plaintext, got %d bytes", len(got))
		}
	})

	t.Run("large plaintext 1MB round-trip", func(t *testing.T) {
		key := validKey()
		plaintext := make([]byte, 1<<20) // 1 MiB
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("generate random plaintext: %v", err)
		}

		ct, err := aesGCMEncrypt(plaintext, key)
		if err != nil {
			t.Fatalf("encrypt 1MB: %v", err)
		}

		got, err := aesGCMDecrypt(ct, key)
		if err != nil {
			t.Fatalf("decrypt 1MB: %v", err)
		}

		if !bytes.Equal(got, plaintext) {
			t.Fatal("1MB round-trip mismatch")
		}
	})

	t.Run("nil key fails encrypt", func(t *testing.T) {
		_, err := aesGCMEncrypt([]byte("data"), nil)
		if err == nil {
			t.Fatal("expected error for nil key on encrypt")
		}
	})

	t.Run("nil key fails decrypt", func(t *testing.T) {
		// Need valid-looking ciphertext (>12 bytes) to reach key validation.
		_, err := aesGCMDecrypt(make([]byte, 32), nil)
		if err == nil {
			t.Fatal("expected error for nil key on decrypt")
		}
	})

	t.Run("ciphertext is at least nonce + tag larger than plaintext", func(t *testing.T) {
		key := validKey()
		plaintext := []byte("size check")
		ct, err := aesGCMEncrypt(plaintext, key)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		// GCM nonce = 12 bytes, tag = 16 bytes.
		minOverhead := 12 + 16
		if len(ct) < len(plaintext)+minOverhead {
			t.Fatalf("ciphertext too short: got %d bytes for %d byte plaintext (expected >= %d)",
				len(ct), len(plaintext), len(plaintext)+minOverhead)
		}
	})

	t.Run("each encryption produces different ciphertext", func(t *testing.T) {
		key := validKey()
		plaintext := []byte("nonce uniqueness")

		ct1, err := aesGCMEncrypt(plaintext, key)
		if err != nil {
			t.Fatalf("first encrypt: %v", err)
		}

		ct2, err := aesGCMEncrypt(plaintext, key)
		if err != nil {
			t.Fatalf("second encrypt: %v", err)
		}

		if bytes.Equal(ct1, ct2) {
			t.Fatal("two encryptions of same plaintext produced identical ciphertext (nonce reuse)")
		}
	})
}
