package opsec

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// allZero returns true if every byte in b is 0x00.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// --------------------------------------------------------------------------
// NewEncryptedBlob
// --------------------------------------------------------------------------

func TestNewEncryptedBlob(t *testing.T) {
	t.Run("empty input returns empty blob", func(t *testing.T) {
		blob, err := NewEncryptedBlob(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if blob.data != nil || blob.key != nil {
			t.Fatal("expected nil data and key for empty input")
		}
	})

	t.Run("empty slice returns empty blob", func(t *testing.T) {
		blob, err := NewEncryptedBlob([]byte{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if blob.data != nil || blob.key != nil {
			t.Fatal("expected nil data and key for empty slice")
		}
	})

	t.Run("normal input produces non-nil data and key", func(t *testing.T) {
		plain := []byte("hello world")
		blob, err := NewEncryptedBlob(plain)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if blob.data == nil || blob.key == nil {
			t.Fatal("expected non-nil data and key")
		}
		if len(blob.data) != 11 || len(blob.key) != 11 {
			t.Fatalf("expected len 11, got data=%d key=%d", len(blob.data), len(blob.key))
		}
	})

	t.Run("plaintext buffer is shredded after creation", func(t *testing.T) {
		plain := make([]byte, 32)
		copy(plain, []byte("sensitive material here!!12345678"))
		_, err := NewEncryptedBlob(plain)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allZero(plain) {
			t.Fatal("plaintext buffer was not shredded after NewEncryptedBlob")
		}
	})
}

// --------------------------------------------------------------------------
// Decrypt
// --------------------------------------------------------------------------

func TestDecrypt(t *testing.T) {
	t.Run("round-trip encrypt then decrypt", func(t *testing.T) {
		original := []byte("round trip test data 1234")
		plainCopy := make([]byte, len(original))
		copy(plainCopy, original)

		blob, err := NewEncryptedBlob(plainCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		got := blob.Decrypt()
		defer ShredMemory(got)
		if !bytes.Equal(got, original) {
			t.Fatalf("decrypt mismatch: got %q, want %q", got, original)
		}
	})

	t.Run("empty blob returns nil", func(t *testing.T) {
		blob, err := NewEncryptedBlob(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := blob.Decrypt()
		if got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("single byte round-trip", func(t *testing.T) {
		plain := []byte{0x42}
		plainCopy := make([]byte, 1)
		copy(plainCopy, plain)

		blob, err := NewEncryptedBlob(plainCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		got := blob.Decrypt()
		defer ShredMemory(got)
		if !bytes.Equal(got, plain) {
			t.Fatalf("got %x, want %x", got, plain)
		}
	})

	t.Run("binary data round-trip", func(t *testing.T) {
		original := make([]byte, 256)
		for i := range original {
			original[i] = byte(i)
		}
		plainCopy := make([]byte, len(original))
		copy(plainCopy, original)

		blob, err := NewEncryptedBlob(plainCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		got := blob.Decrypt()
		defer ShredMemory(got)
		if !bytes.Equal(got, original) {
			t.Fatal("binary round-trip failed")
		}
	})
}

// --------------------------------------------------------------------------
// Update
// --------------------------------------------------------------------------

func TestUpdate(t *testing.T) {
	t.Run("update with new data", func(t *testing.T) {
		plain1 := []byte("first value")
		p1Copy := make([]byte, len(plain1))
		copy(p1Copy, plain1)

		blob, err := NewEncryptedBlob(p1Copy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		newPlain := []byte("second value!!!")
		original := make([]byte, len(newPlain))
		copy(original, newPlain)

		if err := blob.Update(newPlain); err != nil {
			t.Fatalf("Update error: %v", err)
		}

		got := blob.Decrypt()
		defer ShredMemory(got)
		if !bytes.Equal(got, original) {
			t.Fatalf("after update: got %q, want %q", got, original)
		}
	})

	t.Run("update with empty data clears blob", func(t *testing.T) {
		plain := []byte("some data")
		pCopy := make([]byte, len(plain))
		copy(pCopy, plain)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := blob.Update([]byte{}); err != nil {
			t.Fatalf("Update error: %v", err)
		}

		if blob.data != nil || blob.key != nil {
			t.Fatal("expected nil data and key after empty update")
		}
		got := blob.Decrypt()
		if got != nil {
			t.Fatalf("expected nil decrypt after empty update, got %v", got)
		}
	})

	t.Run("old material is shredded and caller buffer is shredded", func(t *testing.T) {
		plain := []byte("original secret")
		pCopy := make([]byte, len(plain))
		copy(pCopy, plain)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Capture references to old internal buffers.
		oldData := blob.data
		oldKey := blob.key

		newPlain := []byte("replacement secret")
		if err := blob.Update(newPlain); err != nil {
			t.Fatalf("Update error: %v", err)
		}

		// Old internal buffers should be zeroed.
		if !allZero(oldData) {
			t.Fatal("old data was not shredded")
		}
		if !allZero(oldKey) {
			t.Fatal("old key was not shredded")
		}
		// Caller's input buffer should be zeroed.
		if !allZero(newPlain) {
			t.Fatal("caller's newPlaintext was not shredded")
		}
	})
}

// --------------------------------------------------------------------------
// Destroy
// --------------------------------------------------------------------------

func TestDestroy(t *testing.T) {
	t.Run("data and key become nil", func(t *testing.T) {
		plain := []byte("destroy me")
		pCopy := make([]byte, len(plain))
		copy(pCopy, plain)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		oldData := blob.data
		oldKey := blob.key

		blob.Destroy()

		if blob.data != nil || blob.key != nil {
			t.Fatal("expected nil data and key after Destroy")
		}
		// The old backing slices should be zeroed.
		if !allZero(oldData) {
			t.Fatal("old data backing not shredded")
		}
		if !allZero(oldKey) {
			t.Fatal("old key backing not shredded")
		}
	})

	t.Run("decrypt after destroy returns nil", func(t *testing.T) {
		plain := []byte("soon gone")
		pCopy := make([]byte, len(plain))
		copy(pCopy, plain)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		blob.Destroy()
		got := blob.Decrypt()
		if got != nil {
			t.Fatalf("expected nil after destroy, got %v", got)
		}
	})
}

// --------------------------------------------------------------------------
// Rekey
// --------------------------------------------------------------------------

func TestRekey(t *testing.T) {
	t.Run("decrypt before and after rekey gives same plaintext", func(t *testing.T) {
		original := []byte("rekey test data!!")
		pCopy := make([]byte, len(original))
		copy(pCopy, original)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		before := blob.Decrypt()
		defer ShredMemory(before)
		if !bytes.Equal(before, original) {
			t.Fatalf("before rekey: got %q, want %q", before, original)
		}

		// Save old key/data for comparison.
		oldData := make([]byte, len(blob.data))
		copy(oldData, blob.data)
		oldKey := make([]byte, len(blob.key))
		copy(oldKey, blob.key)

		if err := blob.Rekey(); err != nil {
			t.Fatalf("Rekey error: %v", err)
		}

		after := blob.Decrypt()
		defer ShredMemory(after)
		if !bytes.Equal(after, original) {
			t.Fatalf("after rekey: got %q, want %q", after, original)
		}

		// Internal data and key should have changed (with overwhelming probability).
		if bytes.Equal(blob.data, oldData) && bytes.Equal(blob.key, oldKey) {
			t.Fatal("rekey did not change internal data/key")
		}
	})

	t.Run("empty blob rekey is no-op", func(t *testing.T) {
		blob, err := NewEncryptedBlob(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := blob.Rekey(); err != nil {
			t.Fatalf("Rekey on empty blob should not error: %v", err)
		}
		got := blob.Decrypt()
		if got != nil {
			t.Fatalf("expected nil after rekey on empty blob, got %v", got)
		}
	})

	t.Run("multiple rekeys preserve plaintext", func(t *testing.T) {
		original := []byte("multi-rekey")
		pCopy := make([]byte, len(original))
		copy(pCopy, original)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i := 0; i < 10; i++ {
			if err := blob.Rekey(); err != nil {
				t.Fatalf("Rekey iteration %d: %v", i, err)
			}
		}

		got := blob.Decrypt()
		defer ShredMemory(got)
		if !bytes.Equal(got, original) {
			t.Fatalf("after 10 rekeys: got %q, want %q", got, original)
		}
	})
}

// --------------------------------------------------------------------------
// WithDecrypted
// --------------------------------------------------------------------------

func TestWithDecrypted(t *testing.T) {
	t.Run("callback receives correct plaintext", func(t *testing.T) {
		original := []byte("callback data")
		pCopy := make([]byte, len(original))
		copy(pCopy, original)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var received []byte
		WithDecrypted(blob, func(plain []byte) {
			received = make([]byte, len(plain))
			copy(received, plain)
		})

		if !bytes.Equal(received, original) {
			t.Fatalf("callback got %q, want %q", received, original)
		}
	})

	t.Run("plaintext is shredded after callback", func(t *testing.T) {
		original := []byte("shred after callback")
		pCopy := make([]byte, len(original))
		copy(pCopy, original)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var capturedPlain []byte
		WithDecrypted(blob, func(plain []byte) {
			// Capture a reference to the plain slice header (same backing array).
			capturedPlain = plain
		})

		if !allZero(capturedPlain) {
			t.Fatal("plaintext was not shredded after WithDecrypted callback")
		}
	})

	t.Run("panic in callback still shreds plaintext", func(t *testing.T) {
		original := []byte("panic shred test")
		pCopy := make([]byte, len(original))
		copy(pCopy, original)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var capturedPlain []byte
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected panic to propagate")
				}
			}()
			WithDecrypted(blob, func(plain []byte) {
				capturedPlain = plain
				panic("boom")
			})
		}()

		if !allZero(capturedPlain) {
			t.Fatal("plaintext was not shredded after panic in callback")
		}
	})
}

// --------------------------------------------------------------------------
// ProtectedString
// --------------------------------------------------------------------------

func TestProtectedString(t *testing.T) {
	t.Run("NewProtectedString and Get round-trip", func(t *testing.T) {
		ps, err := NewProtectedString("secret-value-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := ps.Get()
		if got != "secret-value-123" {
			t.Fatalf("got %q, want %q", got, "secret-value-123")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		ps, err := NewProtectedString("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := ps.Get()
		if got != "" {
			t.Fatalf("got %q, want empty string", got)
		}
	})

	t.Run("Destroy then Get returns empty", func(t *testing.T) {
		ps, err := NewProtectedString("destroy me")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ps.Destroy()
		got := ps.Get()
		if got != "" {
			t.Fatalf("expected empty string after Destroy, got %q", got)
		}
	})

	t.Run("unicode string round-trip", func(t *testing.T) {
		ps, err := NewProtectedString("hello \u4e16\u754c \U0001f512")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := ps.Get()
		if got != "hello \u4e16\u754c \U0001f512" {
			t.Fatalf("got %q, want %q", got, "hello \u4e16\u754c \U0001f512")
		}
	})
}

// --------------------------------------------------------------------------
// ProtectedConfig
// --------------------------------------------------------------------------

func TestProtectedConfig(t *testing.T) {
	t.Run("encrypts all fields and zeros originals", func(t *testing.T) {
		psk := make([]byte, 32)
		_, _ = rand.Read(psk)
		pskCopy := make([]byte, 32)
		copy(pskCopy, psk)

		pubKey := make([]byte, 65)
		_, _ = rand.Read(pubKey)
		pubKeyCopy := make([]byte, 65)
		copy(pubKeyCopy, pubKey)

		cfg := &config.ImplantConfig{
			C2Servers:    []string{"https://c2.example.com/beacon", "https://c2-backup.example.com/beacon"},
			DNSDomains:   []string{"ns1.evil.com", "ns2.evil.com"},
			DoHResolvers: []string{"https://1.1.1.1/dns-query"},
			PSK:          psk,
			ServerPubKey: pubKey,
		}

		pc, err := NewProtectedConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer pc.Destroy()

		// Originals in cfg should be zeroed/nil.
		if cfg.C2Servers != nil {
			t.Fatal("cfg.C2Servers not nilled")
		}
		if cfg.DNSDomains != nil {
			t.Fatal("cfg.DNSDomains not nilled")
		}
		if cfg.DoHResolvers != nil {
			t.Fatal("cfg.DoHResolvers not nilled")
		}
		if cfg.PSK != nil {
			t.Fatal("cfg.PSK not nilled")
		}
		if cfg.ServerPubKey != nil {
			t.Fatal("cfg.ServerPubKey not nilled")
		}

		// The original byte slices (psk, pubKey) should be zeroed.
		if !allZero(psk) {
			t.Fatal("original PSK bytes not shredded")
		}
		if !allZero(pubKey) {
			t.Fatal("original ServerPubKey bytes not shredded")
		}

		// Verify encrypted content is recoverable.
		if len(pc.C2Servers) != 2 {
			t.Fatalf("expected 2 C2Servers, got %d", len(pc.C2Servers))
		}
		if len(pc.DNSDomains) != 2 {
			t.Fatalf("expected 2 DNSDomains, got %d", len(pc.DNSDomains))
		}
		if len(pc.DoHResolvers) != 1 {
			t.Fatalf("expected 1 DoHResolver, got %d", len(pc.DoHResolvers))
		}
	})

	t.Run("GetC2Servers returns correct values", func(t *testing.T) {
		cfg := &config.ImplantConfig{
			C2Servers: []string{"https://alpha.com/c2", "https://beta.com/c2", "https://gamma.com/c2"},
		}

		pc, err := NewProtectedConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer pc.Destroy()

		servers := pc.GetC2Servers()
		expected := []string{"https://alpha.com/c2", "https://beta.com/c2", "https://gamma.com/c2"}
		if len(servers) != len(expected) {
			t.Fatalf("expected %d servers, got %d", len(expected), len(servers))
		}
		for i, s := range servers {
			if s != expected[i] {
				t.Fatalf("server[%d]: got %q, want %q", i, s, expected[i])
			}
		}
	})

	t.Run("GetC2ServersBytes returns correct values", func(t *testing.T) {
		cfg := &config.ImplantConfig{
			C2Servers: []string{"https://one.com", "https://two.com"},
		}

		pc, err := NewProtectedConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer pc.Destroy()

		bservers := pc.GetC2ServersBytes()
		expected := [][]byte{[]byte("https://one.com"), []byte("https://two.com")}
		if len(bservers) != len(expected) {
			t.Fatalf("expected %d, got %d", len(expected), len(bservers))
		}
		for i, b := range bservers {
			if !bytes.Equal(b, expected[i]) {
				t.Fatalf("server[%d]: got %q, want %q", i, b, expected[i])
			}
		}

		// Clean up.
		ShredServerList(bservers)
	})

	t.Run("ShredServerList zeros all slices", func(t *testing.T) {
		cfg := &config.ImplantConfig{
			C2Servers: []string{"https://shred1.com", "https://shred2.com"},
		}

		pc, err := NewProtectedConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer pc.Destroy()

		bservers := pc.GetC2ServersBytes()

		// Capture references before shredding.
		refs := make([][]byte, len(bservers))
		copy(refs, bservers)

		ShredServerList(bservers)

		for i, ref := range refs {
			if !allZero(ref) {
				t.Fatalf("server[%d] backing was not zeroed", i)
			}
		}
		for i, b := range bservers {
			if b != nil {
				t.Fatalf("server[%d] reference not nilled", i)
			}
		}
	})

	t.Run("RekeyAll works", func(t *testing.T) {
		psk := make([]byte, 32)
		_, _ = rand.Read(psk)
		pubKey := make([]byte, 65)
		_, _ = rand.Read(pubKey)

		pskOrig := make([]byte, len(psk))
		copy(pskOrig, psk)
		pubKeyOrig := make([]byte, len(pubKey))
		copy(pubKeyOrig, pubKey)

		cfg := &config.ImplantConfig{
			C2Servers:    []string{"https://rekey.com/c2"},
			DNSDomains:   []string{"ns.rekey.com"},
			DoHResolvers: []string{"https://doh.rekey.com"},
			PSK:          psk,
			ServerPubKey: pubKey,
		}

		pc, err := NewProtectedConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer pc.Destroy()

		// Verify values before rekey.
		servers := pc.GetC2Servers()
		if servers[0] != "https://rekey.com/c2" {
			t.Fatalf("before rekey: got %q", servers[0])
		}

		if err := RekeyAll(pc); err != nil {
			t.Fatalf("RekeyAll error: %v", err)
		}

		// Verify values after rekey are unchanged.
		servers = pc.GetC2Servers()
		if servers[0] != "https://rekey.com/c2" {
			t.Fatalf("after rekey: got %q", servers[0])
		}

		// Verify PSK decrypts correctly.
		pskDecrypted := pc.PSK.Decrypt()
		defer ShredMemory(pskDecrypted)
		if !bytes.Equal(pskDecrypted, pskOrig) {
			t.Fatal("PSK mismatch after rekey")
		}

		// Verify ServerPubKey decrypts correctly.
		pubDecrypted := pc.ServerPubKey.Decrypt()
		defer ShredMemory(pubDecrypted)
		if !bytes.Equal(pubDecrypted, pubKeyOrig) {
			t.Fatal("ServerPubKey mismatch after rekey")
		}
	})

	t.Run("Destroy shreds everything", func(t *testing.T) {
		cfg := &config.ImplantConfig{
			C2Servers:  []string{"https://destroy.com"},
			DNSDomains: []string{"ns.destroy.com"},
		}

		pc, err := NewProtectedConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Capture internal references before Destroy.
		c2Data := pc.C2Servers[0].blob.data
		c2Key := pc.C2Servers[0].blob.key
		dnsData := pc.DNSDomains[0].blob.data
		dnsKey := pc.DNSDomains[0].blob.key

		pc.Destroy()

		if !allZero(c2Data) {
			t.Fatal("C2 data not shredded after Destroy")
		}
		if !allZero(c2Key) {
			t.Fatal("C2 key not shredded after Destroy")
		}
		if !allZero(dnsData) {
			t.Fatal("DNS data not shredded after Destroy")
		}
		if !allZero(dnsKey) {
			t.Fatal("DNS key not shredded after Destroy")
		}
	})

	t.Run("empty config fields", func(t *testing.T) {
		cfg := &config.ImplantConfig{
			C2Servers:    []string{},
			DNSDomains:   []string{},
			DoHResolvers: []string{},
			PSK:          nil,
			ServerPubKey: nil,
		}

		pc, err := NewProtectedConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer pc.Destroy()

		servers := pc.GetC2Servers()
		if len(servers) != 0 {
			t.Fatalf("expected 0 servers, got %d", len(servers))
		}

		bservers := pc.GetC2ServersBytes()
		if len(bservers) != 0 {
			t.Fatalf("expected 0 byte servers, got %d", len(bservers))
		}

		// PSK and ServerPubKey should be empty blobs (no error).
		pskDec := pc.PSK.Decrypt()
		if pskDec != nil {
			t.Fatalf("expected nil PSK decrypt, got %v", pskDec)
		}
	})
}

// --------------------------------------------------------------------------
// Concurrency
// --------------------------------------------------------------------------

func TestConcurrency(t *testing.T) {
	t.Run("concurrent Decrypt calls do not race", func(t *testing.T) {
		original := []byte("concurrent access test data")
		pCopy := make([]byte, len(original))
		copy(pCopy, original)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		const goroutines = 50
		var wg sync.WaitGroup
		wg.Add(goroutines)

		errs := make(chan string, goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				got := blob.Decrypt()
				defer ShredMemory(got)
				if !bytes.Equal(got, original) {
					errs <- "decrypt mismatch in concurrent goroutine"
				}
			}()
		}

		wg.Wait()
		close(errs)

		for e := range errs {
			t.Fatal(e)
		}
	})

	t.Run("concurrent Decrypt and Rekey do not race", func(t *testing.T) {
		original := []byte("concurrent rekey test")
		pCopy := make([]byte, len(original))
		copy(pCopy, original)

		blob, err := NewEncryptedBlob(pCopy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		const goroutines = 30
		var wg sync.WaitGroup
		wg.Add(goroutines * 2)

		errs := make(chan string, goroutines*2)

		// Half the goroutines do Decrypt.
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				got := blob.Decrypt()
				defer ShredMemory(got)
				if !bytes.Equal(got, original) {
					errs <- "decrypt mismatch during concurrent rekey"
				}
			}()
		}

		// Half the goroutines do Rekey.
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				if err := blob.Rekey(); err != nil {
					errs <- "rekey error: " + err.Error()
				}
			}()
		}

		wg.Wait()
		close(errs)

		for e := range errs {
			t.Fatal(e)
		}

		// Final verify after all rekeys.
		got := blob.Decrypt()
		defer ShredMemory(got)
		if !bytes.Equal(got, original) {
			t.Fatal("final decrypt mismatch after concurrent rekeys")
		}
	})
}
