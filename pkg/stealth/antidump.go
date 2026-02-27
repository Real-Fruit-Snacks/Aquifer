package stealth

// MADV_WIPEONFORK + MADV_DONTDUMP — Anti-Dump Memory Regions
//
// OPSEC rationale: Memory forensic tools extract process memory via:
//   1. Core dumps (gcore, /proc/pid/coredump_filter)
//   2. /proc/pid/mem reads (LiME, AVML)
//   3. ptrace PEEKDATA
//   4. Fork-based dumpers (fork child, read child memory)
//
// We mark sensitive memory regions with two madvise flags:
//
//   MADV_DONTDUMP (kernel 3.4+):
//     Region is excluded from core dumps entirely. Even if RLIMIT_CORE
//     is overridden and a core dump is forced, our regions are empty.
//
//   MADV_WIPEONFORK (kernel 4.14+):
//     Region is ZEROED in child processes after fork(). Memory dump
//     tools that use fork() to snapshot memory (common pattern) get
//     all zeros for our regions. The parent retains the real data.
//
// Combined with /proc/self/coredump_filter=0x00 (from ktune.go),
// this creates layered defense against memory forensics.
//
// Capability: None (madvise is unprivileged)

import (
	"fmt"
	"syscall"
	"unsafe"
)

// madvise constants not in Go's syscall package.
const (
	madvDontDump   = 16 // MADV_DONTDUMP
	madvWipeOnFork = 18 // MADV_WIPEONFORK
	madvDontFork   = 10 // MADV_DONTFORK (region not inherited at all)
)

// ProtectRegion marks a memory region as anti-dump and anti-fork.
// After this call:
//   - Core dumps exclude this region
//   - Fork-based dumpers see zeros
func ProtectRegion(addr uintptr, length uintptr) error {
	// Align to page boundaries
	pageSize := uintptr(syscall.Getpagesize())
	alignedAddr := addr &^ (pageSize - 1)
	alignedLen := ((addr + length) - alignedAddr + pageSize - 1) &^ (pageSize - 1)

	// MADV_DONTDUMP — exclude from core dumps
	if err := madvise(alignedAddr, alignedLen, madvDontDump); err != nil {
		return fmt.Errorf("MADV_DONTDUMP: %v", err)
	}

	// MADV_WIPEONFORK — zero on fork
	if err := madvise(alignedAddr, alignedLen, madvWipeOnFork); err != nil {
		// Non-fatal: kernel may be < 4.14
		_ = err
	}

	return nil
}

// ProtectSlice marks a Go byte slice's backing memory as anti-dump.
// The slice must not be moved by the runtime (safe for mmap'd or
// long-lived heap allocations — Go's GC doesn't move objects).
func ProtectSlice(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	addr := uintptr(unsafe.Pointer(&data[0]))
	return ProtectRegion(addr, uintptr(len(data)))
}

// AllocProtected allocates a memory region that is excluded from core dumps
// and zeroed on fork. Uses mmap directly for guaranteed alignment and
// control over page-level attributes.
func AllocProtected(size int) ([]byte, error) {
	// Round up to page size
	pageSize := syscall.Getpagesize()
	size = (size + pageSize - 1) &^ (pageSize - 1)

	// mmap anonymous private memory
	mem, err := syscall.Mmap(-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("mmap: %v", err)
	}

	// Apply anti-dump protections
	addr := uintptr(unsafe.Pointer(&mem[0]))

	madvise(addr, uintptr(size), madvDontDump)
	madvise(addr, uintptr(size), madvWipeOnFork)

	return mem, nil
}

// FreeProtected releases memory allocated by AllocProtected.
func FreeProtected(mem []byte) error {
	if len(mem) == 0 {
		return nil
	}
	return syscall.Munmap(mem)
}

// HideFromFork marks a region as DONTFORK — the region is not mapped
// at all in child processes. More aggressive than WIPEONFORK: the child
// gets a segfault if it tries to access the region.
func HideFromFork(addr uintptr, length uintptr) error {
	pageSize := uintptr(syscall.Getpagesize())
	alignedAddr := addr &^ (pageSize - 1)
	alignedLen := ((addr + length) - alignedAddr + pageSize - 1) &^ (pageSize - 1)

	return madvise(alignedAddr, alignedLen, madvDontFork)
}

// madvise wraps the madvise(2) syscall.
func madvise(addr uintptr, length uintptr, advice int) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_MADVISE,
		addr,
		length,
		uintptr(advice),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// AntiDumpAvailable checks if MADV_DONTDUMP and MADV_WIPEONFORK are supported.
func AntiDumpAvailable() (dontdump bool, wipeonfork bool) {
	// Allocate a test page
	pageSize := syscall.Getpagesize()
	mem, err := syscall.Mmap(-1, 0, pageSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return false, false
	}
	defer syscall.Munmap(mem)

	addr := uintptr(unsafe.Pointer(&mem[0]))

	dontdump = madvise(addr, uintptr(pageSize), madvDontDump) == nil
	wipeonfork = madvise(addr, uintptr(pageSize), madvWipeOnFork) == nil
	return
}
