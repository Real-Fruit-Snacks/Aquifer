package opsec

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// forensicParentProcs lists process names commonly associated with debugging
// and reverse engineering tools.
var forensicParentProcs = []string{
	"gdb",
	"strace",
	"ltrace",
	"ida",
	"ida64",
	"idaq",
	"idaq64",
	"r2",
	"radare2",
	"x64dbg",
	"ollydbg",
	"edb",
	"lldb",
	"delve",
	"dlv",
	"frida",
	"ghidra",
}

// DisableCoreDumpsEx provides comprehensive core dump prevention.
// It combines prctl PR_SET_DUMPABLE, RLIMIT_CORE, and coredump_filter
// to ensure no memory contents reach disk.
func DisableCoreDumpsEx() error {
	// Set PR_SET_DUMPABLE to 0: prevents core dump generation and
	// restricts /proc/pid/mem access from other processes.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("coredump: failed to set PR_SET_DUMPABLE: %w", err)
	}

	// Set RLIMIT_CORE to 0 for belt-and-suspenders core dump prevention.
	rlimit := unix.Rlimit{Cur: 0, Max: 0}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &rlimit); err != nil {
		return fmt.Errorf("coredump: failed to set RLIMIT_CORE to 0: %w", err)
	}

	// Write "0" to coredump_filter to disable dumping of all memory segment types.
	if err := os.WriteFile("/proc/self/coredump_filter", []byte("0"), 0); err != nil {
		// Non-fatal: this file may not be writable in all contexts.
		_ = err
	}

	return nil
}

// DetectDebugger checks multiple indicators to determine if the process
// is being debugged or traced. Returns true if a debugger is detected.
func DetectDebugger() bool {
	// Check 1: Read TracerPid from /proc/self/status.
	if checkTracerPid() {
		return true
	}

	// Check 2: Check if the parent process is a known debugger.
	if checkParentDebugger() {
		return true
	}

	return false
}

// checkTracerPid reads /proc/self/status and checks if TracerPid is non-zero,
// which indicates another process is tracing us.
func checkTracerPid() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
			break
		}
	}

	return false
}

// checkParentDebugger checks if the parent process name matches known
// debugging and reverse engineering tools.
func checkParentDebugger() bool {
	ppid := os.Getppid()
	commPath := fmt.Sprintf("/proc/%d/comm", ppid)

	comm, err := os.ReadFile(commPath)
	if err != nil {
		return false
	}

	parentName := strings.TrimSpace(string(comm))
	parentLower := strings.ToLower(parentName)

	for _, proc := range forensicParentProcs {
		if parentLower == proc {
			return true
		}
	}

	return false
}

// AntiPtrace calls PTRACE_TRACEME on the current process to prevent other
// processes from attaching a debugger. Only one tracer can be attached at
// a time, so this preemptively claims the slot.
func AntiPtrace() error {
	// PTRACE_TRACEME = 0. This indicates that this process is to be traced
	// by its parent. Any attempt by another process to ptrace will fail.
	_, _, errno := unix.RawSyscall(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0)
	if errno != 0 {
		return fmt.Errorf("coredump: PTRACE_TRACEME failed (possibly already traced): %w", errno)
	}

	return nil
}

// DetectBreakpoints performs basic breakpoint detection by examining
// /proc/self/maps for suspicious anonymous executable regions and checking
// for INT3 (0xCC) instructions at function prologues.
func DetectBreakpoints() bool {
	// Check 1: Look for anonymous rwxp mappings which may indicate
	// injected code or debugger-modified pages.
	if checkSuspiciousMaps() {
		return true
	}

	// Check 2: Check our own function prologues for INT3 (0xCC) bytes
	// which debuggers insert as software breakpoints.
	if checkInt3() {
		return true
	}

	return false
}

// checkSuspiciousMaps reads /proc/self/maps looking for anonymous memory
// regions with rwxp permissions, which may indicate injected debug code.
func checkSuspiciousMaps() bool {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	suspiciousCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		perms := fields[1]
		// rwxp with no backing file is suspicious: anonymous executable memory.
		if perms == "rwxp" && (len(fields) < 6 || strings.TrimSpace(fields[len(fields)-1]) == "") {
			suspiciousCount++
		}
	}

	// A few anonymous rwxp regions can be normal (JIT, etc.),
	// but multiple is suspicious.
	return suspiciousCount > 2
}

// checkInt3 does a basic check for INT3 (0xCC) software breakpoints at
// known function addresses. This is a heuristic check.
func checkInt3() bool {
	// Check the prologue of a known function as a canary for software breakpoints.
	// Use unsafe.Pointer to get the function's entry point without importing reflect.
	fn := DetectBreakpoints
	funcAddr := **(**uintptr)(unsafe.Pointer(&fn))

	f, err := os.Open("/proc/self/mem")
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, int64(funcAddr)); err != nil {
		return false
	}

	// INT3 = 0xCC is the standard software breakpoint instruction.
	return buf[0] == 0xCC
}

// ProtectMemory locks sensitive memory regions to prevent them from being
// swapped to disk, which would expose secrets in swap space or hibernation files.
func ProtectMemory() error {
	// Lock all current and future memory pages to prevent swapping.
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("coredump: mlockall failed: %w", err)
	}

	return nil
}
