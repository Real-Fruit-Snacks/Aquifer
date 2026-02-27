package evasion

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// IntruderInfo describes a process that has entered our namespace unexpectedly.
type IntruderInfo struct {
	PID     int
	Name    string
	Cmdline string
	PPid    int
	UID     int
	Threat  string // LOW, MEDIUM, HIGH, CRITICAL
}

// NSMonitor watches for unauthorized processes entering our namespaces.
type NSMonitor struct {
	pidNS            uint64
	mntNS            uint64
	netNS            uint64
	knownPIDs        map[int]bool
	pendingIntruders map[int]int // pid -> consecutive detection count
	cleanupFn        func()
	interval         time.Duration
	done             chan struct{}
	mu               sync.Mutex
}

// criticalTools are processes that indicate active tracing/debugging in our namespace.
var criticalTools = map[string]bool{
	"nsenter": true, "strace": true, "ltrace": true,
	"gdb": true, "perf": true, "bpftrace": true,
	"radare2": true, "r2": true, "ida": true,
	"valgrind": true, "lsns": true,
}

// highThreatShells are interactive shells — their presence in our ns suggests IR activity.
var highThreatShells = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "fish": true,
	"dash": true, "ksh": true, "csh": true, "tcsh": true,
}

// NewNSMonitor creates a namespace monitor. cleanupFn is called if intrusion is detected.
func NewNSMonitor(cleanupFn func(), interval time.Duration) *NSMonitor {
	nm := &NSMonitor{
		knownPIDs:        make(map[int]bool),
		pendingIntruders: make(map[int]int),
		cleanupFn:        cleanupFn,
		interval:         interval,
		done:             make(chan struct{}),
	}

	// Record our namespace inodes
	nm.pidNS, _ = getNSInode(os.Getpid(), "pid")
	nm.mntNS, _ = getNSInode(os.Getpid(), "mnt")
	nm.netNS, _ = getNSInode(os.Getpid(), "net")

	// Whitelist ourselves and our children
	nm.mu.Lock()
	nm.knownPIDs[os.Getpid()] = true
	nm.discoverChildren(os.Getpid())
	nm.mu.Unlock()

	return nm
}

// Start begins monitoring for namespace intruders.
func (nm *NSMonitor) Start() {
	go func() {
		ticker := time.NewTicker(nm.interval)
		defer ticker.Stop()
		for {
			select {
			case <-nm.done:
				return
			case <-ticker.C:
				if intruders := nm.detectNSIntruders(); len(intruders) > 0 {
					nm.mu.Lock()
					// Track which PIDs are seen this cycle.
					currentIntruders := make(map[int]bool)
					for _, intr := range intruders {
						if intr.Threat == "CRITICAL" || intr.Threat == "HIGH" {
							currentIntruders[intr.PID] = true
							nm.pendingIntruders[intr.PID]++
						}
					}
					// Prune pending intruders not seen this cycle.
					for pid := range nm.pendingIntruders {
						if !currentIntruders[pid] {
							delete(nm.pendingIntruders, pid)
						}
					}
					// Only trigger cleanup if any intruder persists across 2+ checks.
					shouldCleanup := false
					for _, count := range nm.pendingIntruders {
						if count >= 2 {
							shouldCleanup = true
							break
						}
					}
					nm.mu.Unlock()
					if shouldCleanup {
						if nm.cleanupFn != nil {
							nm.cleanupFn()
						}
						return
					}
				} else {
					// No intruders this cycle; clear pending.
					nm.mu.Lock()
					for pid := range nm.pendingIntruders {
						delete(nm.pendingIntruders, pid)
					}
					nm.mu.Unlock()
				}
				// Also check if our NS inodes changed
				if nm.monitorNSInodes() {
					if nm.cleanupFn != nil {
						nm.cleanupFn()
					}
					return
				}
			}
		}
	}()
}

// Stop halts the monitoring goroutine.
func (nm *NSMonitor) Stop() {
	select {
	case <-nm.done:
	default:
		close(nm.done)
	}
}

// AddKnownPID whitelists a PID we intentionally spawned.
func (nm *NSMonitor) AddKnownPID(pid int) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.knownPIDs[pid] = true
}

// RemoveKnownPID removes a PID from the whitelist.
func (nm *NSMonitor) RemoveKnownPID(pid int) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	delete(nm.knownPIDs, pid)
}

// detectNSIntruders scans /proc for processes sharing our PID namespace.
func (nm *NSMonitor) detectNSIntruders() []IntruderInfo {
	if nm.pidNS == 0 {
		return nil
	}

	var intruders []IntruderInfo

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	nm.mu.Lock()
	known := make(map[int]bool, len(nm.knownPIDs))
	for k, v := range nm.knownPIDs {
		known[k] = v
	}
	nm.mu.Unlock()

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if known[pid] {
			continue
		}

		inode, err := getNSInode(pid, "pid")
		if err != nil || inode != nm.pidNS {
			continue
		}

		// Process is in our PID namespace but not whitelisted
		info := IntruderInfo{PID: pid}
		info.Name = readProcField(pid, "comm")
		info.Cmdline = readProcCmdline(pid)
		info.PPid = readProcPPid(pid)
		info.UID = readProcUID(pid)
		info.Threat = classifyThreat(info.Name, info.Cmdline)

		intruders = append(intruders, info)
	}

	return intruders
}

// monitorNSInodes checks if our namespace inodes have changed (manipulation).
func (nm *NSMonitor) monitorNSInodes() bool {
	if nm.pidNS == 0 {
		return false
	}
	currentPID, _ := getNSInode(os.Getpid(), "pid")
	currentMNT, _ := getNSInode(os.Getpid(), "mnt")
	currentNET, _ := getNSInode(os.Getpid(), "net")

	return (currentPID != 0 && currentPID != nm.pidNS) ||
		(currentMNT != 0 && currentMNT != nm.mntNS) ||
		(currentNET != 0 && currentNET != nm.netNS)
}

// getNSInode returns the inode number of /proc/[pid]/ns/[nsType].
func getNSInode(pid int, nsType string) (uint64, error) {
	if strings.ContainsAny(nsType, "/\\") || strings.Contains(nsType, "..") {
		return 0, fmt.Errorf("invalid ns type: %s", nsType)
	}
	path := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}

// classifyThreat determines the threat level of an intruding process.
func classifyThreat(name, cmdline string) string {
	nameLower := strings.ToLower(strings.TrimSpace(name))

	if criticalTools[nameLower] {
		return "CRITICAL"
	}

	// Check cmdline for nsenter even if the process name is different
	if strings.Contains(strings.ToLower(cmdline), "nsenter") {
		return "CRITICAL"
	}

	if highThreatShells[nameLower] {
		return "HIGH"
	}

	return "MEDIUM"
}

// discoverChildren finds child processes of a given PID.
func (nm *NSMonitor) discoverChildren(parentPID int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if readProcPPid(pid) == parentPID {
			nm.knownPIDs[pid] = true
		}
	}
}

func readProcField(pid int, field string) string {
	// Validate field to prevent path traversal attacks.
	if strings.ContainsAny(field, "/\\") || strings.Contains(field, "..") {
		return ""
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, field))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline is null-separated
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

func readProcPPid(pid int) int {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, _ := strconv.Atoi(parts[1])
				return val
			}
		}
	}
	return 0
}

func readProcUID(pid int) int {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, _ := strconv.Atoi(parts[1])
				return val
			}
		}
	}
	return -1
}
