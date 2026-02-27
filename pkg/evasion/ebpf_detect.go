package evasion

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BPFProgType represents the type of a loaded BPF program.
type BPFProgType int

const (
	BPFProgUnspecified BPFProgType = iota
	BPFProgSocketFilter
	BPFProgKprobe
	BPFProgSchedCLS
	BPFProgSchedACT
	BPFProgTracepoint
	BPFProgXDP
	BPFProgPerfEvent
	BPFProgCgroupSKB
	BPFProgCgroupSock
	BPFProgLWTIn
	BPFProgLWTOut
	BPFProgLWTXmit
	BPFProgSockOps
	BPFProgSKSKB
	BPFProgCgroupDevice
	BPFProgSKMsg
	BPFProgRawTracepoint
	BPFProgCgroupSockAddr
	BPFProgLWTSeg6Local
	BPFProgLIRCMode2
	BPFProgSKReuseport
	BPFProgFlowDissector
	BPFProgCgroupSysctl
	BPFProgRawTracepointWritable
	BPFProgCgroupSockopt
	BPFProgTracing
	BPFProgStructOps
	BPFProgExt
	BPFProgLSM
	BPFProgSKLookup
)

// String returns the human-readable name of the BPF program type.
func (t BPFProgType) String() string {
	names := map[BPFProgType]string{
		BPFProgUnspecified:           "unspecified",
		BPFProgSocketFilter:          "socket_filter",
		BPFProgKprobe:                "kprobe",
		BPFProgSchedCLS:              "sched_cls",
		BPFProgSchedACT:              "sched_act",
		BPFProgTracepoint:            "tracepoint",
		BPFProgXDP:                   "xdp",
		BPFProgPerfEvent:             "perf_event",
		BPFProgCgroupSKB:             "cgroup_skb",
		BPFProgCgroupSock:            "cgroup_sock",
		BPFProgRawTracepoint:         "raw_tracepoint",
		BPFProgTracing:               "tracing",
		BPFProgLSM:                   "lsm",
		BPFProgRawTracepointWritable: "raw_tracepoint_writable",
	}

	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("type_%d", int(t))
}

// BPFProgram represents a loaded BPF program discovered on the system.
type BPFProgram struct {
	ID       string      `json:"id"`
	Type     BPFProgType `json:"type"`
	TypeName string      `json:"type_name"`
	Name     string      `json:"name,omitempty"`
	Source   string      `json:"source"` // Where it was discovered (fdinfo, pinned, etc.)
}

// eBPFTool represents a known eBPF-based security tool.
type eBPFTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// eBPFInfo holds the results of eBPF monitoring detection.
type eBPFInfo struct {
	Programs      []BPFProgram `json:"programs"`
	PinnedPaths   []string     `json:"pinned_paths"`
	SecurityTools []eBPFTool   `json:"security_tools"`
	RiskLevel     RiskLevel    `json:"risk_level"`
	IsMonitoring  bool         `json:"is_monitoring"`
}

// knowneBPFTools maps process names to known eBPF security tools.
var knowneBPFTools = map[string]eBPFTool{
	"tracee": {
		Name:        "Aqua Tracee",
		Description: "eBPF-based runtime security and forensics tool",
	},
	"tetragon": {
		Name:        "Cilium Tetragon",
		Description: "eBPF-based security observability and enforcement",
	},
	"bpftrace": {
		Name:        "bpftrace",
		Description: "High-level tracing language for eBPF",
	},
	"falco": {
		Name:        "Falco",
		Description: "Cloud-native runtime security (eBPF probe)",
	},
	"inspektor-gadget": {
		Name:        "Inspektor Gadget",
		Description: "eBPF-based Kubernetes debugging and security tools",
	},
	"pixie": {
		Name:        "Pixie",
		Description: "eBPF-based observability for Kubernetes",
	},
	"cilium-agent": {
		Name:        "Cilium",
		Description: "eBPF-based networking, observability, and security",
	},
}

// DetecteBPF performs comprehensive eBPF monitoring detection by scanning for
// pinned BPF programs, examining loaded programs via /proc fdinfo, checking
// for known eBPF security tools, and assessing the overall risk.
func DetecteBPF() *eBPFInfo {
	info := &eBPFInfo{
		Programs:      make([]BPFProgram, 0),
		PinnedPaths:   make([]string, 0),
		SecurityTools: make([]eBPFTool, 0),
	}

	// Scan /sys/fs/bpf for pinned programs.
	scanPinnedBPF(info)

	// Scan /proc/*/fdinfo for loaded BPF programs.
	scanProcBPFPrograms(info)

	// Check for known eBPF security tools in running processes.
	detecteBPFTools(info)

	// Assess risk.
	info.RiskLevel = assesseBPFRisk(info)
	info.IsMonitoring = info.RiskLevel > RiskNone

	return info
}

// IseBPFMonitoring provides a quick boolean check for eBPF-based monitoring.
// This is a lightweight check suitable for fast decision-making.
func IseBPFMonitoring() bool {
	// Quick check 1: Are there any pinned BPF objects?
	if hasPinnedBPF() {
		return true
	}

	// Quick check 2: Are known eBPF security tool processes running?
	if haseBPFToolRunning() {
		return true
	}

	return false
}

// scanPinnedBPF walks /sys/fs/bpf to discover pinned BPF programs and maps.
func scanPinnedBPF(info *eBPFInfo) {
	bpfRoot := "/sys/fs/bpf"

	fi, err := os.Stat(bpfRoot)
	if err != nil || !fi.IsDir() {
		return
	}

	_ = filepath.Walk(bpfRoot, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible paths.
		}
		if path == bpfRoot {
			return nil
		}

		info.PinnedPaths = append(info.PinnedPaths, path)
		return nil
	})
}

// scanProcBPFPrograms reads /proc/*/fdinfo/* to discover loaded BPF programs.
// BPF program file descriptors have a "prog_type:" field in their fdinfo.
func scanProcBPFPrograms(info *eBPFInfo) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return
	}

	seen := make(map[string]bool)

	for _, entry := range entries {
		// Only process numeric PID directories.
		if len(entry) == 0 || entry[0] < '0' || entry[0] > '9' {
			continue
		}

		fdInfoDir := filepath.Join("/proc", entry, "fdinfo")
		fds, err := os.ReadDir(fdInfoDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			fdInfoPath := filepath.Join(fdInfoDir, fd.Name())
			prog := parseBPFFdInfo(fdInfoPath, entry)
			if prog != nil {
				// Deduplicate by program ID.
				key := fmt.Sprintf("%s-%d", prog.ID, prog.Type)
				if seen[key] {
					continue
				}
				seen[key] = true
				info.Programs = append(info.Programs, *prog)
			}
		}
	}
}

// parseBPFFdInfo reads a single fdinfo file and returns a BPFProgram if
// this file descriptor refers to a BPF program.
func parseBPFFdInfo(path string, pid string) *BPFProgram {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var progType int
	var progID string
	var progName string
	isBPF := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "prog_type:") {
			isBPF = true
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				fmt.Sscanf(fields[1], "%d", &progType)
			}
		}

		if strings.HasPrefix(line, "prog_id:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				progID = fields[1]
			}
		}

		if strings.HasPrefix(line, "prog_tag:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				progName = fields[1] // Use tag as a name proxy.
			}
		}
	}

	if !isBPF {
		return nil
	}

	pt := BPFProgType(progType)
	return &BPFProgram{
		ID:       progID,
		Type:     pt,
		TypeName: pt.String(),
		Name:     progName,
		Source:   fmt.Sprintf("/proc/%s/fdinfo", pid),
	}
}

// detecteBPFTools scans running processes for known eBPF security tools.
func detecteBPFTools(info *eBPFInfo) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return
	}

	seen := make(map[string]bool)

	for _, entry := range entries {
		if len(entry) == 0 || entry[0] < '0' || entry[0] > '9' {
			continue
		}

		commPath := filepath.Join("/proc", entry, "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		comm := strings.TrimSpace(strings.ToLower(string(data)))
		if tool, ok := knowneBPFTools[comm]; ok {
			if seen[tool.Name] {
				continue
			}
			seen[tool.Name] = true
			info.SecurityTools = append(info.SecurityTools, tool)
		}
	}
}

// assesseBPFRisk computes a risk level based on detected eBPF programs and tools.
func assesseBPFRisk(info *eBPFInfo) RiskLevel {
	// Security tools are the highest signal.
	if len(info.SecurityTools) > 0 {
		// Multiple security tools or known aggressive ones.
		for _, tool := range info.SecurityTools {
			if tool.Name == "Cilium Tetragon" || tool.Name == "Aqua Tracee" {
				return RiskHigh
			}
		}
		if len(info.SecurityTools) >= 2 {
			return RiskHigh
		}
		return RiskMedium
	}

	// Check loaded programs for security-relevant types.
	hasKprobe := false
	hasTracepoint := false
	hasLSM := false
	hasRawTP := false

	for _, prog := range info.Programs {
		switch prog.Type {
		case BPFProgKprobe:
			hasKprobe = true
		case BPFProgTracepoint:
			hasTracepoint = true
		case BPFProgLSM:
			hasLSM = true
		case BPFProgRawTracepoint, BPFProgRawTracepointWritable:
			hasRawTP = true
		case BPFProgTracing:
			hasKprobe = true // Tracing programs are similar to kprobes in risk.
		}
	}

	// LSM programs are always high risk -- they enforce security policy.
	if hasLSM {
		return RiskHigh
	}

	// Multiple tracing program types suggest active security monitoring.
	tracingTypes := 0
	if hasKprobe {
		tracingTypes++
	}
	if hasTracepoint {
		tracingTypes++
	}
	if hasRawTP {
		tracingTypes++
	}

	if tracingTypes >= 2 {
		return RiskMedium
	}

	// Single type of tracing program is low risk (could be performance monitoring).
	if tracingTypes > 0 {
		return RiskLow
	}

	// Pinned programs without identified types.
	if len(info.PinnedPaths) > 0 {
		return RiskLow
	}

	return RiskNone
}

// hasPinnedBPF performs a quick check for any pinned BPF objects.
func hasPinnedBPF() bool {
	entries, err := os.ReadDir("/sys/fs/bpf")
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// haseBPFToolRunning quickly checks if any known eBPF security tool is running.
func haseBPFToolRunning() bool {
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

		comm := strings.TrimSpace(strings.ToLower(string(data)))
		if _, ok := knowneBPFTools[comm]; ok {
			return true
		}
	}

	return false
}
