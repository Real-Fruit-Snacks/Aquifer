package namespace

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// SetupPIDNamespace configures the PID namespace for the implant.
// Inside CLONE_NEWPID, this process is PID 1 and must:
//   - Mount a private /proc so 'ps', /proc reads reflect only namespace processes
//   - Act as an init process by reaping orphaned children (zombie prevention)
func SetupPIDNamespace() error {
	// Verify we are PID 1 in this namespace.
	if os.Getpid() != 1 {
		// Not strictly fatal -- we may be PID 1 from the namespace's perspective
		// even if the kernel reports differently in some configurations.
		// Proceed regardless but note the discrepancy.
	}

	// Mount a private /proc for this PID namespace.
	// First unmount the inherited /proc (ignore error if not mounted).
	_ = unix.Unmount("/proc", unix.MNT_DETACH)

	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("pid: failed to mount private /proc: %w", err)
	}

	// Set up PID 1 signal handling: reap zombie children.
	go reapChildren()

	return nil
}

// reapChildren runs in a goroutine and reaps any orphaned child processes.
// As PID 1 inside the namespace, we inherit orphans and must wait() on them
// to prevent zombie accumulation that could be detected by host-side monitoring.
func reapChildren() {
	sigchld := make(chan os.Signal, 32)
	signal.Notify(sigchld, syscall.SIGCHLD)

	for range sigchld {
		// Reap all available children without blocking.
		for {
			var ws syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
			if pid <= 0 || err != nil {
				break
			}
		}
	}
}
