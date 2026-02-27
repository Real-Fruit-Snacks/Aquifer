package tasking

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// ProcessInfo holds information about a running process.
type ProcessInfo struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	User    string `json:"user"`
	Cmdline string `json:"cmdline"`
	State   string `json:"state"`
}

// ConnectionInfo holds a parsed network connection from /proc/net/*.
type ConnectionInfo struct {
	Protocol  string `json:"protocol"`
	LocalAddr string `json:"local_addr"`
	LocalPort int    `json:"local_port"`
	RemAddr   string `json:"remote_addr"`
	RemPort   int    `json:"remote_port"`
	State     string `json:"state"`
	Inode     string `json:"inode"`
}

// InterfaceDetail holds network interface details.
type InterfaceDetail struct {
	Name  string   `json:"name"`
	Flags string   `json:"flags"`
	MTU   int      `json:"mtu"`
	Addrs []string `json:"addrs"`
	MAC   string   `json:"mac"`
}

// SystemInfoResult holds system-level information.
type SystemInfoResult struct {
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"`
	Distro   string `json:"distro"`
	Uptime   string `json:"uptime"`
	Arch     string `json:"arch"`
	NumCPU   int    `json:"num_cpu"`
	Memory   string `json:"memory"`
}

// GetProcessList reads /proc to enumerate running processes.
func GetProcessList(task config.Task) ([]byte, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("ps: cannot read /proc: %w", err)
	}

	var procs []ProcessInfo

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}

		proc := ProcessInfo{PID: pid}

		// Read comm (process name).
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm")); err == nil {
			proc.Name = strings.TrimSpace(string(data))
		}

		// Read cmdline.
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline")); err == nil {
			// cmdline uses null bytes as separators.
			cmdline := strings.ReplaceAll(string(data), "\x00", " ")
			proc.Cmdline = strings.TrimSpace(cmdline)
		}

		// Read status for state and UID.
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status")); err == nil {
			proc.State, proc.User = parseStatus(string(data))
		}

		procs = append(procs, proc)
	}

	return json.Marshal(procs)
}

// parseStatus extracts State and Uid from /proc/[pid]/status content.
func parseStatus(content string) (state, user string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "State:") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 {
				state = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "Uid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				user = "uid=" + parts[1]
			}
		}
	}
	return
}

// GetNetworkInfo parses /proc/net/tcp, /proc/net/udp, and /proc/net/tcp6
// to list active network connections.
func GetNetworkInfo(task config.Task) ([]byte, error) {
	var connections []ConnectionInfo

	// Parse each protocol file.
	protocols := []struct {
		path string
		name string
		ipv6 bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/tcp6", "tcp6", true},
		{"/proc/net/udp6", "udp6", true},
	}

	for _, proto := range protocols {
		conns, err := parseProcNet(proto.path, proto.name, proto.ipv6)
		if err != nil {
			// Non-fatal: file may not exist (e.g., no IPv6).
			continue
		}
		connections = append(connections, conns...)
	}

	return json.Marshal(connections)
}

// parseProcNet parses a /proc/net/{tcp,udp,tcp6,udp6} file.
func parseProcNet(path, protocol string, ipv6 bool) ([]ConnectionInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []ConnectionInfo
	scanner := bufio.NewScanner(f)

	// Skip header line.
	if scanner.Scan() {
		// discard
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddr, localPort := parseAddr(fields[1], ipv6)
		remAddr, remPort := parseAddr(fields[2], ipv6)

		stateCode, _ := strconv.ParseUint(fields[3], 16, 8)

		conns = append(conns, ConnectionInfo{
			Protocol:  protocol,
			LocalAddr: localAddr,
			LocalPort: localPort,
			RemAddr:   remAddr,
			RemPort:   remPort,
			State:     tcpStateName(int(stateCode)),
			Inode:     fields[9],
		})
	}

	return conns, scanner.Err()
}

// parseAddr parses a hex-encoded address:port string from /proc/net/*.
func parseAddr(s string, ipv6 bool) (string, int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}

	port, _ := strconv.ParseUint(parts[1], 16, 16)

	if ipv6 {
		return parseIPv6(parts[0]), int(port)
	}
	return parseIPv4(parts[0]), int(port)
}

// parseIPv4 converts a hex-encoded little-endian IPv4 address.
func parseIPv4(hexStr string) string {
	if len(hexStr) != 8 {
		return hexStr
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return hexStr
	}
	// /proc/net stores in host byte order (little-endian on x86).
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

// parseIPv6 converts a hex-encoded IPv6 address from /proc/net format.
func parseIPv6(hexStr string) string {
	if len(hexStr) != 32 {
		return hexStr
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return hexStr
	}
	// /proc/net/tcp6 stores each 4-byte group in host byte order.
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		off := i * 4
		ip[off] = b[off+3]
		ip[off+1] = b[off+2]
		ip[off+2] = b[off+1]
		ip[off+3] = b[off]
	}
	return ip.String()
}

// tcpStateName maps TCP state numbers to names.
func tcpStateName(state int) string {
	names := map[int]string{
		1:  "ESTABLISHED",
		2:  "SYN_SENT",
		3:  "SYN_RECV",
		4:  "FIN_WAIT1",
		5:  "FIN_WAIT2",
		6:  "TIME_WAIT",
		7:  "CLOSE",
		8:  "CLOSE_WAIT",
		9:  "LAST_ACK",
		10: "LISTEN",
		11: "CLOSING",
	}
	if n, ok := names[state]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

// GetInterfaceInfo returns information about all network interfaces.
func GetInterfaceInfo(task config.Task) ([]byte, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("ifconfig: %w", err)
	}

	var details []InterfaceDetail
	for _, iface := range ifaces {
		detail := InterfaceDetail{
			Name:  iface.Name,
			Flags: iface.Flags.String(),
			MTU:   iface.MTU,
			MAC:   iface.HardwareAddr.String(),
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				detail.Addrs = append(detail.Addrs, addr.String())
			}
		}

		details = append(details, detail)
	}

	return json.Marshal(details)
}

// GetSystemInfo gathers hostname, kernel, distro, uptime, memory, and CPU info.
func GetSystemInfo(task config.Task) ([]byte, error) {
	info := SystemInfoResult{
		Arch:   runtime.GOARCH,
		NumCPU: runtime.NumCPU(),
	}

	// Hostname.
	info.Hostname, _ = os.Hostname()

	// Kernel version from /proc/version.
	if data, err := os.ReadFile("/proc/version"); err == nil {
		info.Kernel = strings.TrimSpace(string(data))
	}

	// Distro from /etc/os-release.
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info.Distro = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	// Uptime from /proc/uptime.
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				dur := time.Duration(secs * float64(time.Second))
				info.Uptime = dur.String()
			}
		}
	}

	// Memory from /proc/meminfo.
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		var memLines []string
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") ||
				strings.HasPrefix(line, "MemFree:") ||
				strings.HasPrefix(line, "MemAvailable:") {
				memLines = append(memLines, strings.TrimSpace(line))
			}
		}
		info.Memory = strings.Join(memLines, "; ")
	}

	return json.Marshal(info)
}

// GetUserInfo parses /etc/passwd for user accounts and returns current
// user context information.
func GetUserInfo(task config.Task) ([]byte, error) {
	type UserEntry struct {
		Username string `json:"username"`
		UID      string `json:"uid"`
		GID      string `json:"gid"`
		Home     string `json:"home"`
		Shell    string `json:"shell"`
	}

	type UserInfoResult struct {
		CurrentUID  int         `json:"current_uid"`
		CurrentGID  int         `json:"current_gid"`
		CurrentUser string      `json:"current_user"`
		Hostname    string      `json:"hostname"`
		Users       []UserEntry `json:"users"`
	}

	result := UserInfoResult{
		CurrentUID: os.Getuid(),
		CurrentGID: os.Getgid(),
	}
	result.Hostname, _ = os.Hostname()

	// Map UID to username for current user.
	currentUIDStr := strconv.Itoa(result.CurrentUID)

	// Parse /etc/passwd.
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.SplitN(line, ":", 7)
			if len(fields) < 7 {
				continue
			}
			entry := UserEntry{
				Username: fields[0],
				UID:      fields[2],
				GID:      fields[3],
				Home:     fields[5],
				Shell:    fields[6],
			}
			// Only include users with login shells (not nologin/false).
			shell := filepath.Base(entry.Shell)
			if shell == "nologin" || shell == "false" {
				continue
			}
			result.Users = append(result.Users, entry)

			if fields[2] == currentUIDStr {
				result.CurrentUser = fields[0]
			}
		}
	}

	return json.Marshal(result)
}
