package opsec

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// Timestomp copies atime and mtime from a reference file to the target path.
// Good reference files include /bin/ls and /usr/bin/env which have old,
// unsuspicious timestamps.
func Timestomp(targetPath string, referenceFile string) error {
	var stat unix.Stat_t
	if err := unix.Stat(referenceFile, &stat); err != nil {
		return fmt.Errorf("antiforensics: failed to stat reference file %s: %w", referenceFile, err)
	}

	// Extract atime and mtime from the reference file's stat.
	atime := unix.Timespec{Sec: stat.Atim.Sec, Nsec: stat.Atim.Nsec}
	mtime := unix.Timespec{Sec: stat.Mtim.Sec, Nsec: stat.Mtim.Nsec}

	times := []unix.Timespec{atime, mtime}

	if err := unix.UtimesNano(targetPath, times); err != nil {
		return fmt.Errorf("antiforensics: failed to set timestamps on %s: %w", targetPath, err)
	}

	return nil
}

// TimestompToTime sets atime and mtime on the given path to the specified time.
func TimestompToTime(path string, t time.Time) error {
	ts := unix.NsecToTimespec(t.UnixNano())
	times := []unix.Timespec{ts, ts}

	if err := unix.UtimesNano(path, times); err != nil {
		return fmt.Errorf("antiforensics: failed to set timestamps on %s: %w", path, err)
	}

	return nil
}

// SecureDelete overwrites a file with 3 passes of random data, then removes it.
// This makes recovery from disk significantly harder.
func SecureDelete(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("antiforensics: failed to stat %s: %w", path, err)
	}

	size := info.Size()
	if size == 0 {
		return os.Remove(path)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("antiforensics: failed to open %s for overwrite: %w", path, err)
	}

	buf := make([]byte, 4096)
	for pass := 0; pass < 3; pass++ {
		if _, err := f.Seek(0, 0); err != nil {
			f.Close()
			return fmt.Errorf("antiforensics: seek failed on pass %d: %w", pass, err)
		}

		remaining := size
		for remaining > 0 {
			n := int64(len(buf))
			if remaining < n {
				n = remaining
			}
			if _, err := rand.Read(buf[:n]); err != nil {
				f.Close()
				return fmt.Errorf("antiforensics: rand read failed: %w", err)
			}
			written, err := f.Write(buf[:n])
			if err != nil {
				f.Close()
				return fmt.Errorf("antiforensics: write failed on pass %d: %w", pass, err)
			}
			remaining -= int64(written)
		}

		// Sync to ensure data is flushed to disk after each pass.
		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("antiforensics: sync failed on pass %d: %w", pass, err)
		}
	}

	f.Close()

	// Remove the file after overwriting.
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("antiforensics: failed to remove %s: %w", path, err)
	}

	return nil
}

// SecureDeleteDir recursively secure-deletes all files in a directory,
// then removes the empty directory tree.
func SecureDeleteDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("antiforensics: failed to read directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if err := SecureDeleteDir(fullPath); err != nil {
				return err
			}
		} else {
			if err := SecureDelete(fullPath); err != nil {
				return err
			}
		}
	}

	// Remove the now-empty directory.
	if err := os.Remove(dir); err != nil {
		return fmt.Errorf("antiforensics: failed to remove directory %s: %w", dir, err)
	}

	return nil
}

// ShredMemory zeroes out a byte slice to clear sensitive data from memory.
// The go:noinline directive prevents the compiler from inlining and
// optimizing away the zeroing operation. runtime.KeepAlive ensures the
// slice is not collected before zeroing completes.
//
//go:noinline
func ShredMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Prevent the compiler from optimizing away the zeroing.
	runtime.KeepAlive(b)
}
