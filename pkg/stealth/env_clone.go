package stealth

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// EnvProfile represents the captured environment of a target process.
type EnvProfile struct {
	PID  int
	Name string
	Vars map[string]string
}

// CaptureProcessEnv reads the full environment of a target process from /proc/[pid]/environ.
// This gives us the exact env vars that process was started with.
func CaptureProcessEnv(pid int) (*EnvProfile, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil, err
	}

	name, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))

	profile := &EnvProfile{
		PID:  pid,
		Name: strings.TrimSpace(string(name)),
		Vars: make(map[string]string),
	}

	// /proc/pid/environ is null-byte separated
	for _, entry := range bytes.Split(data, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		parts := strings.SplitN(string(entry), "=", 2)
		if len(parts) == 2 {
			profile.Vars[parts[0]] = parts[1]
		}
	}

	return profile, nil
}

// FindTargetProcess finds a running process by name and captures its environment.
// Picks the oldest instance (lowest PID) to get the most "legitimate" looking one.
func FindTargetProcess(processName string) (*EnvProfile, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	bestPID := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 2 {
			continue
		}

		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}

		if strings.TrimSpace(string(comm)) == processName {
			if bestPID == 0 || pid < bestPID {
				bestPID = pid
			}
		}
	}

	if bestPID == 0 {
		return nil, fmt.Errorf("process %s not found", processName)
	}

	return CaptureProcessEnv(bestPID)
}

// ApplyEnvironment replaces the current process environment with the target's.
// This is a full replacement — all existing vars are removed first.
// Preserves a small set of operational vars we need internally (prefixed with _).
func ApplyEnvironment(profile *EnvProfile) {
	// Save our internal operational vars
	preserved := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && strings.HasPrefix(parts[0], "_") {
			preserved[parts[0]] = parts[1]
		}
	}

	// Clear everything
	os.Clearenv()

	// Apply target's environment
	for k, v := range profile.Vars {
		os.Setenv(k, v)
	}

	// Restore our internal vars
	for k, v := range preserved {
		os.Setenv(k, v)
	}
}

// CloneEnvironmentFrom is the all-in-one function: find process, capture env, apply it.
// Falls back gracefully — if target not found, applies a generic service environment.
func CloneEnvironmentFrom(processName string) error {
	profile, err := FindTargetProcess(processName)
	if err != nil {
		// Fallback: apply a generic daemon environment
		applyGenericDaemonEnv()
		return err
	}

	ApplyEnvironment(profile)
	return nil
}

// applyGenericDaemonEnv sets environment variables typical of a systemd-managed daemon.
// Used as fallback when we can't find the target process.
func applyGenericDaemonEnv() {
	os.Clearenv()

	// Standard systemd service environment
	generic := map[string]string{
		"PATH":             "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG":             "en_US.UTF-8",
		"HOME":             "/root",
		"LOGNAME":          "root",
		"USER":             "root",
		"SHELL":            "/bin/false",
		"INVOCATION_ID":    generateFakeInvocationID(),
		"JOURNAL_STREAM":   "8:12345",
		"SYSTEMD_EXEC_PID": strconv.Itoa(os.Getpid()),
	}

	for k, v := range generic {
		os.Setenv(k, v)
	}
}

// generateFakeInvocationID creates a realistic-looking systemd invocation ID.
// Format: 32 hex characters (128-bit UUID without dashes).
func generateFakeInvocationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	}
	return fmt.Sprintf("%x", b)
}

// EnvironmentFingerprint returns a hash-like summary of current environment
// for comparison against expected profiles during verification.
func EnvironmentFingerprint() map[string]bool {
	result := make(map[string]bool)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = true
		}
	}
	return result
}

// DetectEnvAnomalies checks if our current environment has suspicious variables
// that don't belong to the masqueraded process type.
func DetectEnvAnomalies(expectedProfile *EnvProfile) []string {
	var anomalies []string

	current := EnvironmentFingerprint()

	// Check for vars we have that the target doesn't
	for name := range current {
		if _, exists := expectedProfile.Vars[name]; !exists {
			// Internal vars are OK
			if !strings.HasPrefix(name, "_") {
				anomalies = append(anomalies, "unexpected: "+name)
			}
		}
	}

	// Check for vars the target has that we're missing
	for name := range expectedProfile.Vars {
		if !current[name] {
			anomalies = append(anomalies, "missing: "+name)
		}
	}

	return anomalies
}
