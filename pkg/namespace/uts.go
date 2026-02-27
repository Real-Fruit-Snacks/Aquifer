package namespace

import (
	"fmt"
	"syscall"
)

// SetupUTSNamespace configures the UTS namespace by setting the hostname
// and domainname to values that blend with legitimate infrastructure.
// This prevents the real hostname from leaking into namespace-aware tools.
func SetupUTSNamespace(hostname string) error {
	if hostname == "" {
		hostname = "worker-01"
	}

	// Set the hostname inside the namespace.
	if err := syscall.Sethostname([]byte(hostname)); err != nil {
		return fmt.Errorf("uts: failed to set hostname to %q: %w", hostname, err)
	}

	// Set domainname to a pattern matching common enterprise environments.
	// This makes the namespace appear as a legitimate corporate host if
	// any tooling queries the NIS/YP domainname.
	domainname := "corp.internal"
	if err := syscall.Setdomainname([]byte(domainname)); err != nil {
		return fmt.Errorf("uts: failed to set domainname to %q: %w", domainname, err)
	}

	return nil
}
