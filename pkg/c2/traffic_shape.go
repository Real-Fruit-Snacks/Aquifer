package c2

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
)

// PayloadSizeBuckets defines common payload sizes used for traffic shaping.
// Payloads are padded to the nearest bucket to prevent size-based fingerprinting.
var PayloadSizeBuckets = []int{512, 1024, 2048, 4096, 8192}

// ShapePayload pads data to the nearest size bucket with a 4-byte big-endian
// length prefix so the original data can be recovered by UnshapePayload.
// If targetSize is 0, the data is padded to the nearest bucket that fits
// the length header + data. Padding bytes are cryptographically random.
func ShapePayload(data []byte, targetSize int) ([]byte, error) {
	if len(data) > math.MaxUint32 {
		return nil, fmt.Errorf("payload exceeds 4 GiB length prefix limit")
	}
	if targetSize <= 0 {
		targetSize = nearestBucket(len(data) + 4) // +4 for length header
	}
	if targetSize < len(data)+4 {
		targetSize = len(data) + 4
	}

	padded := make([]byte, targetSize)
	binary.BigEndian.PutUint32(padded[:4], uint32(len(data)))
	copy(padded[4:], data)
	if len(data)+4 < targetSize {
		rand.Read(padded[4+len(data):]) //nolint:errcheck // crypto/rand.Read does not fail on Linux
	}
	return padded, nil
}

// UnshapePayload extracts the original data from a ShapePayload output
// by reading the 4-byte big-endian length prefix.
func UnshapePayload(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for shape header")
	}
	origLen := binary.BigEndian.Uint32(data[:4])
	if int(origLen) > len(data)-4 {
		return nil, fmt.Errorf("invalid shape header length")
	}
	return data[4 : 4+origLen], nil
}

// AddNoise prepends a 4-byte big-endian length header and appends a random
// amount of random padding (16-256 bytes) to data. The length header allows
// StripNoise to recover the original data.
func AddNoise(data []byte) ([]byte, error) {
	if len(data) > math.MaxUint32 {
		return nil, fmt.Errorf("payload exceeds 4 GiB length prefix limit")
	}
	// Generate a random padding length between 16 and 256 bytes.
	paddingLen := 16 + CryptoRandIntn(241) // 16..256

	noise := make([]byte, paddingLen)
	rand.Read(noise) //nolint:errcheck

	result := make([]byte, 4+len(data)+paddingLen)
	binary.BigEndian.PutUint32(result[:4], uint32(len(data)))
	copy(result[4:], data)
	copy(result[4+len(data):], noise)
	return result, nil
}

// StripNoise removes the noise padding added by AddNoise by reading the
// 4-byte big-endian length prefix.
func StripNoise(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for noise header")
	}
	origLen := binary.BigEndian.Uint32(data[:4])
	if int(origLen) > len(data)-4 {
		return nil, fmt.Errorf("invalid noise header length")
	}
	return data[4 : 4+origLen], nil
}

// MimicBrowserHeaders sets realistic browser headers on an HTTP request
// to make C2 traffic blend in with normal web browsing activity.
func MimicBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language",
		"en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding",
		"identity")
	req.Header.Set("Connection",
		"keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests",
		"1")
	req.Header.Set("Sec-Fetch-Dest",
		"document")
	req.Header.Set("Sec-Fetch-Mode",
		"navigate")
	req.Header.Set("Sec-Fetch-Site",
		"none")
	req.Header.Set("Sec-Fetch-User",
		"?1")
	req.Header.Set("Cache-Control",
		"max-age=0")
}

// nearestBucket returns the smallest bucket size that is >= dataLen.
// If dataLen exceeds all buckets, it rounds up to the next multiple
// of the largest bucket to maintain traffic shaping for large payloads.
func nearestBucket(dataLen int) int {
	for _, size := range PayloadSizeBuckets {
		if dataLen <= size {
			return size
		}
	}
	largest := PayloadSizeBuckets[len(PayloadSizeBuckets)-1]
	return ((dataLen + largest - 1) / largest) * largest
}
