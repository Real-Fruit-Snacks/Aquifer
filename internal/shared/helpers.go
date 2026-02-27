// Package shared provides utility functions used by both the production
// implant and the test-implant binaries.
package shared

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// GetHostname returns the system hostname, or "" on error.
func GetHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// GetUsername returns the current user's name, or "" on error.
func GetUsername() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// GetUID returns the current user's numeric UID, or -1 on error.
func GetUID() int {
	u, err := user.Current()
	if err != nil {
		return -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return uid
}

// GatherNetInfo returns network interface information for all non-loopback,
// up interfaces. Returns nil on error.
func GatherNetInfo() []config.NetInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []config.NetInfo
	for _, iface := range ifaces {
		// Skip loopback and down interfaces.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		addrStrs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}

		ni := config.NetInfo{
			Name:  iface.Name,
			Addrs: addrStrs,
			MAC:   iface.HardwareAddr.String(),
		}
		result = append(result, ni)
	}

	return result
}

// SleepWithShutdown sleeps for the jittered duration but returns early
// if shutdownCh is closed.
func SleepWithShutdown(base time.Duration, jitter float64, shutdownCh <-chan struct{}) {
	d := CalculateSleep(base, jitter)
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-shutdownCh:
	}
}

// CalculateSleep adds cryptographically random jitter to the base duration.
// The result falls in the range [base*(1-jitter), base*(1+jitter)].
func CalculateSleep(base time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return base
	}
	if jitter > 1.0 {
		jitter = 1.0
	}
	b := make([]byte, 8)
	_, _ = crand.Read(b)
	randFloat := float64(binary.BigEndian.Uint64(b)) / float64(math.MaxUint64)
	offset := float64(base) * jitter * (randFloat*2 - 1)
	return base + time.Duration(offset)
}
