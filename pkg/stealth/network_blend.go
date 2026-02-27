package stealth

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// FakeServiceBanners maps service names to their expected greeting banners.
var FakeServiceBanners = map[string]string{
	"sshd":         "SSH-2.0-OpenSSH_9.6p1 Debian-1\r\n",
	"nginx":        "HTTP/1.1 400 Bad Request\r\nServer: nginx/1.24.0\r\nConnection: close\r\n\r\n",
	"apache2":      "HTTP/1.1 400 Bad Request\r\nServer: Apache/2.4.58 (Debian)\r\nConnection: close\r\n\r\n",
	"smtp":         "220 mail.internal.local ESMTP Postfix (Debian/GNU)\r\n",
	"mysql":        "\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36", // MySQL 8.0.36 greeting prefix
	"redis-server": "-ERR unknown command\r\n",
}

// NetworkBlender maintains fake network connections matching a masqueraded service.
type NetworkBlender struct {
	serviceName string
	conns       []net.Conn
	listeners   []net.Listener
	done        chan struct{}
	mu          sync.Mutex
	connWg      sync.WaitGroup // tracks in-flight connection handler goroutines
}

// NewNetworkBlender creates a blender for the specified service.
func NewNetworkBlender(serviceName string) *NetworkBlender {
	return &NetworkBlender{
		serviceName: serviceName,
		done:        make(chan struct{}),
	}
}

// Start begins maintaining fake connections and network presence.
func (nb *NetworkBlender) Start() {
	// Open a listener on the expected port and respond with the right banner
	if port, ok := ServicePorts[nb.serviceName]; ok {
		nb.startBannerResponder(port)
	}

	// Maintain idle connections typical for this service
	go nb.maintainIdleConnections()

	// Generate expected DNS traffic
	go nb.dnsNoise()
}

// Stop tears down all fake connections and listeners.
func (nb *NetworkBlender) Stop() {
	select {
	case <-nb.done:
		return
	default:
		close(nb.done)
	}

	nb.mu.Lock()
	// Close listeners first — unblocks Accept() in banner responder goroutines
	for _, l := range nb.listeners {
		l.Close()
	}
	nb.listeners = nil

	for _, c := range nb.conns {
		c.Close()
	}
	nb.conns = nil
	nb.mu.Unlock()

	// Wait for all in-flight connection handlers to drain
	nb.connWg.Wait()
}

// startBannerResponder opens a listening socket and responds to probes with
// the correct service banner. This makes port scanners and service detection
// (nmap -sV) identify us as the masqueraded service.
func (nb *NetworkBlender) startBannerResponder(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return
	}

	nb.mu.Lock()
	nb.listeners = append(nb.listeners, listener)
	nb.mu.Unlock()

	banner := FakeServiceBanners[nb.serviceName]

	go func() {
		for {
			select {
			case <-nb.done:
				return
			default:
			}

			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-nb.done:
					return
				default:
					continue
				}
			}

			nb.connWg.Add(1)
			go func(c net.Conn) {
				defer nb.connWg.Done()
				defer c.Close()
				if banner != "" {
					c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					c.Write([]byte(banner))
				}
				// For SSH, wait for client banner first (SSH protocol expects server sends first)
				// For HTTP, read a bit then close
				buf := make([]byte, 1024)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				c.Read(buf)
			}(conn)
		}
	}()
}

// maintainIdleConnections keeps TCP connections open to targets expected
// for this service type. Shows up in ss/netstat as expected connections.
func (nb *NetworkBlender) maintainIdleConnections() {
	targets := idleTargetsForService(nb.serviceName)
	if len(targets) == 0 {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-nb.done:
			return
		case <-ticker.C:
			nb.mu.Lock()
			// Prune dead connections
			alive := nb.conns[:0]
			for _, c := range nb.conns {
				one := make([]byte, 1)
				c.SetReadDeadline(time.Now())
				_, err := c.Read(one)
				if err != nil && !isTimeout(err) {
					c.Close()
					continue
				}
				alive = append(alive, c)
			}
			nb.conns = alive

			// Reconnect dropped targets
			for _, target := range targets {
				found := false
				for _, c := range nb.conns {
					if c.RemoteAddr().String() == target {
						found = true
						break
					}
				}
				if !found {
					conn, err := net.DialTimeout("tcp", target, 2*time.Second)
					if err == nil {
						setTCPKeepalive(conn)
						nb.conns = append(nb.conns, conn)
					}
				}
			}
			nb.mu.Unlock()
		}
	}
}

// dnsNoise periodically resolves domains expected for the masqueraded service.
func (nb *NetworkBlender) dnsNoise() {
	domains := dnsDomainsForService(nb.serviceName)
	if len(domains) == 0 {
		return
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	idx := 0
	for {
		select {
		case <-nb.done:
			return
		case <-ticker.C:
			domain := domains[idx%len(domains)]
			net.LookupHost(domain)
			idx++
		}
	}
}

func idleTargetsForService(service string) []string {
	switch service {
	case "nginx", "apache2":
		return []string{"127.0.0.1:8080", "127.0.0.1:8443"}
	case "systemd-resolved":
		return []string{"127.0.0.1:53"}
	default:
		return nil
	}
}

func dnsDomainsForService(service string) []string {
	switch service {
	case "nginx", "apache2":
		return []string{"api.internal", "backend.local", "cdn.internal"}
	case "systemd-resolved":
		return []string{"google.com", "cloudflare.com", "amazonaws.com"}
	case "sshd":
		return []string{"ldap.internal", "kerberos.internal"}
	default:
		return []string{"ntp.ubuntu.com", "archive.ubuntu.com"}
	}
}

func setTCPKeepalive(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
