# Changelog

All notable changes to Aquifer will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added
- Two-stage execution: parent pre-checks with re-exec into namespace child
- PID, Mount, Network, UTS, and Cgroup namespace isolation with veth pair routing
- HTTPS C2 transport with domain fronting and JA3 fingerprint randomization
- DNS C2 transport via TXT record exfiltration
- DNS-over-HTTPS C2 transport for restrictive networks
- Raw Layer 2 Ethernet C2 transport below netfilter/iptables
- Polymorphic beacons (18 paths, 8 content-types, 13 user-agents, randomized headers)
- Traffic shaping mimicking legitimate browsing patterns with cryptographic jitter
- Automatic transport failover (HTTPS -> DNS -> DoH -> Raw L2)
- ECDH P-256 key exchange with AES-256-GCM encrypted payloads
- ProtectedConfig with XOR-encrypted C2 URLs and session keys at rest
- 36 stealth modules (eBPF cloaking, fileless execution, kernel keyring, io_uring, anti-dump)
- Process masquerade impersonating accounts-daemon with /proc/self/mem zeroing
- Target keying guardrails (hostname, CIDR, MAC, machine ID, canary, kill date)
- Advanced persistence (systemd generators, NSS modules, logrotate, DHCP, APT, audit hooks)
- VM/sandbox detection with EDR behavioral adaptation
- Python C2 operator console (cmd2 + Rich, Catppuccin Mocha theme)
- C2 server with HTTPS and DNS listeners, SQLite backend, polymorphic routing
- Integration test suite (C2 server + test implant on localhost)
- Build targets: standard, ARM64, garble obfuscated, production release
- OPSEC verification suite (strings check, gobuild check, opsec check)
