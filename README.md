<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-light.svg">
  <img alt="Aquifer" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Go](https://img.shields.io/badge/language-Go-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Linux post-exploitation framework using kernel namespace isolation.**

Multi-channel C2 with polymorphic beacons and 36 stealth modules for deep host-level blending. Target keying prevents lab escape.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal.

</div>

---

## Quick Start

**Prerequisites:** Go 1.21+ (1.25+ for garble), Linux

```bash
git clone https://github.com/Real-Fruit-Snacks/Aquifer.git
cd Aquifer
make build
```

**Verify:**

```bash
make opsec-check     # No Go metadata leaks, high entropy, UPX scrubbed
make strings-check   # Compare regular vs garble builds
```

**Build profiles:** `make build` (dev), `make build-garble` (obfuscated), `make build-release` (garble + UPX + patching)

---

## Features

### Namespace Isolation

PID, Mount, Network, UTS, and Cgroup namespace isolation with veth pair routing and NAT masquerade. The implant operates in its own kernel-enforced sandbox with DNAT loopback routing for host connectivity.

```bash
# Two-stage execution: parent validates, re-execs into namespace child
# Parent sets up host-side veth pair, child operates inside isolation
```

### Multi-Channel C2

Four transport channels with automatic failover: HTTPS (domain fronting, JA3 randomization), DNS tunneling (TXT records), DNS-over-HTTPS, and Raw Layer 2 (AF_PACKET below netfilter/iptables).

```
HTTPS → DNS → DoH → Raw L2  (automatic cascading fallback)
```

### Polymorphic Beacons

18 rotating paths, 8 content-types, 13 user-agents, and randomized headers per cycle. JA3 fingerprint randomization per session. Traffic shaping mimics legitimate browsing patterns with cryptographic jitter.

### 36 Stealth Modules

eBPF cloaking hides PIDs in BPF maps. `memfd_create` + `execveat` for fileless execution. Kernel keyring stores secrets invisible to userspace forensics. Anti-dump regions block LiME/AVML. `io_uring` shared ring buffers bypass syscall monitoring.

```go
// pkg/stealth/ — process_blend, ebpf_cloak, memfd_exec, keyring_store,
// iouring, antidump, seccomp_notif, polymorphic, vmwrite_inject, ...
```

### Persistence

Beyond standard methods (cron, systemd, init.d, bashrc), the framework includes systemd generators, NSS modules, logrotate hooks, DHCP client hooks, APT hooks, audit dispatcher, binfmt_misc, modprobe hooks, NM dispatcher, and sysctl.d tunables.

### Guardrails

Hostname, CIDR range, MAC address, machine ID, canary file, and kill date guardrails prevent lab escape. Auto-terminates and cleans up if any guardrail fails.

---

## Architecture

```
.
├── cmd/
│   ├── implant/main.go              # Entry point (parent → namespace child)
│   └── test-implant/main.go         # Integration test implant
├── pkg/
│   ├── c2/                          # HTTPS, DNS, DoH, Raw L2, polymorphic
│   ├── config/config.go             # Compile-time configuration via -ldflags
│   ├── evasion/                     # VM/sandbox/EDR detection
│   ├── namespace/                   # Linux namespace management
│   ├── opsec/                       # Core dumps, anti-ptrace, masquerade
│   ├── stealth/                     # 36 stealth modules
│   └── tasking/                     # Task handler framework
├── c2server/                        # Python operator console (cmd2 + Rich)
├── scripts/
│   ├── integration_test.sh          # End-to-end C2 + implant test
│   └── patch_upx.py                 # UPX signature scrubber
├── Makefile                         # build, build-garble, build-release, opsec-check
└── Dockerfile
```

**Key patterns:** Two-stage execution (parent validates, child operates). Compile-time config via `-ldflags`. Transport failover cascade. Memory-first design with `ProtectedConfig` and deterministic shredding. Kernel-level hiding via namespace isolation + eBPF cloaking.

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Aquifer/security/advisories). 90-day responsible disclosure.

**Aquifer does not:**
- Scan for or exploit vulnerabilities (not initial access)
- Spray credentials or pass hashes (not lateral movement)
- Operate cross-platform (Linux namespace isolation by design)
- Defeat hardware security monitoring (TPM, HSM, IMA/EVM)

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
