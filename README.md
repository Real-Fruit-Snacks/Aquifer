<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-light.svg">
  <img alt="Aquifer" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-dark.svg" width="100%">
</picture>

> [!IMPORTANT]
> **Linux post-exploitation framework using kernel namespace isolation.** Multi-channel C2 with polymorphic beacons and 36 stealth modules for deep host-level blending. Target keying prevents lab escape.

> *An aquifer is groundwater hidden beneath the surface — invisible from above, only reached by drilling. Felt fitting for an implant that lives below the netfilter layer, inside its own kernel-enforced sandbox, hidden from userspace forensics.*

---

## §1 / Premise

Aquifer is a **post-exploitation** framework, not initial access. It assumes a foothold already exists and focuses on what comes next — hiding deeper than userspace tooling can see, and surviving against EDR, DFIR, and active hunt teams on Linux hosts.

The implant operates inside its own **PID/Mount/Network/UTS/Cgroup namespaces** with a veth pair to the host network and DNAT loopback routing for C2. It hides PIDs in **eBPF maps**, executes fileless via **`memfd_create` + `execveat`**, stores secrets in the **kernel keyring** (invisible to userspace), and uses **`io_uring`** shared ring buffers to bypass syscall monitoring. Anti-dump regions block LiME and AVML.

Configuration bakes at compile time via `-ldflags` — no runtime args, no environment lookups, no secrets on disk. Hostname / CIDR / MAC / machine-ID / canary / kill-date guardrails auto-terminate and clean up on lab escape.

---

## §2 / Specs

| KEY        | VALUE                                                                       |
|------------|-----------------------------------------------------------------------------|
| ISOLATION  | **5 namespaces** — PID · Mount · Network · UTS · Cgroup · veth + NAT masquerade |
| CHANNELS   | **HTTPS · DNS · DoH · Raw L2** with automatic cascading failover            |
| BEACONS    | **18 paths · 8 content-types · 13 user-agents** rotating per cycle · JA3 random |
| STEALTH    | **36 modules** — eBPF cloaking · memfd exec · keyring · io_uring · anti-dump |
| BUILD      | `garble` obfuscation + `UPX` packing + signature scrubbing in release pipeline |
| STACK      | **Go 1.21+** (1.25+ for garble) · Linux only · Python operator console      |

Architecture in §5 below.

---

## §3 / Quickstart

```bash
# Prerequisites: Go 1.21+ (1.25+ for garble), Linux
git clone https://github.com/Real-Fruit-Snacks/Aquifer && cd Aquifer
make build
```

```bash
# Build profiles
make build           # dev: stock Go, debug symbols
make build-garble    # obfuscated: garble strips identifiers
make build-release   # garble + UPX + signature patching

# Verification
make opsec-check     # No Go metadata leaks · high entropy · UPX scrubbed
make strings-check   # Compare regular vs garble builds side-by-side
```

```bash
# Two-stage execution
# Parent process validates guardrails, sets up host-side veth pair
# Re-execs into namespace child which operates inside isolation
sudo ./aquifer
```

---

## §4 / Reference

```
ISOLATION                                               # five namespaces

  PID           Process ID isolation · invisible to host ps
  MOUNT         Filesystem view isolation
  NETWORK       Own network stack · veth pair to host · NAT masquerade
  UTS           Hostname/domainname isolation
  CGROUP        Resource limits invisible from host

C2 CHANNELS                                             # automatic failover

  HTTPS         Domain fronting · JA3 randomization · 18 rotating paths
                8 content-types · 13 user-agents · per-session fingerprint
  DNS           TXT record tunneling · query-amplified
  DoH           DNS-over-HTTPS via public resolvers
  RAW L2        AF_PACKET below netfilter / iptables — invisible to filters

  → fallback chain: HTTPS → DNS → DoH → Raw L2

STEALTH MODULES                                         # 36 total

  PROCESS       process_blend · ebpf_cloak · memfd_exec · keyring_store
  EXEC          io_uring (shared ring buffers) · vmwrite_inject · seccomp_notif
  ANTI-FORENSIC antidump (LiME/AVML blocking) · polymorphic
  …             pkg/stealth/ — see source for full module list

PERSISTENCE                                             # beyond the obvious

  STANDARD      cron · systemd · init.d · bashrc
  ESOTERIC      systemd generators · NSS modules · logrotate hooks
                DHCP client hooks · APT hooks · audit dispatcher
                binfmt_misc · modprobe hooks · NM dispatcher · sysctl.d

GUARDRAILS                                              # lab escape prevention

  HOSTNAME      Refuse to run if hostname doesn't match
  CIDR          IP must be in target network range
  MAC           Network adapter MAC fingerprint
  MACHINE-ID    /etc/machine-id check
  CANARY        Specific file must exist on host
  KILL DATE     Auto-terminate after timestamp · cleanup on exit

BUILD TARGETS

  make build               Dev build · stock Go
  make build-garble        Obfuscated · garble strips identifiers
  make build-release       garble + UPX + signature scrubbing
  make opsec-check         Verify no Go metadata leaks
  make strings-check       Compare regular vs garble side-by-side
```

---

## §5 / Architecture

```
.
├── cmd/
│   ├── implant/main.go              # Entry point (parent → namespace child)
│   └── test-implant/main.go         # Integration test implant
├── pkg/
│   ├── c2/                          # HTTPS, DNS, DoH, Raw L2, polymorphic
│   ├── config/config.go             # Compile-time config via -ldflags
│   ├── evasion/                     # VM/sandbox/EDR detection
│   ├── namespace/                   # Linux namespace management
│   ├── opsec/                       # Core dumps, anti-ptrace, masquerade
│   ├── stealth/                     # 36 stealth modules
│   └── tasking/                     # Task handler framework
├── c2server/                        # Python operator console (cmd2 + Rich)
├── scripts/integration_test.sh
├── scripts/patch_upx.py             # UPX signature scrubber
└── Makefile                         # build · build-garble · build-release · opsec-check
```

**Key patterns:** Two-stage execution (parent validates guardrails, re-execs into namespace child). Compile-time config via `-ldflags`. Transport failover cascade. Memory-first design with `ProtectedConfig` and deterministic shredding. Kernel-level hiding via namespace isolation + eBPF cloaking + io_uring.

**Aquifer does not:** scan or exploit vulnerabilities (not initial access) · spray credentials or pass hashes (not lateral movement) · operate cross-platform (Linux namespace isolation by design) · defeat hardware security monitoring (TPM, HSM, IMA/EVM).

---

## §6 / Authorization

Aquifer is built for engagements that are scoped, written, and signed. **Authorization required** — designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal.

Vulnerabilities go through [private security advisories](https://github.com/Real-Fruit-Snacks/Aquifer/security/advisories), never public issues. **90-day responsible disclosure.**

[License: MIT](LICENSE) · Part of [Real-Fruit-Snacks](https://github.com/Real-Fruit-Snacks) — building offensive security tools, one wave at a time.
