<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-light.svg">
  <img alt="Aquifer" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Aquifer/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Go](https://img.shields.io/badge/language-Go-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Linux post-exploitation framework using kernel namespace isolation**

Kernel namespace isolation turns the OS against its own defenses. Multi-channel C2 with polymorphic beacons keeps traffic invisible. 36 stealth modules handle everything from eBPF cloaking to fileless execution.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Stealth Modules](#stealth-modules) • [C2 Transport](#c2-transport) • [Architecture](#architecture) • [Configuration](#configuration) • [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**Namespace Isolation**
PID, Mount, Network, UTS, and Cgroup namespace isolation with veth pair routing and NAT masquerade. The implant operates in its own kernel-enforced sandbox with DNAT loopback routing for host connectivity.

**Multi-Channel C2**
HTTPS primary with domain fronting. DNS tunneling fallback via TXT records. DNS-over-HTTPS for restrictive networks. Raw Layer 2 Ethernet frames below netfilter/iptables for environments where everything else fails.

**Polymorphic Beacons**
18 rotating paths, 8 content-types, 13 user-agents, and randomized headers per cycle. JA3 fingerprint randomization per session. Traffic shaping mimics legitimate browsing patterns with cryptographic jitter.

**Memory Protection**
`ProtectedConfig` encrypts C2 URLs and session keys at rest with XOR rekeying each cycle. `[]byte` API with deterministic shredding after use. `DisableKeepAlives` + `FlushConnections()` + `runtime.GC()` clears transient state.

</td>
<td width="50%">

**Process Masquerade**
Kernel-level argv and `/proc/[pid]/comm` rewrite impersonating `accounts-daemon`. Direct `/proc/self/mem` zeroing of the environ region defeats `cat /proc/PID/environ`. `GOMAXPROCS(1)` reduces visible OS threads.

**36 Stealth Modules**
eBPF cloaking hides PIDs in BPF maps. `memfd_create` + `execveat` for fileless execution. Kernel keyring stores secrets invisible to userspace forensics. Anti-dump regions block LiME/AVML. `io_uring` shared ring buffers bypass syscall monitoring.

**Target Keying**
Hostname, CIDR range, MAC address, machine ID, canary file, and kill date guardrails prevent lab escape. The implant auto-terminates and cleans up if any guardrail fails. No accidental detonation outside the target environment.

**Advanced Persistence**
Systemd generators run before all units at boot. NSS modules trigger on any DNS or user lookup. Logrotate, DHCP, APT, and audit dispatcher hooks fire on routine system events. `binfmt_misc` and modprobe hooks cover the rest.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>Go</td>
<td>1.21+</td>
<td>Compiler toolchain (1.25+ for garble obfuscation)</td>
</tr>
<tr>
<td>Platform</td>
<td>Linux</td>
<td>Kernel namespace support required</td>
</tr>
<tr>
<td>garble</td>
<td>latest</td>
<td>Optional, for obfuscated builds</td>
</tr>
<tr>
<td>UPX</td>
<td>latest</td>
<td>Optional, for release compression</td>
</tr>
<tr>
<td>Python</td>
<td>3.9+</td>
<td>C2 operator console</td>
</tr>
</table>

### Build

```bash
# Clone repository
git clone https://github.com/Real-Fruit-Snacks/Aquifer.git
cd Aquifer

# Development build (stripped, static)
make build

# ARM64 cross-compile
make build-arm64

# Obfuscated build (requires garble)
make build-garble

# Production release (garble + UPX + signature patching)
make build-release

# Full CI check (vet + fmt + build)
make check
```

Output binaries are placed in `build/`.

### Verification

```bash
# Check for Go metadata leaks
make strings-check

# Compare regular vs garble builds
make gobuild-check

# Run OPSEC verification suite on release binary
make opsec-check
```

The OPSEC check verifies: no Go module paths in binary strings, no C2 URLs in plaintext, no Go runtime symbol references, UPX signatures fully scrubbed (via `scripts/patch_upx.py`), no Go section headers (gosymtab, gopclntab, go.buildinfo), and high binary entropy confirming compression/encryption.

---

## Execution Flow

### 1. Parent Stage

Runs pre-namespace checks before isolation:

- Target-keying guardrails (hostname, IP range, machine ID, canary file, kill date)
- Environment fingerprinting (VM/sandbox/debugger detection)
- EDR detection and behavioral adjustment
- OPSEC hardening (disable core dumps, anti-ptrace, process masquerade)

### 2. Namespace Bootstrap

Re-execs into isolated PID + Mount + Network + UTS + Cgroup namespaces with veth pair, NAT masquerade, and DNAT loopback routing for host connectivity. Parent sets up host-side veth pair, then waits for the child process.

Parent process handles SIGTERM/SIGINT: kills child, cleans up host-side network artifacts (veth, iptables, sysctl), removes cgroup directories, then exits. Normal child exit also triggers full host-side cleanup before the parent terminates.

### 3. Child Stage

Operational loop inside namespaces:

- Process hiding and memory protection
- ECDH key exchange with C2 server
- Beacon loop with jittered sleep and exponential backoff
- Task execution with encrypted result delivery
- Signal-driven graceful shutdown with full cleanup (network artifacts, cgroups, workspace, persistence)

---

## C2 Transport

| Channel | Description | Use Case |
|---------|-------------|----------|
| HTTPS | Primary channel with domain fronting support | Standard egress |
| DNS | TXT record exfiltration | Firewall bypass |
| DoH | DNS-over-HTTPS | Restrictive networks |
| Raw L2 | AF_PACKET raw Ethernet frames below netfilter/iptables | Below firewall inspection |

### Transport Features

<table>
<tr>
<th>Feature</th>
<th>Description</th>
</tr>
<tr>
<td>JA3 randomization</td>
<td>Unique TLS fingerprint per session</td>
</tr>
<tr>
<td>Traffic shaping</td>
<td>Mimics legitimate browsing patterns</td>
</tr>
<tr>
<td>Polymorphic intervals</td>
<td>Cryptographic jitter on beacon timing</td>
</tr>
<tr>
<td>Server-side overrides</td>
<td>Sleep and jitter tuning via <code>BeaconResponse</code></td>
</tr>
<tr>
<td>Automatic failover</td>
<td>Cascading transport channel fallback (HTTPS -> DNS -> DoH -> Raw L2)</td>
</tr>
<tr>
<td>Deterministic routing</td>
<td><code>X-Request-ID</code> header for O(1) session resolution</td>
</tr>
</table>

---

## C2 Server

Python operator console for managing implants. Built with cmd2 + Rich using Catppuccin Mocha theme.

```bash
# Install dependencies
pip install -r c2server/requirements.txt

# Launch the operator console
python3 -m c2server --db c2.db --keys server_keys.pem
```

### Components

<table>
<tr>
<th>Component</th>
<th>Description</th>
</tr>
<tr>
<td>ECDH P-256</td>
<td>Persisted server key exchange matching Go implant protocol exactly</td>
</tr>
<tr>
<td>AES-256-GCM</td>
<td>Encrypted beacon traffic with traffic shaping</td>
</tr>
<tr>
<td>HTTPS listener</td>
<td>Starlette + uvicorn with TLS 1.2+ hardening, O(1) session lookup via X-Request-ID</td>
</tr>
<tr>
<td>DNS listener</td>
<td>TXT record C2 with base32 encoding and response truncation</td>
</tr>
<tr>
<td>Polymorphic routing</td>
<td>18 rotating beacon paths + default path</td>
</tr>
<tr>
<td>SQLite backend</td>
<td>Sessions, tasks, results, loot, listeners (WAL mode, per-thread connections)</td>
</tr>
<tr>
<td>Rich CLI</td>
<td>Catppuccin Mocha themed tables, panels, and status display</td>
</tr>
<tr>
<td>Context switching</td>
<td>Main context (sessions/listeners/loot) and implant context (shell/upload/persist/etc)</td>
</tr>
</table>

### Operator Commands

**Main context:** `sessions`, `interact`, `listeners`, `loot`, `generate`

**Implant context:** `shell`, `upload`, `download`, `ls`, `ps`, `netstat`, `ifconfig`, `whoami`, `sysinfo`, `persist`, `cleanup`, `sleep`, `kill`, `info`, `tasks`, `results`, `back`

---

## Stealth Modules

36 modules for deep host-level blending (`pkg/stealth/`):

<table>
<tr>
<th>Module</th>
<th>File</th>
<th>Description</th>
</tr>
<tr><td>Argv masquerade</td><td><code>process_blend.go</code></td><td>Full <code>/proc/[pid]</code> profile mimicry (FDs, CWD, OOM score)</td></tr>
<tr><td>Process genealogy</td><td><code>genealogy.go</code></td><td>Double-fork re-parenting to PID 1</td></tr>
<tr><td>PID manipulation</td><td><code>pid_manip.go</code></td><td>Fork-burn PIDs inside PID namespace to avoid PID 1</td></tr>
<tr><td>PID recycling defense</td><td><code>pid_recycle.go</code></td><td>Land in dense PID regions matching system services</td></tr>
<tr><td>eBPF cloaking</td><td><code>ebpf_cloak.go</code></td><td>BPF map-based PID hide list (stub filter, map functional)</td></tr>
<tr><td>Environment cloning</td><td><code>env_clone.go</code></td><td>Clone env vars from live target process</td></tr>
<tr><td>Network blending</td><td><code>network_blend.go</code></td><td>Fake connections and service banner responders</td></tr>
<tr><td>Decoy processes</td><td><code>decoy.go</code></td><td>Spawn and manage decoy service processes</td></tr>
<tr><td>History obfuscation</td><td><code>history.go</code></td><td>Shell history manipulation and RC file injection</td></tr>
<tr><td>Cgroup camouflage</td><td><code>cgroup_camo.go</code></td><td>Mimic systemd service cgroup hierarchy</td></tr>
<tr><td>Namespace hiding</td><td><code>ns_hide.go</code></td><td>Container ID spoofing and namespace obfuscation</td></tr>
<tr><td>Nested namespaces</td><td><code>ns_layers.go</code></td><td>Outer decoy + inner operational namespace</td></tr>
<tr><td>Group blending</td><td><code>group_blend.go</code></td><td>Match supplementary groups of target service</td></tr>
<tr><td>Capability management</td><td><code>capabilities.go</code></td><td>Ambient capability escalation</td></tr>
<tr><td>Syscall proxying</td><td><code>syscall_proxy.go</code></td><td>Ptrace-based syscall injection into target processes</td></tr>
<tr><td>Memory spoofing</td><td><code>mem_spoof.go</code></td><td><code>/proc/[pid]/maps</code> region name spoofing via PR_SET_VMA</td></tr>
<tr><td>TCP/IP fingerprinting</td><td><code>tcpip_spoof.go</code></td><td>Kernel TCP stack parameter spoofing</td></tr>
<tr><td>D-Bus blending</td><td><code>dbus_blend.go</code></td><td>Register as legitimate D-Bus service</td></tr>
<tr><td>lsof misdirection</td><td><code>lsof_spoof.go</code></td><td>FD spoofing via bind mounts</td></tr>
<tr><td>Benign strings</td><td><code>benign_strings.go</code></td><td>Inject legitimate-looking strings into binary</td></tr>
<tr><td>Seccomp awareness</td><td><code>seccomp_aware.go</code></td><td>Detect seccomp filters and adapt syscall behavior</td></tr>
<tr><td>Socket inheritance</td><td><code>socket_inherit.go</code></td><td>Inherit sockets from target service for blending</td></tr>
<tr><td>Timestamp freezing</td><td><code>ts_freeze.go</code></td><td>tmpfs timestamp manipulation for anti-forensics</td></tr>
<tr><td>Polymorphic engine</td><td><code>polymorphic.go</code></td><td>XOR-encrypt data regions when analysis detected</td></tr>
<tr><td>Exe link spoofing</td><td><code>exe_spoof.go</code></td><td><code>/proc/self/exe</code> manipulation via PR_SET_MM_EXE_FILE</td></tr>
<tr><td>Seccomp forensic block</td><td><code>seccomp_notif.go</code></td><td>BPF filter blocks ptrace/perf_event/process_vm_readv</td></tr>
<tr><td>Kernel keyring storage</td><td><code>keyring_store.go</code></td><td>Store secrets in kernel memory (invisible to memory forensics)</td></tr>
<tr><td>io_uring covert I/O</td><td><code>iouring.go</code></td><td>Shared ring buffer I/O bypassing syscall-level monitoring</td></tr>
<tr><td>Anti-dump regions</td><td><code>antidump.go</code></td><td>MADV_DONTDUMP and MADV_WIPEONFORK memory protection</td></tr>
<tr><td>Cross-process injection</td><td><code>vmwrite_inject.go</code></td><td>process_vm_writev shellcode injection without ptrace</td></tr>
<tr><td>Userfaultfd decoy</td><td><code>uffd_decoy.go</code></td><td>Serve fake memory pages to forensic tools via page fault handler</td></tr>
<tr><td>Kernel tunable manipulation</td><td><code>ktune.go</code></td><td>Disable kprobes, ftrace, perf via /proc/sys and /sys/kernel</td></tr>
<tr><td>Abstract unix sockets</td><td><code>abstract_sock.go</code></td><td>Filesystem-free IPC via abstract namespace sockets</td></tr>
<tr><td>Fileless execution</td><td><code>memfd_exec.go</code></td><td>memfd_create + execveat for diskless ELF execution</td></tr>
<tr><td>eBPF program pinning</td><td><code>bpf_pin.go</code></td><td>Persistent kernel hooks via bpffs that survive process death</td></tr>
<tr><td>Landlock self-sandboxing</td><td><code>landlock_cage.go</code></td><td>Unprivileged Landlock LSM profiles for camouflage</td></tr>
</table>

---

## Evasion

- VM/sandbox detection (hypervisor, timing, MAC OUI, BIOS strings)
- EDR product detection with behavioral adaptation
- Auditd rule parsing and syscall avoidance
- Namespace intrusion detection (nsenter monitoring)
- Filesystem watch detection (inotify/fanotify/audit)
- `/proc` entry hiding and self-unlinking
- eBPF program detection and enumeration

---

## OPSEC

- **Guardrails** -- Target-keying prevents lab escape (hostname, CIDR, machine ID, canary, kill date)
- **Kill switch** -- Auto-cleanup on forensic tool detection or user login
- **Memory encryption** -- Session keys XOR-encrypted at rest, decrypted into short-lived buffers
- **Core dump prevention** -- RLIMIT_CORE=0 and PR_SET_DUMPABLE=0
- **Anti-ptrace** -- Blocks debugger attachment
- **Process masquerade** -- Kernel-level argv rewrite impersonating `accounts-daemon`
- **Environment scrubbing** -- `os.Clearenv()` + direct `/proc/self/mem` zeroing of environ region
- **Thread count reduction** -- `GOMAXPROCS(1)` minimizes OS threads visible in `/proc/PID/status`
- **I/O noise injection** -- Random procfs reads between beacon cycles break `/proc/PID/io` correlation
- **Heap protection** -- `ProtectedConfig` encrypts C2 URLs/keys at rest with XOR rekeying each cycle; `GetC2ServersBytes()` returns `[]byte` slices that callers shred after use; transport and config blobs destroyed on shutdown
- **Polymorphic beacons** -- 18 rotating paths, 8 content-types, 13 user-agents, randomized headers per cycle (applied to both beacon loop and initial registration)
- **Crypto hygiene** -- ECDH client public key shredded after registration; session key stack residue eliminated; rekey failure tracking with graceful shutdown after entropy exhaustion; bias-free `CryptoRandIntn` via rejection sampling
- **Memory-mapped loader** -- In-memory ELF execution without disk artifacts
- **Anti-forensics** -- Timestomping, binary self-deletion, full cleanup on exit
- **Kernel keyring** -- Secrets stored in kernel memory, invisible to userspace forensics
- **Anti-dump** -- MADV_DONTDUMP/WIPEONFORK prevents memory capture by LiME/AVML
- **NSS safety guard** -- Refuses to modify nsswitch.conf if the NSS .so doesn't exist on disk (prevents breaking host DNS)
- **Host-side cleanup** -- Removes veth interfaces, iptables rules, sysctl overrides, and cgroup directories on exit
- **Parent signal handler** -- SIGTERM/SIGINT caught by parent process to ensure host artifacts are cleaned even if parent is killed directly
- **Sysctl restoration** -- Removing sysctl.d persistence restores runtime kernel parameters (ptrace_scope, kptr_restrict, ftrace, BPF, perf) without requiring reboot

---

## Advanced Persistence

Beyond standard persistence (cron, systemd, init.d, bashrc), the framework includes advanced mechanisms:

<table>
<tr>
<th>Method</th>
<th>Description</th>
</tr>
<tr><td>Systemd generators</td><td><code>/etc/systemd/system-generators/</code> -- runs before all units at boot</td></tr>
<tr><td>NSS modules</td><td><code>/etc/nsswitch.conf</code> injection -- triggered by any DNS/user lookup</td></tr>
<tr><td>Logrotate hooks</td><td><code>/etc/logrotate.d/</code> post-rotate scripts -- periodic execution</td></tr>
<tr><td>DHCP client hooks</td><td><code>/etc/dhcp/dhclient-exit-hooks.d/</code> -- runs on network events</td></tr>
<tr><td>APT hooks</td><td><code>/etc/apt/apt.conf.d/</code> -- executes on package operations</td></tr>
<tr><td>Audit dispatcher</td><td><code>/etc/audit/plugins.d/</code> -- runs on audit events</td></tr>
<tr><td>binfmt_misc</td><td><code>/etc/binfmt.d/</code> -- triggers on specific file execution</td></tr>
<tr><td>Modprobe hooks</td><td><code>/etc/modprobe.d/</code> install commands -- runs on module load</td></tr>
<tr><td>NM dispatcher</td><td><code>/etc/NetworkManager/dispatcher.d/</code> -- runs on network state changes</td></tr>
<tr><td>Sysctl.d</td><td><code>/etc/sysctl.d/</code> -- kernel tunables applied at boot (disables tracing/debugging)</td></tr>
</table>

---

## Wire Protocol

The Go implant and Python C2 server communicate via JSON-encoded, AES-256-GCM encrypted payloads.

| Field | Go JSON Tag | Python Key | Notes |
|-------|-------------|------------|-------|
| Sleep override | `json:"sleep"` | `"sleep"` | Seconds (int) |
| Jitter override | `json:"jitter"` | `"jitter"` | 0.0-1.0 (float64) |
| Task result ID | `json:"id"` | `"id"` | UUID string |
| Task result output | `json:"output"` | `"output"` | Go `[]byte` -> base64 in JSON, Python base64-decodes |
| Shutdown flag | `json:"shutdown"` | `"shutdown"` | Boolean |

CLI task arguments are serialized as `map[string]string` -- all values must be strings on the wire.

---

## Architecture

```
.
├── cmd/
│   ├── implant/main.go              Entry point (parent -> namespace child)
│   └── test-implant/main.go         Integration test implant (no namespaces)
├── pkg/
│   ├── c2/                          C2 transports
│   │   ├── dns.go                   DNS TXT record transport
│   │   ├── doh.go                   DNS-over-HTTPS transport
│   │   ├── fronting.go              Domain fronting
│   │   ├── https.go                 Primary HTTPS transport
│   │   ├── ja3.go                   JA3 fingerprint randomization
│   │   ├── polymorphic_beacon.go    Polymorphic beacon encoding
│   │   ├── protocol.go              Beacon encode/decode
│   │   ├── rawl2.go                 Raw Layer 2 Ethernet transport
│   │   ├── traffic_shape.go         Traffic pattern shaping
│   │   └── transport.go             Transport manager with failover
│   ├── config/config.go             Compile-time configuration
│   ├── evasion/                     Detection and evasion
│   ├── namespace/                   Linux namespace management
│   ├── opsec/                       Operational security
│   ├── stealth/                     36 stealth modules
│   ├── tasking/                     Task handler framework
│   └── version/                     Build version metadata
├── internal/
│   └── shared/                      Internal shared utilities
├── scripts/
│   ├── integration_test.sh          End-to-end C2 + implant test
│   └── patch_upx.py                 UPX signature scrubber
├── c2server/                        Python C2 operator console
│   ├── __main__.py                  Entry point
│   ├── crypto/                      ECDH, AES-GCM, traffic shaping
│   ├── protocol/                    Beacon encode/decode, polymorphic paths
│   ├── models/                      SQLite models (sessions, tasks, loot)
│   ├── listeners/                   HTTPS + DNS listeners
│   ├── cli/                         cmd2 app, Rich theme, commands
│   └── requirements.txt             Python dependencies
├── docs/                            GitHub Pages + assets
│   ├── index.html                   Project landing page
│   └── assets/
│       ├── logo-dark.svg            Logo for dark theme
│       └── logo-light.svg           Logo for light theme
├── Makefile                         Build targets
├── Dockerfile                       Container build
├── go.mod
└── go.sum
```

### Key Patterns

<table>
<tr>
<th>Pattern</th>
<th>Implementation</th>
</tr>
<tr>
<td>Two-stage execution</td>
<td>Parent runs checks, re-execs into namespace child</td>
</tr>
<tr>
<td>Compile-time config</td>
<td>All settings baked via <code>-ldflags</code>, no runtime config files</td>
</tr>
<tr>
<td>Transport failover</td>
<td>HTTPS -> DNS -> DoH -> Raw L2 cascade</td>
</tr>
<tr>
<td>Memory-first</td>
<td><code>ProtectedConfig</code>, <code>[]byte</code> APIs, deterministic shredding</td>
</tr>
<tr>
<td>Kernel-level hiding</td>
<td>Namespace isolation + eBPF cloaking + procfs manipulation</td>
</tr>
</table>

---

## Configuration

All configuration is compile-time via `pkg/config/config.go`. Override defaults with `-ldflags` at build time:

<table>
<tr>
<th>Field</th>
<th>Default</th>
<th>Description</th>
</tr>
<tr>
<td><code>C2Servers</code></td>
<td><code>https://127.0.0.1:8443/api/v1/beacon</code></td>
<td>Primary HTTPS endpoints</td>
</tr>
<tr>
<td><code>DNSDomains</code></td>
<td><code>ns1.example.com</code></td>
<td>DNS fallback domains</td>
</tr>
<tr>
<td><code>CallbackInterval</code></td>
<td>30s</td>
<td>Beacon interval</td>
</tr>
<tr>
<td><code>Jitter</code></td>
<td>0.2</td>
<td>Sleep jitter (0.0-1.0)</td>
</tr>
<tr>
<td><code>MasqueradeName</code></td>
<td><code>accounts-daemon</code></td>
<td>Process name disguise</td>
</tr>
<tr>
<td><code>KillDate</code></td>
<td>+30 days</td>
<td>Auto-expiry date</td>
</tr>
<tr>
<td><code>SandboxEvasion</code></td>
<td>true</td>
<td>VM/sandbox detection</td>
</tr>
<tr>
<td><code>EDRAwareness</code></td>
<td>true</td>
<td>EDR behavioral adaptation</td>
</tr>
</table>

### Build Targets

```bash
make build            # Development build (stripped, static)
make build-arm64      # ARM64 cross-compile
make build-garble     # Obfuscated build
make build-release    # Production release (garble + UPX + patching)
make check            # Full CI check (vet + fmt + build)
make strings-check    # Check for Go metadata leaks
make opsec-check      # OPSEC verification suite
make clean            # Remove build artifacts
```

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Linux x86_64</th>
<th>Linux ARM64</th>
</tr>
<tr>
<td>Namespace isolation</td>
<td>Full (PID + Mount + Net + UTS + Cgroup)</td>
<td>Full</td>
</tr>
<tr>
<td>HTTPS C2</td>
<td>Full (domain fronting, JA3 randomization)</td>
<td>Full</td>
</tr>
<tr>
<td>DNS C2</td>
<td>Full (TXT records, DoH)</td>
<td>Full</td>
</tr>
<tr>
<td>Raw L2 C2</td>
<td>Full (AF_PACKET)</td>
<td>Full</td>
</tr>
<tr>
<td>eBPF cloaking</td>
<td>Full (kernel 5.10+)</td>
<td>Full (kernel 5.10+)</td>
</tr>
<tr>
<td>io_uring I/O</td>
<td>Full (kernel 5.1+)</td>
<td>Full (kernel 5.1+)</td>
</tr>
<tr>
<td>Fileless execution</td>
<td>Full (memfd_create)</td>
<td>Full</td>
</tr>
<tr>
<td>Process masquerade</td>
<td>Full (prctl + /proc/self/mem)</td>
<td>Full</td>
</tr>
<tr>
<td>Garble obfuscation</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>C2 server</td>
<td>Full (Python 3.9+)</td>
<td>Full (Python 3.9+)</td>
</tr>
</table>

---

## Testing

### Integration Test

Full end-to-end test: C2 server + test implant running a beacon loop on localhost.

```bash
./scripts/integration_test.sh
```

The test:

1. Builds a test implant (`cmd/test-implant/`) with sandbox evasion disabled
2. Starts the C2 HTTPS listener on `127.0.0.1:8443`
3. Launches the implant which performs ECDH key exchange and registers a session
4. Verifies a session was recorded in the C2 database
5. Confirms at least one beacon was sent and received

The test implant runs without namespace isolation or evasion checks, making it suitable for lab/VM environments. Built with `-tags testbuild`.

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers
- Exploit vulnerabilities in unauthorized contexts

### Threat Model

**In scope:**
- Hiding from standard system monitoring and forensic tools
- Encrypting C2 traffic in transit with multiple fallback channels
- Authorized testing with known (or unknown) endpoint monitoring
- Evading userspace forensic collection (LiME, AVML, volatility)

**Out of scope:**
- Defeating hardware-based security monitoring (TPM, HSM)
- Evading kernel-level integrity monitoring (IMA/EVM)
- Cross-platform operation (Linux only by design)

### What Aquifer Does NOT Do

Aquifer is a **post-exploitation framework**, not a general-purpose attack tool:

- **Not an initial access tool** -- No vulnerability scanning, exploitation, or phishing
- **Not a lateral movement tool** -- No credential spraying or pass-the-hash
- **Not a data exfiltration tool** -- File upload/download exists but is not the focus
- **Not cross-platform** -- Linux namespace isolation is the core design

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer)
- **Releases**: [Latest Release](https://github.com/Real-Fruit-Snacks/Aquifer/releases/latest)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Aquifer/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Deadwater](https://github.com/Real-Fruit-Snacks/Deadwater) • [Deluge](https://github.com/Real-Fruit-Snacks/Deluge) • [Depth](https://github.com/Real-Fruit-Snacks/Depth) • [Dew](https://github.com/Real-Fruit-Snacks/Dew) • [Droplet](https://github.com/Real-Fruit-Snacks/Droplet) • [Fathom](https://github.com/Real-Fruit-Snacks/Fathom) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [Grotto](https://github.com/Real-Fruit-Snacks/Grotto) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Maelstrom](https://github.com/Real-Fruit-Snacks/Maelstrom) • [Rapids](https://github.com/Real-Fruit-Snacks/Rapids) • [Ripple](https://github.com/Real-Fruit-Snacks/Ripple) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Shallows](https://github.com/Real-Fruit-Snacks/Shallows) • [Siphon](https://github.com/Real-Fruit-Snacks/Siphon) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Spillway](https://github.com/Real-Fruit-Snacks/Spillway) • [Surge](https://github.com/Real-Fruit-Snacks/Surge) • [Tidemark](https://github.com/Real-Fruit-Snacks/Tidemark) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undercurrent](https://github.com/Real-Fruit-Snacks/Undercurrent) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • [Vapor](https://github.com/Real-Fruit-Snacks/Vapor) • [Wellspring](https://github.com/Real-Fruit-Snacks/Wellspring) • [Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)

*Remember: With great power comes great responsibility.*

</div>
