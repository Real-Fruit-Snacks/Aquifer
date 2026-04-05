# Security Policy

## Supported Versions

Only the latest release of Aquifer is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

## Reporting a Vulnerability

**Do NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in Aquifer, please report it responsibly:

1. **Preferred:** Use [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Aquifer/security/advisories/new) to create a private report.
2. **Alternative:** Email the maintainers directly with details of the vulnerability.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Assessment:** Within 7 days
- **Fix & Disclosure:** Within 90 days (coordinated responsible disclosure)

We follow a 90-day responsible disclosure timeline. If a fix is not released within 90 days, the reporter may disclose the vulnerability publicly.

## What is NOT a Vulnerability

Aquifer is a post-exploitation framework designed for authorized security assessments. The following behaviors are **features, not bugs**:

- Namespace isolation and process hiding
- Multi-channel C2 communications (HTTPS, DNS, DoH, Raw L2)
- Polymorphic beacon encoding and JA3 randomization
- Process masquerade and environment scrubbing
- eBPF cloaking and kernel keyring storage
- Fileless execution via memfd_create
- Anti-dump memory protection (MADV_DONTDUMP/WIPEONFORK)
- Advanced persistence mechanisms (systemd generators, NSS modules, etc.)
- Target keying and auto-termination guardrails

These capabilities exist by design for legitimate security testing. Reports that simply describe Aquifer working as intended will be closed.

## Scope

This policy covers the Aquifer codebase including:

- Go implant (`cmd/`, `pkg/`)
- Python C2 server (`c2server/`)
- Build system (`Makefile`, `scripts/`)

## Responsible Use

Aquifer is intended for authorized penetration testing, red team operations, and security research only. Users are responsible for ensuring they have proper authorization before using this tool against any systems.
