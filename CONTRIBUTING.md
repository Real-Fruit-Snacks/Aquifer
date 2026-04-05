# Contributing to Aquifer

Thank you for your interest in contributing to Aquifer! This document provides guidelines and instructions for contributing.

## Development Environment Setup

### Prerequisites

- **Go toolchain:** 1.21+ (1.25+ for garble obfuscation)
- **Python:** 3.9+ (for C2 server development)
- **Linux:** Kernel 5.10+ (namespace features require Linux)
- **Git:** For version control

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/Aquifer.git
cd Aquifer

# Build the implant
make build

# Run CI checks
make check
```

## Code Style

All code must pass the following checks before submission:

### Go

- **Formatting:** `gofmt` -- all code must be formatted
- **Vetting:** `go vet ./...` -- zero warnings allowed
- **Static analysis:** `staticcheck ./...` -- zero warnings allowed
- **Tests:** `make test` -- all tests must pass

### Python

- Follow PEP 8
- Add type hints to new functions
- Pin new dependencies in `c2server/requirements.txt`

Run all checks before submitting a PR:

```bash
make check
make test
```

## Testing Requirements

- All existing tests must continue to pass
- New features must include tests
- New stealth modules must include unit tests
- Integration tests go in `scripts/`
- Unit tests use Go `_test.go` convention

### Integration Testing

```bash
# Full end-to-end C2 test (requires root)
./scripts/integration_test.sh
```

## Pull Request Process

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Test thoroughly:**
   ```bash
   make check
   make test
   ```

4. **Push** your branch and open a Pull Request against `main`.

5. **Describe your changes** in the PR using the provided template.

6. **Respond to review feedback** promptly.

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                          |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation changes                |
| `style`    | Formatting, no code change           |
| `refactor` | Code restructuring, no behavior change |
| `test`     | Adding or updating tests             |
| `ci`       | CI/CD changes                        |
| `chore`    | Maintenance, dependencies            |
| `perf`     | Performance improvements             |

### Examples

```
feat(stealth): add landlock self-sandboxing module
fix(c2): handle DNS TXT record truncation
docs: update build instructions for ARM64
ci: add garble obfuscation job
```

### Important

- Do **not** include AI co-author signatures in commits.
- Keep commits focused on a single logical change.

## What We Accept

- Bug fixes
- Test coverage improvements
- Documentation improvements
- New stealth modules (with tests)
- Transport channel improvements
- Build system improvements
- C2 server enhancements

## What Needs Discussion First

Open an issue before submitting PRs for:

- New C2 transport channels
- Architecture changes
- New dependencies
- Changes to the wire protocol
- New persistence mechanisms

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub.
