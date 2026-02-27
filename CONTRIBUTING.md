# Contributing to Aquifer

Thank you for your interest in contributing. This document provides guidelines for contributions.

## Getting Started

```bash
git clone https://github.com/Real-Fruit-Snacks/Aquifer.git
cd Aquifer
make build
make test
```

### Prerequisites

- Go 1.21+
- Python 3.10+ (for C2 server)
- Linux (namespace features require Linux kernel 5.10+)

## Development Workflow

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run checks: `make check && make test`
5. Submit a pull request

## Code Standards

### Go

- Run `gofmt` before committing
- Pass `go vet ./...` and `staticcheck ./...`
- Write tests for new functionality
- Follow existing patterns in the codebase

### Python

- Follow PEP 8
- Add type hints to new functions
- Pin new dependencies in `c2server/requirements.txt`

## Commit Messages

- Use present tense ("add feature" not "added feature")
- Keep the first line under 72 characters
- Reference issues with `#123` where applicable

## Testing

- **Go**: `make test` runs all Go unit tests
- **Integration**: `./scripts/integration_test.sh` runs end-to-end C2 test (requires root)
- All pull requests must pass CI before merge

## What We Accept

- Bug fixes
- Test coverage improvements
- Documentation improvements
- New stealth modules (with tests)
- Transport channel improvements
- Build system improvements

## What Needs Discussion First

Open an issue before submitting PRs for:

- New C2 transport channels
- Architecture changes
- New dependencies
- Changes to the wire protocol

## Legal

By contributing, you agree that your contributions will be licensed under the same [BSD 3-Clause License](LICENSE) as the project.
