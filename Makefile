# Makefile for agent_cmdb
# CI/CD automation targets

.PHONY: all build build-linux test test-verbose test-coverage lint fmt vet clean deps tidy check generate help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Build parameters
BINARY_NAME=agent_cmdb
BUILD_DIR=build
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME = $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Linker flags for version info
LDFLAGS = -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)

# Lint tool
GOLINT=golangci-lint

# Default target
all: generate deps fmt vet test build

# Generate eBPF code
generate:
	@echo "==> Generating eBPF code..."
	@if command -v clang >/dev/null 2>&1; then \
		cd probe && clang -O2 -g -target bpf -c bpf/counter.c -o bpf_bpfel_x86.o; \
		echo "eBPF code generated"; \
	else \
		echo "clang not found, skipping eBPF code generation"; \
	fi

# Build the binary
build: generate
	@echo "==> Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -v -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) .

# Build for Linux (cross-compile)
build-linux:
	@echo "==> Building $(BINARY_NAME) for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -v -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .

# Build static binary (for containers)
build-static:
	@echo "==> Building static $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -v -ldflags "$(LDFLAGS) -extldflags '-static'" -o $(BUILD_DIR)/$(BINARY_NAME)-static .

# Run tests (all modules)
test:
	@echo "==> Running tests..."
	$(GOTEST) -race ./...
	@echo "==> Running probe tests..."
	cd probe && $(GOTEST) -race ./...

# Run tests with verbose output
test-verbose:
	@echo "==> Running tests (verbose)..."
	$(GOTEST) -v -race ./...
	cd probe && $(GOTEST) -v -race ./...

# Run tests with coverage
test-coverage:
	@echo "==> Running tests with coverage..."
	@mkdir -p coverage
	$(GOTEST) -v -race -coverprofile=coverage/main.out -covermode=atomic ./...
	cd probe && $(GOTEST) -v -race -coverprofile=../coverage/probe.out -covermode=atomic ./...
	@echo "==> Coverage reports generated in coverage/"

# Run short tests only (skip integration tests)
test-short:
	@echo "==> Running short tests..."
	$(GOTEST) -short -race ./...
	cd probe && $(GOTEST) -short -race ./...

# Run linter
lint:
	@echo "==> Running linter..."
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
		cd probe && $(GOLINT) run ./...; \
	else \
		echo "golangci-lint not installed, running go vet instead"; \
		$(GOVET) ./...; \
		cd probe && $(GOVET) ./...; \
	fi

# Format code
fmt:
	@echo "==> Formatting code..."
	$(GOFMT) ./...
	cd probe && $(GOFMT) ./...

# Check formatting (CI mode)
fmt-check:
	@echo "==> Checking code formatting..."
	@diff=$$($(GOFMT) ./... 2>&1); \
	if [ -n "$$diff" ]; then \
		echo "Code was not formatted: $$diff"; \
		exit 1; \
	fi
	@diff=$$(cd probe && $(GOFMT) ./... 2>&1); \
	if [ -n "$$diff" ]; then \
		echo "Probe code was not formatted: $$diff"; \
		exit 1; \
	fi

# Run go vet
vet:
	@echo "==> Running go vet..."
	$(GOVET) ./...
	cd probe && $(GOVET) ./...

# Clean build artifacts
clean:
	@echo "==> Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf coverage
	cd probe && $(GOCLEAN) && rm -rf build coverage

# Download dependencies
deps:
	@echo "==> Downloading dependencies..."
	$(GOMOD) download
	cd probe && $(GOMOD) download

# Tidy dependencies
tidy:
	@echo "==> Tidying dependencies..."
	$(GOMOD) tidy
	cd probe && $(GOMOD) tidy

# Verify dependencies
verify:
	@echo "==> Verifying dependencies..."
	$(GOMOD) verify
	cd probe && $(GOMOD) verify

# Full CI check
ci: generate deps fmt-check vet lint test
	@echo "==> CI checks passed!"

# Pre-commit check
check: generate fmt vet test
	@echo "==> All checks passed!"

# Install the binary to GOPATH/bin
install: build
	@echo "==> Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

# Run the agent (for development)
run: build
	@echo "==> Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME) --verbose --once

# Run with network collection (requires root)
run-network: build
	@echo "==> Running $(BINARY_NAME) with network collection..."
	./$(BUILD_DIR)/$(BINARY_NAME) --verbose --once --network

# Install development tools
install-tools:
	@echo "==> Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Tools installed successfully"

# Show version info
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"

# Show help
help:
	@echo "agent_cmdb Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Generate, deps, fmt, vet, test, and build (default)"
	@echo "  build            - Build the binary"
	@echo "  build-linux      - Cross-compile for Linux amd64"
	@echo "  build-static     - Build static binary for containers"
	@echo "  test             - Run tests with race detection"
	@echo "  test-verbose     - Run tests with verbose output"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  test-short       - Run short tests only"
	@echo "  lint             - Run golangci-lint"
	@echo "  fmt              - Format code"
	@echo "  fmt-check        - Check code formatting (CI mode)"
	@echo "  vet              - Run go vet"
	@echo "  clean            - Clean build artifacts"
	@echo "  deps             - Download dependencies"
	@echo "  tidy             - Tidy dependencies"
	@echo "  verify           - Verify dependencies"
	@echo "  ci               - Run full CI checks"
	@echo "  check            - Run pre-commit checks"
	@echo "  generate         - Generate eBPF code"
	@echo "  install          - Install binary to GOPATH/bin"
	@echo "  run              - Build and run (development)"
	@echo "  run-network      - Build and run with network collection"
	@echo "  install-tools    - Install development tools"
	@echo "  version          - Show version info"
	@echo "  help             - Show this help message"
