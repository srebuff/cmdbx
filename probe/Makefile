# Makefile for agent_cmdb/probe module
# CI/CD automation targets

.PHONY: all build test test-verbose test-coverage lint fmt vet clean deps tidy check help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Build parameters
BINARY_NAME=probe
BUILD_DIR=build
COVERAGE_DIR=coverage
COVERAGE_FILE=$(COVERAGE_DIR)/coverage.out
COVERAGE_HTML=$(COVERAGE_DIR)/coverage.html

# Lint tool
GOLINT=golangci-lint

# Default target
all: generate deps fmt vet test build

# Build the binary (probe is a library, this just compiles to verify)
build: generate
	@echo "==> Building..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -v -o $(BUILD_DIR)/$(BINARY_NAME) ./...

# Build for Linux (cross-compile)
build-linux:
	@echo "==> Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -v -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./...

# Run tests
test:
	@echo "==> Running tests..."
	$(GOTEST) -race ./...

# Run tests with verbose output
test-verbose:
	@echo "==> Running tests (verbose)..."
	$(GOTEST) -v -race ./...

# Run tests with coverage
test-coverage:
	@echo "==> Running tests with coverage..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@echo "==> Generating coverage report..."
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	$(GOCMD) tool cover -func=$(COVERAGE_FILE)

# Run tests with coverage and check threshold
test-coverage-check: test-coverage
	@echo "==> Checking coverage threshold..."
	@total=$$(go tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print $$3}' | sed 's/%//'); \
	threshold=50; \
	if [ $$(echo "$$total < $$threshold" | bc -l) -eq 1 ]; then \
		echo "Coverage $$total% is below threshold $$threshold%"; \
		exit 1; \
	else \
		echo "Coverage $$total% meets threshold $$threshold%"; \
	fi

# Run short tests only (skip integration tests)
test-short:
	@echo "==> Running short tests..."
	$(GOTEST) -short -race ./...

# Run linter
lint:
	@echo "==> Running linter..."
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "golangci-lint not installed, running go vet instead"; \
		$(GOVET) ./...; \
	fi

# Format code
fmt:
	@echo "==> Formatting code..."
	$(GOFMT) ./...

# Check formatting (CI mode - fails if not formatted)
fmt-check:
	@echo "==> Checking code formatting..."
	@diff=$$($(GOCMD) fmt ./... 2>&1); \
	if [ -n "$$diff" ]; then \
		echo "Code was not formatted. Files formatted: $$diff"; \
		echo "Please run 'make fmt' and commit the changes"; \
		exit 1; \
	fi

# Run go vet
vet:
	@echo "==> Running go vet..."
	$(GOVET) ./...

# Clean build artifacts
clean:
	@echo "==> Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)

# Download dependencies
deps:
	@echo "==> Downloading dependencies..."
	$(GOMOD) download

# Tidy dependencies
tidy:
	@echo "==> Tidying dependencies..."
	$(GOMOD) tidy

# Verify dependencies
verify:
	@echo "==> Verifying dependencies..."
	$(GOMOD) verify

# Full CI check (format check, vet, lint, test with coverage)
ci: generate deps fmt-check vet lint test-coverage
	@echo "==> CI checks passed!"

# Pre-commit check (format, vet, test)
check: generate fmt vet test
	@echo "==> All checks passed!"

# Generate eBPF code (compile BPF C code with clang)
generate:
	@echo "==> Generating eBPF code..."
	@if command -v clang >/dev/null 2>&1; then \
		clang -O2 -g -target bpf -c bpf/counter.c -o bpf_bpfel_x86.o; \
		echo "eBPF code generated (bpf_bpfel_x86.o)"; \
	else \
		echo "clang not found, skipping eBPF code generation"; \
		echo "Install clang: apt-get install clang"; \
	fi

# Install development tools
install-tools:
	@echo "==> Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Tools installed successfully"

# Show help
help:
	@echo "Available targets:"
	@echo "  all              - Run deps, fmt, vet, test, and build (default)"
	@echo "  build            - Build the binary"
	@echo "  build-linux      - Cross-compile for Linux amd64"
	@echo "  test             - Run tests with race detection"
	@echo "  test-verbose     - Run tests with verbose output"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  test-coverage-check - Run tests and check coverage threshold"
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
	@echo "  install-tools    - Install development tools"
	@echo "  help             - Show this help message"
