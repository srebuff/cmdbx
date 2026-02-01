# eBPF Demo Makefile
# Builds the eBPF XDP packet counter

BINARY := ebpfdemo
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

# Build variables
BUILDSTAMP := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GITHASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-s -w -X main.buildstamp=$(BUILDSTAMP) -X main.githash=$(GITHASH)"

# eBPF compiler flags
CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf

.PHONY: all build generate clean deps install-deps help mod test bench test-bpf

all: build

# Download Go module dependencies
mod:
	@echo "Downloading Go dependencies..."
	go mod tidy
	go mod download

# Install system dependencies (requires root)
install-deps:
	@echo "Installing eBPF build dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		apt-get update && apt-get install -y clang llvm libbpf-dev linux-headers-$$(uname -r); \
	elif command -v yum >/dev/null 2>&1; then \
		yum install -y clang llvm libbpf-devel kernel-headers; \
	else \
		echo "Unsupported package manager. Install clang, llvm, libbpf-dev manually."; \
		exit 1; \
	fi
	@echo "Installing bpf2go..."
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Generate BPF objects from C code (uses bpf2go)
generate: mod
	@echo "Generating eBPF Go bindings..."
	go generate ./...

# Build the binary
build: generate
	@echo "Building $(BINARY)..."
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) .
	@echo "Done: $(BINARY)"

# Build without regenerating (faster for code changes)
build-fast:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) .

# Clean build artifacts
clean:
	rm -f $(BINARY)
	rm -f bpf_*.go bpf_*.o

# Run the program (requires root for XDP)
run: build
	@echo "Running $(BINARY) (requires root)..."
	sudo ./$(BINARY)

# Run unit tests
test:
	@echo "Running tests..."
	CGO_ENABLED=0 go test -v .

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	CGO_ENABLED=0 go test -bench=. -benchmem .

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	CGO_ENABLED=0 go test -coverprofile=coverage.out .
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run BPF program tests (requires root)
test-bpf:
	@echo "Running BPF program tests (requires root)..."
	sudo go test -v -run TestXDP .

# Show help
help:
	@echo "eBPF Demo Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build everything (default)"
	@echo "  mod          - Download Go module dependencies"
	@echo "  install-deps - Install system dependencies (requires root)"
	@echo "  generate     - Generate Go bindings from eBPF C code"
	@echo "  build        - Build the binary"
	@echo "  build-fast   - Build without regenerating eBPF code"
	@echo "  test         - Run unit tests"
	@echo "  test-bpf     - Run BPF program tests (requires root)"
	@echo "  bench        - Run benchmarks"
	@echo "  coverage     - Run tests with coverage report"
	@echo "  clean        - Remove build artifacts"
	@echo "  run          - Build and run (requires root for XDP)"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - clang, llvm, libbpf-dev"
	@echo "  - Linux kernel headers"
	@echo "  - github.com/cilium/ebpf/cmd/bpf2go"
