SHELL := /bin/bash

GO ?= go
PKG := ./...
BIN := processdemo
GOFILES := $(shell find . -name '*.go')

.PHONY: all fmt vet test build clean tidy ci

all: build

fmt:
	@if [ -n "$(GOFILES)" ]; then \
		gofmt -w $(GOFILES); \
	fi
	$(GO) fmt $(PKG)

vet:
	$(GO) vet $(PKG)

test:
	$(GO) test $(PKG)

build:
	CGO_ENABLED=0 $(GO) build -o $(BIN) .

clean:
	rm -f $(BIN)

tidy:
	$(GO) mod tidy

ci: fmt vet test build
