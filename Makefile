VERSION := 0.1.0
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BINARY  := pgharden-go
PKG     := github.com/pgharden/pgharden/internal/buildinfo
LDFLAGS := -ldflags "-s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)"

.PHONY: build test test-unit test-integration lint clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/pgharden

test: test-unit test-integration

test-unit:
	go test -short -race ./...

test-integration:
	go test -race -run TestIntegration -timeout 120s ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
