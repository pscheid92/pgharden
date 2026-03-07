VERSION := 0.1.0
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BINARY  := pgharden-go
PKG     := github.com/pgharden/pgharden/internal/buildinfo
LDFLAGS := -ldflags "-s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)"

.PHONY: build test lint clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/pgharden

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
