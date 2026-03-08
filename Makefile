COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BINARY  := pgharden
PKG     := github.com/pscheid92/pgharden/internal/platform/buildinfo
LDFLAGS := -ldflags "-s -w -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)"

.PHONY: build test test-unit test-integration lint cover clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/pgharden

test: test-unit test-integration

test-unit:
	go test -short -race ./...

test-integration:
	go test -race -run TestIntegration -timeout 120s ./...

lint:
	golangci-lint run ./...

cover:
	go test -short -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -f $(BINARY) coverage.out coverage.html
