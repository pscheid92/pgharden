VERSION := 0.1.0
BINARY  := pgharden-go
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: build test lint clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/pgharden

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
