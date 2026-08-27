VERSION ?= 0.1.0
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.gitHash=$(GIT_HASH) \
	-X main.gitBranch=$(GIT_BRANCH) \
	-X main.buildTime=$(BUILD_TIME)

.PHONY: build clean test

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o akmcp ./cmd

clean:
	rm -f akmcp

test:
	go test ./...

# Dump the tool manifest consumed by the public alertkick-webmcp package.
.PHONY: webmcp-manifest
webmcp-manifest:
	go run -ldflags "-X main.version=$(VERSION)" ./cmd/webmcp-manifest > webmcp-manifest.json
