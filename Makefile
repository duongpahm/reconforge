# ReconForge — Makefile
# Build, test, and install the reconnaissance framework

BINARY    = reconforge
PKG       = github.com/reconforge/reconforge
CMD       = ./cmd/reconforge
BUILD_DIR = bin
VERSION   = $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_AT  = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS   = -s -w \
            -X '$(PKG)/internal/config.Version=$(VERSION)' \
            -X '$(PKG)/internal/config.BuildTime=$(BUILD_AT)'

.PHONY: all build test vet lint clean install help

## Default: build + test + vet
all: vet test build

## Build the binary
build:
	@echo "🔨 Building $(BINARY) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "✅ $(BUILD_DIR)/$(BINARY)"

## Run all tests with coverage
test:
	@echo "🧪 Running tests..."
	CGO_ENABLED=0 go test -count=1 -cover -race ./...

## Run go vet
vet:
	@echo "🔍 Running go vet..."
	go vet ./...

## Run tests in verbose mode
test-v:
	@echo "🧪 Running tests (verbose)..."
	CGO_ENABLED=0 go test -count=1 -v -cover ./...

## Run tests with coverage report
coverage:
	@echo "📊 Generating coverage report..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go test -coverprofile=$(BUILD_DIR)/coverage.out ./...
	go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "✅ Coverage report: $(BUILD_DIR)/coverage.html"

## Install binary to GOPATH/bin
install:
	@echo "📦 Installing $(BINARY)..."
	CGO_ENABLED=0 go install -ldflags "$(LDFLAGS)" $(CMD)
	@echo "✅ Installed to $$(go env GOPATH)/bin/$(BINARY)"

## Cross-compile for Linux (Kali VM target)
build-linux:
	@echo "🐧 Cross-compiling for Linux amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(CMD)
	@echo "✅ $(BUILD_DIR)/$(BINARY)-linux-amd64"

## Cross-compile for Linux ARM64
build-linux-arm:
	@echo "🐧 Cross-compiling for Linux arm64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-arm64 $(CMD)
	@echo "✅ $(BUILD_DIR)/$(BINARY)-linux-arm64"

## Build all platforms
build-all: build build-linux build-linux-arm
	@echo "✅ All builds completed"

## Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	rm -rf $(BUILD_DIR)
	go clean -testcache
	@echo "✅ Clean"

## Show version
version:
	@echo "$(VERSION)"

## Show help
help:
	@echo "ReconForge Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all            Build + test + vet (default)"
	@echo "  build          Build binary for current platform"
	@echo "  build-linux    Cross-compile for Linux amd64"
	@echo "  build-linux-arm Cross-compile for Linux arm64"
	@echo "  build-all      Build all platforms"
	@echo "  test           Run tests with coverage"
	@echo "  test-v         Run tests verbose"
	@echo "  coverage       Generate HTML coverage report"
	@echo "  vet            Run go vet"
	@echo "  install        Install to GOPATH/bin"
	@echo "  clean          Remove build artifacts"
	@echo "  version        Show version"
	@echo "  help           Show this help"
