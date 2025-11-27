.PHONY: build install test clean run help

# Binary name
BINARY_NAME=dockerscan
VERSION=2.0.0
BUILD_DIR=bin

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Build flags
LDFLAGS=-ldflags "-s -w -X github.com/cr0hn/dockerscan/v2/internal/config.Version=$(VERSION)"

all: help

help: ## Show this help
	@echo "DockerScan v$(VERSION) - Advanced Docker Security Scanner"
	@echo "by Daniel Garcia (cr0hn) - https://cr0hn.com"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build all binaries (dockerscan, nvd2sqlite)
	@echo "🔨 Building DockerScan v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/dockerscan
	@echo "✅ Binary built: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "🔨 Building nvd2sqlite..."
	$(GOBUILD) -o $(BUILD_DIR)/nvd2sqlite ./cmd/nvd2sqlite
	@echo "✅ Binary built: $(BUILD_DIR)/nvd2sqlite"

build-all: ## Build for all platforms
	@echo "🔨 Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/dockerscan
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/dockerscan
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/dockerscan
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/dockerscan
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/dockerscan
	@echo "✅ Built for all platforms"

install: build ## Install the binary
	@echo "📦 Installing $(BINARY_NAME)..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "✅ Installed to $(GOPATH)/bin/$(BINARY_NAME)"

test: ## Run tests
	@echo "🧪 Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo "✅ Tests passed"

coverage: test ## Show test coverage
	$(GOCMD) tool cover -html=coverage.out

fmt: ## Format code
	@echo "🎨 Formatting code..."
	$(GOFMT) ./...
	@echo "✅ Code formatted"

vet: ## Run go vet
	@echo "🔍 Running go vet..."
	$(GOVET) ./...
	@echo "✅ Vet passed"

lint: fmt vet ## Run all linters
	@echo "✅ All linters passed"

clean: ## Clean build artifacts
	@echo "🧹 Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out
	@echo "✅ Cleaned"

deps: ## Download dependencies
	@echo "📥 Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✅ Dependencies ready"

run: build ## Build and run
	@echo "🚀 Running DockerScan..."
	@./$(BUILD_DIR)/$(BINARY_NAME)

scan: build ## Run a quick scan (usage: make scan IMAGE=nginx:latest)
	@./$(BUILD_DIR)/$(BINARY_NAME) $(IMAGE)

docker-build: ## Build Docker image
	docker build -t dockerscan:$(VERSION) .

release: clean lint test build-all ## Prepare release
	@echo "🎉 Release $(VERSION) ready in $(BUILD_DIR)/"
