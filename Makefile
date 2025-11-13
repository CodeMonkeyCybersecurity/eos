# Eos Makefile
# Last Updated: 2025-10-23

.PHONY: all build test lint lint-fix clean install help

# Build configuration
BINARY_NAME := eos
BUILD_DIR := /tmp
INSTALL_DIR := /usr/local/bin

# CGO configuration for Ceph and libvirt support
CGO_ENABLED := 1
export CGO_ENABLED

# Go build flags
BUILD_FLAGS := -v
LDFLAGS := -s -w

# Linting configuration
GOLANGCI_LINT := golangci-lint
GOLANGCI_LINT_VERSION := v1.61.0

##@ General

all: lint test build ## Run lint, test, and build

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

build: ## Build Eos binary with CGO support
	@echo "[INFO] Building Eos with libvirt and Ceph support..."
	@echo "[INFO] CGO_ENABLED=$(CGO_ENABLED)"
	CGO_ENABLED=$(CGO_ENABLED) go build $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/

build-debug: ## Build with debug symbols and race detector
	@echo "[INFO] Building Eos with debug symbols..."
	CGO_ENABLED=$(CGO_ENABLED) go build $(BUILD_FLAGS) -race -o $(BUILD_DIR)/$(BINARY_NAME)-debug ./cmd/

install: build ## Build and install Eos to /usr/local/bin
	@echo "[INFO] Installing Eos to $(INSTALL_DIR)..."
	@if [ -f "$(INSTALL_DIR)/$(BINARY_NAME)" ]; then \
		backup="$(INSTALL_DIR)/$(BINARY_NAME).backup.$$(date +%Y%m%d-%H%M%S)"; \
		echo "[INFO] Backing up existing binary to $$backup"; \
		sudo mv "$(INSTALL_DIR)/$(BINARY_NAME)" "$$backup"; \
	fi
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "[INFO] Installation complete"

##@ Testing

test: ## Run all tests
	@echo "[INFO] Running tests..."
	go test -v -race -timeout=5m ./pkg/...

test-coverage: ## Run tests with coverage report
	@echo "[INFO] Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./pkg/...
	go tool cover -html=coverage.out -o coverage.html
	@echo "[INFO] Coverage report generated: coverage.html"

test-cgo: ## Run tests for CGO-enabled packages (cephfs, kvm)
	@echo "[INFO] Running CGO-enabled tests..."
	CGO_ENABLED=1 go test -v -race -tags=integration ./pkg/cephfs/...
	CGO_ENABLED=1 go test -v -race -tags=integration ./pkg/kvm/...

test-e2e-smoke: ## Run E2E smoke tests (fast, non-destructive)
	@echo "[INFO] Running E2E smoke tests..."
	@echo "[INFO] These tests verify command structure without modifying the system"
	go test -v -tags=e2e_smoke -timeout=5m ./test/e2e/smoke/...

test-e2e-full: ## Run full E2E tests (slow, DESTRUCTIVE - requires isolated test environment)
	@echo "[WARN] ==================================================================="
	@echo "[WARN] Running FULL E2E tests - these MODIFY the system!"
	@echo "[WARN] Only run in isolated test environment (VM or container)"
	@echo "[WARN] ==================================================================="
	@if [ "$$EOS_E2E_FULL_APPROVED" != "true" ]; then \
		echo "[ERROR] Full E2E tests not approved"; \
		echo "[ERROR] Set EOS_E2E_FULL_APPROVED=true to run destructive tests"; \
		exit 1; \
	fi
	@echo "[INFO] Running full E2E tests..."
	sudo -E go test -v -tags=e2e_full -timeout=60m ./test/e2e/full/...

##@ Linting

lint-install: ## Install golangci-lint
	@echo "[INFO] Checking for golangci-lint..."
	@if ! command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		echo "[INFO] Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin $(GOLANGCI_LINT_VERSION); \
	else \
		echo "[INFO] golangci-lint already installed: $$($(GOLANGCI_LINT) --version)"; \
	fi

lint: lint-install ## Run golangci-lint (all packages including CGO)
	@echo "[INFO] Running golangci-lint with CGO support..."
	CGO_ENABLED=1 $(GOLANGCI_LINT) run --config .golangci.yml ./...

lint-fix: lint-install ## Run golangci-lint with auto-fix
	@echo "[INFO] Running golangci-lint with auto-fix..."
	CGO_ENABLED=1 $(GOLANGCI_LINT) run --config .golangci.yml --fix ./...

lint-cgo: lint-install ## Run golangci-lint on CGO packages only (cephfs, kvm)
	@echo "[INFO] Linting CGO-enabled packages..."
	CGO_ENABLED=1 $(GOLANGCI_LINT) run --config .golangci.yml ./pkg/cephfs/...
	CGO_ENABLED=1 $(GOLANGCI_LINT) run --config .golangci.yml ./pkg/kvm/...

lint-verbose: lint-install ## Run golangci-lint with verbose output
	@echo "[INFO] Running golangci-lint (verbose)..."
	CGO_ENABLED=1 $(GOLANGCI_LINT) run --config .golangci.yml -v ./...

##@ Code Quality

fmt: ## Run gofmt on all files
	@echo "[INFO] Running gofmt..."
	@gofmt -l -s -w .

fmt-check: ## Check if code is formatted (CI-friendly)
	@echo "[INFO] Checking code formatting..."
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "[ERROR] The following files are not formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	else \
		echo "[INFO] All files are properly formatted"; \
	fi

vet: ## Run go vet
	@echo "[INFO] Running go vet..."
	CGO_ENABLED=1 go vet ./...

vet-cgo: ## Run go vet on CGO packages
	@echo "[INFO] Running go vet on CGO packages..."
	CGO_ENABLED=1 go vet ./pkg/cephfs/...
	CGO_ENABLED=1 go vet ./pkg/kvm/...

imports: ## Fix import formatting
	@echo "[INFO] Fixing imports..."
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "[INFO] Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi
	goimports -local github.com/CodeMonkeyCybersecurity/eos -w .

##@ Pre-commit

pre-commit: fmt-check vet lint test ## Run all pre-commit checks
	@echo "[INFO] All pre-commit checks passed"

pre-commit-cgo: fmt-check vet-cgo lint-cgo test-cgo ## Run pre-commit checks for CGO packages
	@echo "[INFO] All CGO pre-commit checks passed"

##@ Cleanup

clean: ## Remove build artifacts
	@echo "[INFO] Cleaning build artifacts..."
	@rm -f $(BUILD_DIR)/$(BINARY_NAME)
	@rm -f $(BUILD_DIR)/$(BINARY_NAME)-debug
	@rm -f coverage.out coverage.html
	@echo "[INFO] Clean complete"

clean-all: clean ## Remove all generated files including vendor
	@echo "[INFO] Removing vendor directory..."
	@rm -rf vendor/
	@echo "[INFO] Deep clean complete"

##@ Development

deps: ## Download and verify dependencies
	@echo "[INFO] Downloading dependencies..."
	go mod download
	go mod verify
	@echo "[INFO] Dependencies verified"

deps-update: ## Update dependencies
	@echo "[INFO] Updating dependencies..."
	go get -u ./...
	go mod tidy
	@echo "[INFO] Dependencies updated"

deps-vendor: ## Vendor dependencies
	@echo "[INFO] Vendoring dependencies..."
	go mod vendor
	@echo "[INFO] Dependencies vendored"

##@ CI/CD

ci: deps fmt-check vet lint test build ## CI pipeline (no auto-fix)
	@echo "[INFO] CI pipeline complete"

ci-cgo: deps fmt-check vet-cgo lint-cgo test-cgo build ## CI pipeline for CGO packages
	@echo "[INFO] CGO CI pipeline complete"

##@ Deployment

DEPLOY_SERVERS ?= vhost2
REMOTE_INSTALL_PATH := /usr/local/bin/eos

deploy: test build ## Deploy to servers (set DEPLOY_SERVERS="host1 host2")
	@echo "[INFO] Deploying Eos to servers: $(DEPLOY_SERVERS)"
	@for server in $(DEPLOY_SERVERS); do \
		echo "[INFO] → Deploying to $$server..."; \
		scp $(BUILD_DIR)/$(BINARY_NAME) $$server:/tmp/eos-new || exit 1; \
		ssh $$server "sudo mv /tmp/eos-new $(REMOTE_INSTALL_PATH) && sudo chmod +x $(REMOTE_INSTALL_PATH)" || exit 1; \
		version=$$(ssh $$server "$(REMOTE_INSTALL_PATH) --version 2>/dev/null || echo 'unknown'"); \
		echo "[INFO]   ✓ Deployed to $$server (version: $$version)"; \
	done
	@echo "[INFO] Deployment complete!"

deploy-check: ## Verify deployment on all servers
	@echo "[INFO] Checking Eos version on servers..."
	@for server in $(DEPLOY_SERVERS); do \
		echo "[INFO] → Checking $$server..."; \
		ssh $$server "$(REMOTE_INSTALL_PATH) --version" || echo "[ERROR] Failed to get version from $$server"; \
	done

deploy-all: test build ## Deploy to all production servers
	@$(MAKE) deploy DEPLOY_SERVERS="vhost2 vhost3 vhost4"

deploy-rollback: ## Rollback to previous version (if backup exists)
	@echo "[INFO] Rolling back Eos on servers: $(DEPLOY_SERVERS)"
	@for server in $(DEPLOY_SERVERS); do \
		echo "[INFO] → Rolling back $$server..."; \
		backup=$$(ssh $$server "ls -t $(REMOTE_INSTALL_PATH).backup.* 2>/dev/null | head -1"); \
		if [ -z "$$backup" ]; then \
			echo "[ERROR] No backup found on $$server"; \
			exit 1; \
		fi; \
		ssh $$server "sudo cp $$backup $(REMOTE_INSTALL_PATH) && sudo chmod +x $(REMOTE_INSTALL_PATH)"; \
		echo "[INFO]   ✓ Rolled back to $$backup"; \
	done
