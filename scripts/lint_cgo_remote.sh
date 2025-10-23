#!/usr/bin/env bash
# lint_cgo_remote.sh - Lint CGO packages remotely for macOS development
# Last Updated: 2025-10-23
#
# PROBLEM: CGO packages (cephfs, kvm) cannot be linted on macOS due to missing C dependencies
# SOLUTION: SSH to Linux server (vhost1), sync code, run linters, parse results for VS Code
#
# USAGE:
#   ./scripts/lint_cgo_remote.sh                    # Lint all CGO packages
#   ./scripts/lint_cgo_remote.sh --watch            # Watch for changes and auto-lint
#   ./scripts/lint_cgo_remote.sh --package cephfs   # Lint specific package

set -euo pipefail

# Configuration
REMOTE_HOST="${EOS_REMOTE_HOST:-vhost1}"
REMOTE_DIR="/opt/eos"
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CGO_PACKAGES=(
    "./pkg/cephfs/..."
    "./pkg/kvm/..."
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
WATCH_MODE=false
SPECIFIC_PACKAGE=""
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --watch|-w)
            WATCH_MODE=true
            shift
            ;;
        --package|-p)
            SPECIFIC_PACKAGE="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            cat <<EOF
Usage: $0 [OPTIONS]

Lint CGO packages remotely on Linux server for macOS development.

OPTIONS:
    --watch, -w              Watch for file changes and auto-lint
    --package, -p PACKAGE    Lint specific package (cephfs, kvm)
    --verbose, -v            Verbose output
    --help, -h               Show this help message

ENVIRONMENT:
    EOS_REMOTE_HOST         Remote SSH host (default: vhost1)

EXAMPLES:
    $0                       # Lint all CGO packages once
    $0 --watch               # Watch and auto-lint on changes
    $0 -p cephfs             # Lint only cephfs package
    $0 -v -w                 # Verbose watch mode

INTEGRATION:
    - Run manually: ./scripts/lint_cgo_remote.sh
    - VS Code task: Cmd+Shift+P -> "Run Task" -> "Eos: Lint CGO Packages"
    - VS Code keybinding: Add to keybindings.json
    - Pre-commit hook: ln -s ../../scripts/lint_cgo_remote.sh .git/hooks/pre-commit

EOF
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Unknown option: $1"
            echo "Run '$0 --help' for usage information"
            exit 1
            ;;
    esac
done

# Override package list if specific package requested
if [[ -n "$SPECIFIC_PACKAGE" ]]; then
    CGO_PACKAGES=("./pkg/${SPECIFIC_PACKAGE}/...")
fi

# Function: Log with color
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Function: Check if remote host is reachable
check_remote_host() {
    if ! ssh -q -o BatchMode=yes -o ConnectTimeout=5 "$REMOTE_HOST" exit; then
        log_error "Cannot connect to remote host: $REMOTE_HOST"
        log_error "Fix: Ensure SSH key authentication is configured"
        log_error "  ssh-copy-id $REMOTE_HOST"
        exit 1
    fi
    log_info "Remote host reachable: $REMOTE_HOST"
}

# Function: Sync local code to remote
sync_to_remote() {
    log_info "Syncing code to $REMOTE_HOST:$REMOTE_DIR..."

    # Use rsync for efficient sync
    rsync -az --delete \
        --exclude='.git/' \
        --exclude='vendor/' \
        --exclude='*.test' \
        --exclude='*.out' \
        --exclude='.vscode/' \
        "$LOCAL_DIR/" "$REMOTE_HOST:$REMOTE_DIR/" 2>/dev/null || {
        log_warn "rsync failed, falling back to git pull on remote"
        ssh "$REMOTE_HOST" "cd $REMOTE_DIR && git pull" >/dev/null 2>&1
    }

    if [[ "$VERBOSE" == true ]]; then
        log_info "Sync complete"
    fi
}

# Function: Run linting on remote
run_remote_lint() {
    local packages=("$@")
    local pkg_args="${packages[*]}"

    log_info "Running golangci-lint on: ${pkg_args}"

    # Run linting on remote host
    ssh "$REMOTE_HOST" bash <<EOF
set -e
cd $REMOTE_DIR

# Check if golangci-lint is installed
if ! command -v golangci-lint >/dev/null 2>&1; then
    echo -e "${YELLOW}[WARN]${NC} golangci-lint not found, installing..."
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$(go env GOPATH)/bin v1.61.0
fi

# Run linting with CGO enabled
CGO_ENABLED=1 golangci-lint run --config .golangci.yml --out-format=colored-line-number $pkg_args
EOF

    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "Linting passed"
    else
        log_error "Linting found issues (see above)"
    fi

    return $exit_code
}

# Function: Run go vet on remote
run_remote_vet() {
    local packages=("$@")
    local pkg_args="${packages[*]}"

    log_info "Running go vet on: ${pkg_args}"

    ssh "$REMOTE_HOST" bash <<EOF
set -e
cd $REMOTE_DIR
CGO_ENABLED=1 go vet $pkg_args
EOF

    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "go vet passed"
    else
        log_error "go vet found issues"
    fi

    return $exit_code
}

# Function: Run build test on remote
run_remote_build() {
    log_info "Testing build with CGO..."

    ssh "$REMOTE_HOST" bash <<EOF
set -e
cd $REMOTE_DIR
CGO_ENABLED=1 go build -o /tmp/eos-build ./cmd/
EOF

    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "Build successful"
    else
        log_error "Build failed"
    fi

    return $exit_code
}

# Function: Full lint cycle
full_lint_cycle() {
    echo ""
    echo "========================================"
    echo " CGO Linting - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================"

    # Sync code
    sync_to_remote

    # Run checks
    local overall_status=0

    # 1. go vet
    if ! run_remote_vet "${CGO_PACKAGES[@]}"; then
        overall_status=1
    fi

    # 2. golangci-lint
    if ! run_remote_lint "${CGO_PACKAGES[@]}"; then
        overall_status=1
    fi

    # 3. Build test
    if ! run_remote_build; then
        overall_status=1
    fi

    echo "========================================"
    if [[ $overall_status -eq 0 ]]; then
        log_success "All checks passed"
    else
        log_error "Some checks failed"
    fi
    echo "========================================"

    return $overall_status
}

# Main execution
main() {
    # Check prerequisites
    check_remote_host

    if [[ "$WATCH_MODE" == true ]]; then
        log_info "Starting watch mode..."
        log_info "Watching: pkg/cephfs/ pkg/kvm/"
        log_info "Press Ctrl+C to stop"

        # Check if fswatch is installed
        if ! command -v fswatch >/dev/null 2>&1; then
            log_error "fswatch not found. Install with: brew install fswatch"
            exit 1
        fi

        # Run initial lint
        full_lint_cycle

        # Watch for changes
        fswatch -o "$LOCAL_DIR/pkg/cephfs" "$LOCAL_DIR/pkg/kvm" | while read -r _; do
            sleep 1  # Debounce rapid changes
            full_lint_cycle
        done
    else
        # Single run
        full_lint_cycle
    fi
}

# Run main
main "$@"
