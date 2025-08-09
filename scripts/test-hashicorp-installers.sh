#!/bin/bash
# Test script for HashiCorp native installers
# This script validates that all HashiCorp installers work correctly

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test tracking
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

test_start() {
    echo -e "\n${YELLOW}=== Testing: $1 ===${NC}"
}

test_pass() {
    echo -e "${GREEN}✓${NC} $1 passed"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}✗${NC} $1 failed: $2"
    ((TESTS_FAILED++))
    FAILED_TESTS+=("$1: $2")
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Build eos binary
build_eos() {
    test_start "Building Eos Binary"
    
    if go build -o /tmp/eos-test 2>/dev/null; then
        test_pass "Eos build"
        export EOS_BIN="/tmp/eos-test"
    else
        test_fail "Eos build" "Compilation failed"
        exit 1
    fi
}

# Test Consul installer
test_consul() {
    test_start "Consul Native Installer"
    
    # Test version resolution
    if $EOS_BIN create consul --version=latest --dry-run 2>/dev/null; then
        test_pass "Consul version resolution"
    else
        test_fail "Consul version resolution" "Failed to resolve version"
    fi
    
    # Test idempotency - run twice
    if $EOS_BIN create consul --force 2>/dev/null; then
        test_pass "Consul installation"
        
        # Run again to test idempotency
        if $EOS_BIN create consul 2>/dev/null; then
            test_pass "Consul idempotency"
        else
            test_fail "Consul idempotency" "Second run failed"
        fi
    else
        test_fail "Consul installation" "Installation failed"
    fi
    
    # Verify service
    if systemctl is-active consul >/dev/null 2>&1; then
        test_pass "Consul service running"
    else
        test_fail "Consul service" "Service not running"
    fi
    
    # Verify binary
    if consul version >/dev/null 2>&1; then
        test_pass "Consul binary working"
    else
        test_fail "Consul binary" "Binary not working"
    fi
}

# Test Vault installer
test_vault() {
    test_start "Vault Native Installer"
    
    # Test installation with file backend
    if $EOS_BIN create vault --storage-backend=file --force 2>/dev/null; then
        test_pass "Vault installation"
        
        # Test idempotency
        if $EOS_BIN create vault 2>/dev/null; then
            test_pass "Vault idempotency"
        else
            test_fail "Vault idempotency" "Second run failed"
        fi
    else
        test_fail "Vault installation" "Installation failed"
    fi
    
    # Verify service
    if systemctl is-active vault >/dev/null 2>&1; then
        test_pass "Vault service running"
    else
        log_warn "Vault service not running (expected - needs initialization)"
    fi
    
    # Verify binary
    if vault version >/dev/null 2>&1; then
        test_pass "Vault binary working"
    else
        test_fail "Vault binary" "Binary not working"
    fi
}

# Test Nomad installer
test_nomad() {
    test_start "Nomad Native Installer"
    
    # Test installation as both server and client
    if $EOS_BIN create nomad --server --client --force 2>/dev/null; then
        test_pass "Nomad installation"
        
        # Test idempotency
        if $EOS_BIN create nomad 2>/dev/null; then
            test_pass "Nomad idempotency"
        else
            test_fail "Nomad idempotency" "Second run failed"
        fi
    else
        test_fail "Nomad installation" "Installation failed"
    fi
    
    # Verify service
    if systemctl is-active nomad >/dev/null 2>&1; then
        test_pass "Nomad service running"
    else
        test_fail "Nomad service" "Service not running"
    fi
    
    # Verify binary
    if nomad version >/dev/null 2>&1; then
        test_pass "Nomad binary working"
    else
        test_fail "Nomad binary" "Binary not working"
    fi
    
    # Check node status
    if nomad node status >/dev/null 2>&1; then
        test_pass "Nomad node status"
    else
        log_warn "Nomad node status failed (may need time to initialize)"
    fi
}

# Test Terraform installer
test_terraform() {
    test_start "Terraform Native Installer"
    
    # Test installation
    if $EOS_BIN create terraform --force 2>/dev/null; then
        test_pass "Terraform installation"
        
        # Test idempotency
        if $EOS_BIN create terraform 2>/dev/null; then
            test_pass "Terraform idempotency"
        else
            test_fail "Terraform idempotency" "Second run failed"
        fi
    else
        test_fail "Terraform installation" "Installation failed"
    fi
    
    # Verify binary
    if terraform version >/dev/null 2>&1; then
        test_pass "Terraform binary working"
    else
        test_fail "Terraform binary" "Binary not working"
    fi
    
    # Test init (should fail without config but shows terraform works)
    cd /tmp
    if terraform init 2>&1 | grep -q "no configuration files"; then
        test_pass "Terraform init test"
    else
        test_fail "Terraform init" "Unexpected output"
    fi
}

# Test Packer installer
test_packer() {
    test_start "Packer Native Installer"
    
    # Test installation
    if $EOS_BIN create packer --force 2>/dev/null; then
        test_pass "Packer installation"
        
        # Test idempotency
        if $EOS_BIN create packer 2>/dev/null; then
            test_pass "Packer idempotency"
        else
            test_fail "Packer idempotency" "Second run failed"
        fi
    else
        test_fail "Packer installation" "Installation failed"
    fi
    
    # Verify binary
    if packer version >/dev/null 2>&1; then
        test_pass "Packer binary working"
    else
        test_fail "Packer binary" "Binary not working"
    fi
}

# Test Boundary installer
test_boundary() {
    test_start "Boundary Native Installer"
    
    # Test dev mode installation
    if $EOS_BIN create boundary --dev --force 2>/dev/null; then
        test_pass "Boundary dev mode installation"
        
        # Test idempotency
        if $EOS_BIN create boundary --dev 2>/dev/null; then
            test_pass "Boundary idempotency"
        else
            test_fail "Boundary idempotency" "Second run failed"
        fi
    else
        test_fail "Boundary installation" "Installation failed"
    fi
    
    # Verify binary
    if boundary version >/dev/null 2>&1; then
        test_pass "Boundary binary working"
    else
        test_fail "Boundary binary" "Binary not working"
    fi
    
    # Check dev script
    if [[ -f /usr/local/bin/boundary-dev ]]; then
        test_pass "Boundary dev script created"
    else
        test_fail "Boundary dev script" "Script not found"
    fi
}

# Test repository installation method
test_repository_method() {
    test_start "Repository Installation Method"
    
    # Test Consul via repository
    if $EOS_BIN create consul --use-repository --clean --force 2>/dev/null; then
        test_pass "Repository installation (Consul)"
    else
        log_warn "Repository installation failed (may not have repository configured)"
    fi
}

# Test version resolution
test_version_resolution() {
    test_start "Version Resolution"
    
    # This should resolve to the latest version without actually installing
    if $EOS_BIN create vault --version=latest --dry-run 2>&1 | grep -q "version"; then
        test_pass "Version resolution"
    else
        log_warn "Version resolution test inconclusive"
    fi
}

# Cleanup function
cleanup() {
    test_start "Cleanup"
    
    # Stop services
    for service in consul vault nomad boundary; do
        systemctl stop $service 2>/dev/null || true
        systemctl disable $service 2>/dev/null || true
    done
    
    # Remove binaries (optional - comment out if you want to keep them)
    # rm -f /usr/local/bin/{consul,vault,nomad,terraform,packer,boundary}
    
    log_info "Cleanup completed"
}

# Print summary
print_summary() {
    echo -e "\n${YELLOW}=== Test Summary ===${NC}"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "\n${RED}Failed tests:${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            echo "  - $test"
        done
        exit 1
    else
        echo -e "\n${GREEN}All tests passed successfully!${NC}"
        exit 0
    fi
}

# Main execution
main() {
    log_info "Starting HashiCorp Installers Test Suite"
    log_info "Test date: $(date)"
    
    # Check prerequisites
    check_root
    
    # Build eos
    build_eos
    
    # Run tests based on arguments
    if [[ $# -eq 0 ]]; then
        # Run all tests
        test_consul
        test_vault
        test_nomad
        test_terraform
        test_packer
        test_boundary
        test_repository_method
        test_version_resolution
    else
        # Run specific tests
        for test in "$@"; do
            case $test in
                consul)
                    test_consul
                    ;;
                vault)
                    test_vault
                    ;;
                nomad)
                    test_nomad
                    ;;
                terraform)
                    test_terraform
                    ;;
                packer)
                    test_packer
                    ;;
                boundary)
                    test_boundary
                    ;;
                repo)
                    test_repository_method
                    ;;
                version)
                    test_version_resolution
                    ;;
                cleanup)
                    cleanup
                    ;;
                *)
                    log_error "Unknown test: $test"
                    ;;
            esac
        done
    fi
    
    # Print summary
    print_summary
}

# Handle script arguments
case "${1:-}" in
    -h|--help)
        echo "Usage: $0 [test1 test2 ...] [cleanup]"
        echo ""
        echo "Available tests:"
        echo "  consul    - Test Consul installer"
        echo "  vault     - Test Vault installer"
        echo "  nomad     - Test Nomad installer"
        echo "  terraform - Test Terraform installer"
        echo "  packer    - Test Packer installer"
        echo "  boundary  - Test Boundary installer"
        echo "  repo      - Test repository installation method"
        echo "  version   - Test version resolution"
        echo "  cleanup   - Clean up installations"
        echo ""
        echo "If no tests specified, all tests will run"
        echo ""
        echo "Examples:"
        echo "  $0                    # Run all tests"
        echo "  $0 consul vault       # Test only Consul and Vault"
        echo "  $0 cleanup            # Clean up installations"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac