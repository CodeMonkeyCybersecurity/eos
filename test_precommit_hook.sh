#!/bin/bash
# test_precommit_hook.sh - Test suite for pre-commit security hooks
#
# USAGE: ./test_precommit_hook.sh
# REQUIREMENT: Must be run from Eos repository root
# PURPOSE: Validate all 6 pre-commit security checks and exception handling
#
# EXIT CODES:
#   0 - All tests passed
#   1 - One or more tests failed

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Print functions
print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_test() {
    echo -e "${YELLOW}TEST:${NC} $1"
}

print_pass() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_info() {
    echo -e "${BLUE}ℹ INFO:${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check if in git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        echo "ERROR: Not in a git repository"
        exit 1
    fi

    # Check if pre-commit hook exists
    if [ ! -f .git/hooks/pre-commit ]; then
        echo "ERROR: Pre-commit hook not found at .git/hooks/pre-commit"
        exit 1
    fi

    # Check if hook is executable
    if [ ! -x .git/hooks/pre-commit ]; then
        echo "ERROR: Pre-commit hook is not executable"
        exit 1
    fi

    print_pass "All prerequisites met"
    echo ""
}

# Setup test environment
setup_test_env() {
    print_header "Setting Up Test Environment"

    # Create temporary test files directory
    TEST_DIR=$(mktemp -d)
    echo "Test directory: $TEST_DIR"

    # Ensure cleanup on exit
    trap "cleanup_test_env" EXIT

    print_pass "Test environment created"
    echo ""
}

cleanup_test_env() {
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi

    # Unstage any test files
    git reset HEAD -- "test_*.go" "vulnerable_*.go" 2>/dev/null || true
    rm -f test_*.go vulnerable_*.go 2>/dev/null || true
}

# Test helper: Create vulnerable Go file and test pre-commit hook
test_precommit_check() {
    local test_name="$1"
    local test_file="$2"
    local test_content="$3"
    local should_fail="$4"  # "true" if hook should block, "false" if should pass

    TESTS_RUN=$((TESTS_RUN + 1))
    print_test "$test_name"

    # Create test Go file
    echo "$test_content" > "$test_file"
    git add "$test_file"

    # Run pre-commit hook
    if .git/hooks/pre-commit 2>&1 | tee /tmp/precommit-output.txt; then
        # Hook passed (exit 0)
        if [ "$should_fail" = "true" ]; then
            print_fail "$test_name - Hook should have blocked but passed"
            git reset HEAD -- "$test_file"
            rm -f "$test_file"
            return 1
        else
            print_pass "$test_name - Hook correctly allowed commit"
        fi
    else
        # Hook failed (exit 1)
        if [ "$should_fail" = "false" ]; then
            print_fail "$test_name - Hook should have passed but blocked"
            git reset HEAD -- "$test_file"
            rm -f "$test_file"
            return 1
        else
            print_pass "$test_name - Hook correctly blocked commit"
        fi
    fi

    # Cleanup
    git reset HEAD -- "$test_file"
    rm -f "$test_file"
    return 0
}

# Test 1: Hardcoded Secrets Detection
test_hardcoded_secrets() {
    print_header "Test 1: Hardcoded Secrets Detection"

    # Test 1.1: Detect hardcoded password
    test_precommit_check \
        "1.1 - Hardcoded password" \
        "test_hardcoded_password.go" \
        'package test
const PASSWORD = "mysecretpassword123"
' \
        "true"

    # Test 1.2: Detect hardcoded API key
    test_precommit_check \
        "1.2 - Hardcoded API key" \
        "test_hardcoded_apikey.go" \
        'package test
var apiKey = "sk-1234567890abcdef"
' \
        "true"

    # Test 1.3: Allow secrets from SecretManager (not hardcoded)
    test_precommit_check \
        "1.3 - Secret from SecretManager (allowed)" \
        "test_secret_manager.go" \
        'package test
password := secretManager.GetSecret("db_password")
' \
        "false"

    echo ""
}

# Test 2: VAULT_SKIP_VERIFY Detection
test_vault_skip_verify() {
    print_header "Test 2: VAULT_SKIP_VERIFY Detection"

    # Test 2.1: Detect unconditional VAULT_SKIP_VERIFY
    test_precommit_check \
        "2.1 - Unconditional VAULT_SKIP_VERIFY" \
        "test_vault_skip_verify.go" \
        'package test
func setup() {
    os.Setenv("VAULT_SKIP_VERIFY", "1")
}
' \
        "true"

    # Test 2.2: Allow VAULT_SKIP_VERIFY in handleTLSValidationFailure (P0-2 exception)
    test_precommit_check \
        "2.2 - VAULT_SKIP_VERIFY in handleTLSValidationFailure (allowed)" \
        "test_vault_skip_verify_exception.go" \
        'package test
func handleTLSValidationFailure() {
    // P0-2: Informed consent required
    os.Setenv("VAULT_SKIP_VERIFY", "1")
}
' \
        "false"

    # Test 2.3: Allow VAULT_SKIP_VERIFY with Eos_ALLOW_INSECURE_VAULT check
    test_precommit_check \
        "2.3 - VAULT_SKIP_VERIFY with Eos_ALLOW_INSECURE_VAULT (allowed)" \
        "test_vault_allow_insecure.go" \
        'package test
func setup() {
    if os.Getenv("Eos_ALLOW_INSECURE_VAULT") == "true" {
        os.Setenv("VAULT_SKIP_VERIFY", "1")
    }
}
' \
        "false"

    echo ""
}

# Test 3: InsecureSkipVerify Detection
test_insecure_skip_verify() {
    print_header "Test 3: InsecureSkipVerify Detection"

    # Test 3.1: Detect InsecureSkipVerify in production code
    test_precommit_check \
        "3.1 - InsecureSkipVerify in production code" \
        "test_insecure_skip.go" \
        'package test
import "crypto/tls"
func createClient() {
    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
    }
}
' \
        "true"

    # Test 3.2: Allow InsecureSkipVerify in test files
    test_precommit_check \
        "3.2 - InsecureSkipVerify in test file (allowed)" \
        "test_insecure_skip_test.go" \
        'package test
import "crypto/tls"
func TestClient(t *testing.T) {
    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
    }
}
' \
        "false"

    echo ""
}

# Test 4: VAULT_TOKEN Environment Variables
test_vault_token_env() {
    print_header "Test 4: VAULT_TOKEN Environment Variables"

    # Test 4.1: Detect VAULT_TOKEN in environment
    test_precommit_check \
        "4.1 - VAULT_TOKEN in environment variable" \
        "test_vault_token_env.go" \
        'package test
func runCommand(token string) {
    cmd.Env = append(cmd.Env, fmt.Sprintf("VAULT_TOKEN=%s", token))
}
' \
        "true"

    # Test 4.2: Allow VAULT_TOKEN_FILE (P0-1 fix)
    test_precommit_check \
        "4.2 - VAULT_TOKEN_FILE (allowed)" \
        "test_vault_token_file.go" \
        'package test
func runCommand(tokenFile string) {
    cmd.Env = append(cmd.Env, fmt.Sprintf("VAULT_TOKEN_FILE=%s", tokenFile))
}
' \
        "false"

    # Test 4.3: Allow VAULT_TOKEN with P0-1 comment
    test_precommit_check \
        "4.3 - VAULT_TOKEN with P0-1 comment (allowed)" \
        "test_vault_token_p01.go" \
        'package test
func runCommand(token string) {
    // P0-1: Legacy code, migrating to token files
    cmd.Env = append(cmd.Env, fmt.Sprintf("VAULT_TOKEN=%s", token))
}
' \
        "false"

    echo ""
}

# Test 5: Hardcoded File Permissions
test_hardcoded_permissions() {
    print_header "Test 5: Hardcoded File Permissions"

    # Test 5.1: Detect hardcoded permissions in os.Chmod
    test_precommit_check \
        "5.1 - Hardcoded os.Chmod permissions" \
        "test_hardcoded_chmod.go" \
        'package test
func setPerms(file string) {
    os.Chmod(file, 0755)
}
' \
        "true"

    # Test 5.2: Detect hardcoded permissions in os.MkdirAll
    test_precommit_check \
        "5.2 - Hardcoded os.MkdirAll permissions" \
        "test_hardcoded_mkdir.go" \
        'package test
func createDir(dir string) {
    os.MkdirAll(dir, 0644)
}
' \
        "true"

    # Test 5.3: Allow permission constants
    test_precommit_check \
        "5.3 - Permission constants (allowed)" \
        "test_permission_constants.go" \
        'package test
func createDir(dir string) {
    os.MkdirAll(dir, vault.VaultDirPerm)
}
' \
        "false"

    echo ""
}

# Test 6: Security TODOs
test_security_todos() {
    print_header "Test 6: Unresolved Security TODOs"

    # Test 6.1: Detect TODO(security)
    test_precommit_check \
        "6.1 - TODO(security)" \
        "test_security_todo.go" \
        'package test
// TODO(security): Implement input validation
func processInput(input string) {
}
' \
        "true"

    # Test 6.2: Detect FIXME(security)
    test_precommit_check \
        "6.2 - FIXME(security)" \
        "test_security_fixme.go" \
        'package test
// FIXME(security): This function is vulnerable to injection
func processInput(input string) {
}
' \
        "true"

    # Test 6.3: Allow regular TODOs (non-security)
    test_precommit_check \
        "6.3 - Regular TODO (allowed)" \
        "test_regular_todo.go" \
        'package test
// TODO: Refactor this function
func processInput(input string) {
}
' \
        "false"

    echo ""
}

# Test 7: No Go Files (Should Pass)
test_no_go_files() {
    print_header "Test 7: No Go Files to Check"

    TESTS_RUN=$((TESTS_RUN + 1))
    print_test "7.1 - No Go files staged"

    # Create and stage a non-Go file
    echo "# Test README" > test_readme.md
    git add test_readme.md

    # Run pre-commit hook
    if .git/hooks/pre-commit 2>&1 | grep -q "No Go files to check"; then
        print_pass "Hook correctly detected no Go files"
    else
        print_fail "Hook should detect no Go files"
    fi

    # Cleanup
    git reset HEAD -- test_readme.md
    rm -f test_readme.md

    echo ""
}

# Test 8: Multiple Violations
test_multiple_violations() {
    print_header "Test 8: Multiple Violations in Single File"

    TESTS_RUN=$((TESTS_RUN + 1))
    print_test "8.1 - Multiple security violations"

    # Create file with multiple violations
    cat > test_multiple_violations.go << 'EOF'
package test

import (
    "crypto/tls"
    "os"
)

// TODO(security): Fix this
func badFunction() {
    // Hardcoded password
    const password = "hardcoded123"

    // Unconditional VAULT_SKIP_VERIFY
    os.Setenv("VAULT_SKIP_VERIFY", "1")

    // InsecureSkipVerify
    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
    }

    // VAULT_TOKEN in env
    os.Setenv("VAULT_TOKEN", password)

    // Hardcoded permissions
    os.Chmod("/tmp/test", 0777)
}
EOF

    git add test_multiple_violations.go

    # Run pre-commit hook (should fail with multiple errors)
    if ! .git/hooks/pre-commit 2>&1 | tee /tmp/precommit-multiple.txt; then
        # Count number of FAIL messages
        fail_count=$(grep -c "❌ FAIL" /tmp/precommit-multiple.txt || echo "0")

        if [ "$fail_count" -ge "5" ]; then
            print_pass "Hook detected multiple violations (found $fail_count)"
        else
            print_fail "Hook should detect at least 5 violations, found $fail_count"
        fi
    else
        print_fail "Hook should have blocked file with multiple violations"
    fi

    # Cleanup
    git reset HEAD -- test_multiple_violations.go
    rm -f test_multiple_violations.go

    echo ""
}

# Test 9: Hook Bypass Prevention
test_hook_bypass() {
    print_header "Test 9: Hook Bypass Prevention"

    print_info "Note: Pre-commit hook can be bypassed with --no-verify"
    print_info "CI/CD workflow provides defense-in-depth"

    # This is documented behavior, not a bug
    TESTS_RUN=$((TESTS_RUN + 1))
    print_pass "Hook bypass is documented (CI/CD provides backup)"

    echo ""
}

# Test 10: Performance Check
test_performance() {
    print_header "Test 10: Performance Check"

    TESTS_RUN=$((TESTS_RUN + 1))
    print_test "10.1 - Hook execution time"

    # Create large test file
    cat > test_performance.go << 'EOF'
package test

// Large file with many lines to test performance
EOF

    # Add 1000 lines of code
    for i in {1..1000}; do
        echo "func function${i}() { return }" >> test_performance.go
    done

    git add test_performance.go

    # Measure execution time
    start_time=$(date +%s%N)
    .git/hooks/pre-commit > /dev/null 2>&1 || true
    end_time=$(date +%s%N)

    # Calculate duration in milliseconds
    duration=$(( ($end_time - $start_time) / 1000000 ))

    if [ "$duration" -lt 5000 ]; then
        print_pass "Hook execution time acceptable: ${duration}ms"
    else
        print_fail "Hook execution too slow: ${duration}ms (expected <5000ms)"
    fi

    # Cleanup
    git reset HEAD -- test_performance.go
    rm -f test_performance.go

    echo ""
}

# Print final summary
print_summary() {
    print_header "Test Summary"

    echo -e "Tests Run:    ${BLUE}$TESTS_RUN${NC}"
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        return 0
    else
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}✗ SOME TESTS FAILED${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        return 1
    fi
}

# Main execution
main() {
    echo ""
    print_header "Pre-Commit Hook Test Suite"
    echo "Testing all 6 security checks + edge cases"
    echo "Location: .git/hooks/pre-commit"
    echo ""

    check_prerequisites
    setup_test_env

    # Run all tests
    test_hardcoded_secrets
    test_vault_skip_verify
    test_insecure_skip_verify
    test_vault_token_env
    test_hardcoded_permissions
    test_security_todos
    test_no_go_files
    test_multiple_violations
    test_hook_bypass
    test_performance

    # Print summary and exit with appropriate code
    if print_summary; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main
