#!/bin/bash
# Comprehensive test runner for Eos - includes unit tests, integration tests, and fuzzing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TEST_TIMEOUT="${TEST_TIMEOUT:-10m}"
FUZZ_DURATION="${FUZZ_DURATION:-30s}"
COVERAGE_THRESHOLD="${COVERAGE_THRESHOLD:-80}"
LOG_DIR="${LOG_DIR:-/tmp/eos-test-logs}"
PARALLEL_JOBS="${PARALLEL_JOBS:-$(nproc)}"

# Create log directory
mkdir -p "$LOG_DIR"

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Timestamp for logs
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$LOG_DIR/test-report-$TIMESTAMP.md"

# Function to print section headers
print_header() {
    echo -e "\n${CYAN}===========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}===========================================${NC}\n"
}

# Function to run tests with timing
run_test_suite() {
    local suite_name=$1
    local test_command=$2
    local log_file="$LOG_DIR/${suite_name}-$TIMESTAMP.log"
    
    echo -e "${BLUE}🧪 Running $suite_name...${NC}"
    
    local start_time=$(date +%s)
    
    if eval "$test_command" > "$log_file" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${GREEN} $suite_name passed (${duration}s)${NC}"
        ((PASSED_TESTS++))
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${RED}❌ $suite_name failed (${duration}s)${NC}"
        echo -e "${YELLOW}   See log: $log_file${NC}"
        ((FAILED_TESTS++))
        return 1
    fi
}

# Start report
cat > "$REPORT_FILE" << EOF
# Eos Comprehensive Test Report
**Generated**: $(date)
**System**: $(uname -a)
**Go Version**: $(go version)

## Test Configuration
- Test Timeout: $TEST_TIMEOUT
- Fuzz Duration: $FUZZ_DURATION
- Coverage Threshold: $COVERAGE_THRESHOLD%
- Parallel Jobs: $PARALLEL_JOBS

## Test Results

EOF

print_header "Eos Comprehensive Test Suite"

# 1. Build verification
print_header "1. Build Verification"
echo -e "${BLUE}🔨 Compiling all packages...${NC}"
if go build -o /tmp/eos-test-build ./cmd/ > "$LOG_DIR/build-$TIMESTAMP.log" 2>&1; then
    echo -e "${GREEN} Build successful${NC}"
else
    echo -e "${RED}❌ Build failed${NC}"
    echo -e "${RED}Cannot continue with tests. See $LOG_DIR/build-$TIMESTAMP.log${NC}"
    exit 1
fi

# 2. Linting
print_header "2. Code Quality Checks"
run_test_suite "Linting" "golangci-lint run --timeout 5m"

# 3. Unit Tests with Coverage
print_header "3. Unit Tests with Coverage"

# Run unit tests for each critical package
CRITICAL_PACKAGES=(
    "vault"
    "crypto"
    "authentication"
    "execute"
    "eos_io"
    "eos_err"
    "security"
)

echo -e "${BLUE}📊 Running unit tests for critical packages...${NC}"
COVERAGE_FILE="$LOG_DIR/coverage-$TIMESTAMP.out"

# Run tests with coverage
if go test -v -timeout="$TEST_TIMEOUT" \
    -coverprofile="$COVERAGE_FILE" \
    -covermode=atomic \
    ./pkg/... > "$LOG_DIR/unit-tests-$TIMESTAMP.log" 2>&1; then
    echo -e "${GREEN} Unit tests passed${NC}"
    ((PASSED_TESTS++))
    
    # Generate coverage report
    go tool cover -html="$COVERAGE_FILE" -o "$LOG_DIR/coverage-$TIMESTAMP.html"
    
    # Check coverage percentage
    COVERAGE=$(go tool cover -func="$COVERAGE_FILE" | grep total | awk '{print $3}' | sed 's/%//')
    echo -e "${BLUE}📊 Total coverage: ${COVERAGE}%${NC}"
    
    if (( $(echo "$COVERAGE < $COVERAGE_THRESHOLD" | bc -l) )); then
        echo -e "${YELLOW}Coverage ${COVERAGE}% is below threshold ${COVERAGE_THRESHOLD}%${NC}"
    else
        echo -e "${GREEN} Coverage ${COVERAGE}% meets threshold${NC}"
    fi
else
    echo -e "${RED}❌ Unit tests failed${NC}"
    ((FAILED_TESTS++))
fi

# 4. Security-Critical Package Tests
print_header "4. Security-Critical Package Tests"

for pkg in "${CRITICAL_PACKAGES[@]}"; do
    run_test_suite "Package $pkg tests" "go test -v -timeout=2m ./pkg/$pkg/..."
    ((TOTAL_TESTS++))
done

# 5. Fuzz Testing
print_header "5. Fuzz Testing"

echo -e "${BLUE}🔀 Running fuzz tests for security-critical functions...${NC}"

# Define fuzz targets
declare -A FUZZ_TARGETS=(
    ["pkg/vault"]="FuzzValidateVaultPath,FuzzSanitizeVaultToken,FuzzParseVaultResponse"
    ["pkg/authentication"]="FuzzValidateUsername,FuzzValidatePassword,FuzzValidateEmail"
    ["pkg/execute"]="FuzzCommandExecution,FuzzCommandValidation,FuzzArgumentValidation"
    ["pkg/crypto"]="FuzzValidateStrongPassword,FuzzHashString,FuzzRedact"
    ["pkg/security"]="FuzzValidateNoShellMeta,FuzzSanitizeInput"
)

FUZZ_FAILED=0
for pkg in "${!FUZZ_TARGETS[@]}"; do
    IFS=',' read -ra TESTS <<< "${FUZZ_TARGETS[$pkg]}"
    for test in "${TESTS[@]}"; do
        echo -e "${BLUE}  Running $pkg/$test for $FUZZ_DURATION...${NC}"
        if go test -fuzz="$test" -fuzztime="$FUZZ_DURATION" "./$pkg" \
            > "$LOG_DIR/fuzz-${pkg##*/}-$test-$TIMESTAMP.log" 2>&1; then
            echo -e "${GREEN}     $test passed${NC}"
        else
            echo -e "${RED}    ❌ $test failed or found crashes${NC}"
            ((FUZZ_FAILED++))
        fi
    done
done

if [ $FUZZ_FAILED -eq 0 ]; then
    echo -e "${GREEN} All fuzz tests passed${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ $FUZZ_FAILED fuzz tests failed${NC}"
    ((FAILED_TESTS++))
fi

# 6. Integration Tests
print_header "6. Integration Tests"

if [ -f "./integration_test.go" ]; then
    run_test_suite "Integration tests" "go test -v -timeout=5m -tags=integration ./..."
    ((TOTAL_TESTS++))
else
    echo -e "${YELLOW}No integration tests found${NC}"
fi

# 7. Race Condition Detection
print_header "7. Race Condition Detection"

echo -e "${BLUE}🏃 Running race detector on critical packages...${NC}"
RACE_FAILED=0

for pkg in "${CRITICAL_PACKAGES[@]}"; do
    if go test -race -timeout=2m "./pkg/$pkg/..." > "$LOG_DIR/race-$pkg-$TIMESTAMP.log" 2>&1; then
        echo -e "${GREEN}   $pkg: No races detected${NC}"
    else
        echo -e "${RED}  ❌ $pkg: Race conditions detected${NC}"
        ((RACE_FAILED++))
    fi
done

if [ $RACE_FAILED -eq 0 ]; then
    echo -e "${GREEN} No race conditions detected${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ Race conditions found in $RACE_FAILED packages${NC}"
    ((FAILED_TESTS++))
fi

# 8. Benchmark Tests (optional)
print_header "8. Benchmark Tests"

if [ "${RUN_BENCHMARKS:-false}" = "true" ]; then
    echo -e "${BLUE}📈 Running benchmarks...${NC}"
    go test -bench=. -benchmem -timeout=5m ./pkg/... > "$LOG_DIR/benchmarks-$TIMESTAMP.log" 2>&1
    echo -e "${GREEN} Benchmarks completed${NC}"
    echo -e "${YELLOW}   See results: $LOG_DIR/benchmarks-$TIMESTAMP.log${NC}"
else
    echo -e "${YELLOW}Benchmarks skipped (set RUN_BENCHMARKS=true to enable)${NC}"
fi

# 9. Security Vulnerability Scan
print_header "9. Security Vulnerability Scan"

echo -e "${BLUE}🔒 Checking for known vulnerabilities...${NC}"
if command -v gosec &> /dev/null; then
    if gosec -fmt json -out "$LOG_DIR/security-$TIMESTAMP.json" ./... > /dev/null 2>&1; then
        echo -e "${GREEN} No security vulnerabilities found${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${YELLOW}Security issues found. See $LOG_DIR/security-$TIMESTAMP.json${NC}"
        ((FAILED_TESTS++))
    fi
else
    echo -e "${YELLOW}gosec not installed. Run: go install github.com/securego/gosec/v2/cmd/gosec@latest${NC}"
fi

# 10. Dependency Audit
print_header "10. Dependency Audit"

echo -e "${BLUE} Auditing dependencies...${NC}"
if go list -json -m all | nancy sleuth > "$LOG_DIR/deps-audit-$TIMESTAMP.log" 2>&1; then
    echo -e "${GREEN} No vulnerable dependencies found${NC}"
    ((PASSED_TESTS++))
else
    if command -v nancy &> /dev/null; then
        echo -e "${YELLOW}Dependency vulnerabilities found. See $LOG_DIR/deps-audit-$TIMESTAMP.log${NC}"
        ((FAILED_TESTS++))
    else
        echo -e "${YELLOW}nancy not installed. Run: go install github.com/sonatype-nexus-community/nancy@latest${NC}"
    fi
fi

# Generate final report
print_header "Test Summary"

TOTAL_TESTS=$((PASSED_TESTS + FAILED_TESTS + SKIPPED_TESTS))

cat >> "$REPORT_FILE" << EOF

## Summary

- **Total Test Suites**: $TOTAL_TESTS
- **Passed**: $PASSED_TESTS
- **Failed**: $FAILED_TESTS
- **Skipped**: $SKIPPED_TESTS
- **Coverage**: ${COVERAGE:-N/A}%

## Detailed Results

### Unit Tests
- Coverage: ${COVERAGE:-N/A}%
- Coverage Report: [coverage-$TIMESTAMP.html](coverage-$TIMESTAMP.html)

### Fuzz Tests
- Duration: $FUZZ_DURATION per test
- Failed Tests: $FUZZ_FAILED

### Race Detection
- Packages with races: $RACE_FAILED

## Logs
All detailed logs are available in: $LOG_DIR

## Recommendations

EOF

# Add recommendations based on results
if [ $FAILED_TESTS -gt 0 ]; then
    cat >> "$REPORT_FILE" << EOF
### ⚠️ Action Required
- Fix failing tests before deployment
- Review logs for detailed error information
EOF
fi

if (( $(echo "${COVERAGE:-0} < $COVERAGE_THRESHOLD" | bc -l) )); then
    cat >> "$REPORT_FILE" << EOF
### 📊 Coverage Improvement Needed
- Current coverage (${COVERAGE}%) is below threshold ($COVERAGE_THRESHOLD%)
- Add tests for uncovered code paths
EOF
fi

if [ $RACE_FAILED -gt 0 ]; then
    cat >> "$REPORT_FILE" << EOF
### 🏃 Race Conditions
- Fix race conditions in affected packages
- Use sync primitives appropriately
EOF
fi

# Print summary
echo ""
echo -e "${CYAN}===========================================${NC}"
echo -e "${CYAN}            TEST SUMMARY                   ${NC}"
echo -e "${CYAN}===========================================${NC}"
echo ""
echo -e "Total Test Suites: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo -e "${YELLOW}Skipped: $SKIPPED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    echo -e "${BLUE}📊 Coverage: ${COVERAGE:-N/A}%${NC}"
    echo -e "${BLUE}📄 Full report: $REPORT_FILE${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed!${NC}"
    echo -e "${YELLOW}📄 See full report: $REPORT_FILE${NC}"
    echo -e "${YELLOW}📁 Check logs in: $LOG_DIR${NC}"
    exit 1
fi