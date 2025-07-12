#!/bin/bash
# Enhanced overnight fuzzing script for comprehensive security testing

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
FUZZTIME_LONG="${FUZZTIME_LONG:-8h}"
FUZZTIME_MEDIUM="${FUZZTIME_MEDIUM:-2h}"
FUZZTIME_SHORT="${FUZZTIME_SHORT:-30m}"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"
LOG_DIR="${LOG_DIR:-/tmp/eos-fuzz-logs}"
EMAIL_REPORT="${EMAIL_REPORT:-false}"
EMAIL_ADDRESS="${EMAIL_ADDRESS:-}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"

# Create log directory
mkdir -p "$LOG_DIR"

# Timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$LOG_DIR/fuzz-report-enhanced-$TIMESTAMP.md"

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
TOTAL_EXECS=0
CRASHES_FOUND=0

# Function to run fuzz test with logging
run_fuzz_test() {
    local package=$1
    local test=$2
    local duration=$3
    local phase=$4
    
    local log_file="$LOG_DIR/${test}_${TIMESTAMP}.log"
    local test_name="${package}/${test}"
    
    echo -e "${BLUE}[Phase $phase] Fuzzing $test_name for $duration...${NC}"
    
    ((TOTAL_TESTS++))
    
    local start_time=$(date +%s)
    
    if timeout $(($(echo $duration | sed 's/h/*3600+/g;s/m/*60+/g;s/s/+/g;s/+$//')+300)) \
        go test -fuzz="$test" -fuzztime="$duration" "./$package" > "$log_file" 2>&1; then
        
        local end_time=$(date +%s)
        local duration_secs=$((end_time - start_time))
        
        # Extract execution count
        local execs=$(grep -oP 'execs: \K\d+' "$log_file" | tail -1 || echo "0")
        ((TOTAL_EXECS += execs))
        
        echo -e "${GREEN}   $test_name completed successfully${NC}"
        echo -e "${CYAN}     Executions: $execs | Duration: ${duration_secs}s${NC}"
        ((PASSED_TESTS++))
        
        return 0
    else
        local end_time=$(date +%s)
        local duration_secs=$((end_time - start_time))
        
        # Check if it was a crash or timeout
        if grep -q "FAIL.*fuzz" "$log_file"; then
            echo -e "${RED}  ❌ $test_name CRASHED!${NC}"
            ((CRASHES_FOUND++))
            
            # Extract crash details
            echo "### Crash in $test_name" >> "$LOG_DIR/crashes_$TIMESTAMP.log"
            grep -A 10 "FAIL" "$log_file" >> "$LOG_DIR/crashes_$TIMESTAMP.log"
            echo "" >> "$LOG_DIR/crashes_$TIMESTAMP.log"
        else
            echo -e "${YELLOW}  ⚠️  $test_name timed out or failed${NC}"
        fi
        
        echo -e "${CYAN}     Duration: ${duration_secs}s${NC}"
        ((FAILED_TESTS++))
        
        return 1
    fi
}

# Function to run tests in parallel
run_parallel_tests() {
    local phase=$1
    shift
    local tests=("$@")
    
    local pids=()
    local job_count=0
    
    for test_spec in "${tests[@]}"; do
        IFS=':' read -r package test duration <<< "$test_spec"
        
        run_fuzz_test "$package" "$test" "$duration" "$phase" &
        pids+=($!)
        ((job_count++))
        
        # Limit parallel jobs
        if [ $job_count -ge $PARALLEL_JOBS ]; then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
            ((job_count--))
        fi
    done
    
    # Wait for remaining jobs
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
}

# Start report
cat > "$REPORT_FILE" << EOF
# Enhanced Overnight Fuzzing Report
**Started**: $(date)
**Configuration**:
- Long tests: $FUZZTIME_LONG
- Medium tests: $FUZZTIME_MEDIUM  
- Short tests: $FUZZTIME_SHORT
- Parallel jobs: $PARALLEL_JOBS

## Test Phases

EOF

echo -e "${CYAN}🔀 Starting Enhanced Overnight Fuzzing${NC}"
echo -e "${CYAN}===========================================${NC}"

# Phase 1: Critical Security Tests (Sequential)
echo -e "\n${PURPLE}Phase 1: Critical Security Tests${NC}"
cat >> "$REPORT_FILE" << EOF
### Phase 1: Critical Security Tests (Sequential)
Testing core security components with extended duration.

EOF

CRITICAL_TESTS=(
    "pkg/vault:FuzzValidateVaultPath:$FUZZTIME_LONG"
    "pkg/vault:FuzzSanitizeVaultToken:$FUZZTIME_LONG"
    "pkg/authentication:FuzzValidateUsername:$FUZZTIME_LONG"
    "pkg/authentication:FuzzValidatePassword:$FUZZTIME_LONG"
    "pkg/execute:FuzzCommandExecution:$FUZZTIME_LONG"
)

for test_spec in "${CRITICAL_TESTS[@]}"; do
    IFS=':' read -r package test duration <<< "$test_spec"
    run_fuzz_test "$package" "$test" "$duration" "1"
done

# Phase 2: Authentication & Authorization (Parallel)
echo -e "\n${PURPLE}Phase 2: Authentication & Authorization Tests${NC}"
cat >> "$REPORT_FILE" << EOF

### Phase 2: Authentication & Authorization (Parallel)
Testing authentication, authorization, and session management.

EOF

AUTH_TESTS=(
    "pkg/authentication:FuzzValidateEmail:$FUZZTIME_MEDIUM"
    "pkg/authentication:FuzzValidateAPIKey:$FUZZTIME_MEDIUM"
    "pkg/authentication:FuzzJWTValidation:$FUZZTIME_MEDIUM"
    "pkg/authentication:FuzzSessionIDValidation:$FUZZTIME_MEDIUM"
)

run_parallel_tests "2" "${AUTH_TESTS[@]}"

# Phase 3: Command & Input Security (Parallel)
echo -e "\n${PURPLE}Phase 3: Command & Input Security Tests${NC}"
cat >> "$REPORT_FILE" << EOF

### Phase 3: Command & Input Security (Parallel)
Testing command execution, input validation, and injection prevention.

EOF

COMMAND_TESTS=(
    "pkg/execute:FuzzCommandValidation:$FUZZTIME_MEDIUM"
    "pkg/execute:FuzzArgumentValidation:$FUZZTIME_MEDIUM"
    "pkg/execute:FuzzEnvironmentVariables:$FUZZTIME_MEDIUM"
    "pkg/execute:FuzzCommandTimeout:$FUZZTIME_SHORT"
    "pkg/execute:FuzzCommandChaining:$FUZZTIME_MEDIUM"
)

run_parallel_tests "3" "${COMMAND_TESTS[@]}"

# Phase 4: Cryptographic Operations (Parallel)
echo -e "\n${PURPLE}Phase 4: Cryptographic Operations Tests${NC}"
cat >> "$REPORT_FILE" << EOF

### Phase 4: Cryptographic Operations (Parallel)
Testing encryption, hashing, and cryptographic validation.

EOF

CRYPTO_TESTS=(
    "pkg/crypto:FuzzValidateStrongPassword:$FUZZTIME_MEDIUM"
    "pkg/crypto:FuzzHashString:$FUZZTIME_MEDIUM"
    "pkg/crypto:FuzzRedact:$FUZZTIME_SHORT"
    "pkg/crypto:FuzzInjectSecretsFromPlaceholders:$FUZZTIME_SHORT"
)

run_parallel_tests "4" "${CRYPTO_TESTS[@]}"

# Phase 5: Vault Security (Parallel)
echo -e "\n${PURPLE}Phase 5: Vault Security Tests${NC}"
cat >> "$REPORT_FILE" << EOF

### Phase 5: Vault Security (Parallel)
Testing vault policy validation and response parsing.

EOF

VAULT_TESTS=(
    "pkg/vault:FuzzParseVaultResponse:$FUZZTIME_SHORT"
    "pkg/vault:FuzzVaultPolicyValidation:$FUZZTIME_SHORT"
    "pkg/vault:FuzzVaultUnsealKeyValidation:$FUZZTIME_SHORT"
)

run_parallel_tests "5" "${VAULT_TESTS[@]}"

# Phase 6: Input Sanitization (Parallel)
echo -e "\n${PURPLE}Phase 6: Input Sanitization Tests${NC}"
cat >> "$REPORT_FILE" << EOF

### Phase 6: Input Sanitization (Parallel)
Testing input validation and sanitization across the system.

EOF

if [ -d "pkg/security" ]; then
    SANITIZATION_TESTS=(
        "pkg/security:FuzzValidateNoShellMeta:$FUZZTIME_SHORT"
        "pkg/security:FuzzSanitizeInput:$FUZZTIME_SHORT"
    )
    run_parallel_tests "6" "${SANITIZATION_TESTS[@]}"
fi

# Phase 7: Parser Security (Parallel)
echo -e "\n${PURPLE}Phase 7: Parser Security Tests${NC}"
cat >> "$REPORT_FILE" << EOF

### Phase 7: Parser Security (Parallel)
Testing parsers for various data formats.

EOF

if [ -d "pkg/parse" ]; then
    PARSER_TESTS=(
        "pkg/parse:FuzzYAMLParsing:$FUZZTIME_SHORT"
        "pkg/parse:FuzzJSONParsing:$FUZZTIME_SHORT"
    )
    run_parallel_tests "7" "${PARSER_TESTS[@]}"
fi

# Generate summary
echo -e "\n${CYAN}===========================================${NC}"
echo -e "${CYAN}Generating summary report...${NC}"

END_TIME=$(date +"%Y-%m-%d %H:%M:%S")
TOTAL_DURATION=$(($(date +%s) - $(date -d "$TIMESTAMP" +%s 2>/dev/null || date -j -f "%Y%m%d_%H%M%S" "$TIMESTAMP" +%s)))

cat >> "$REPORT_FILE" << EOF

## Summary

**Completed**: $END_TIME
**Total Duration**: $((TOTAL_DURATION / 3600))h $((TOTAL_DURATION % 3600 / 60))m

### Results
- **Total Tests**: $TOTAL_TESTS
- **Passed**: $PASSED_TESTS
- **Failed**: $FAILED_TESTS
- **Crashes Found**: $CRASHES_FOUND
- **Total Executions**: $TOTAL_EXECS

### Success Rate
$((PASSED_TESTS * 100 / TOTAL_TESTS))% ($PASSED_TESTS/$TOTAL_TESTS)

EOF

if [ $CRASHES_FOUND -gt 0 ]; then
    cat >> "$REPORT_FILE" << EOF

### ⚠️ Crashes Detected
$CRASHES_FOUND crashes were found during fuzzing.
See detailed crash logs: $LOG_DIR/crashes_$TIMESTAMP.log

EOF
fi

# Performance metrics
if [ $TOTAL_EXECS -gt 0 ] && [ $TOTAL_DURATION -gt 0 ]; then
    EXECS_PER_SEC=$((TOTAL_EXECS / TOTAL_DURATION))
    cat >> "$REPORT_FILE" << EOF

### Performance
- Average executions/second: $EXECS_PER_SEC
- Total test executions: $TOTAL_EXECS

EOF
fi

# Add recommendations
cat >> "$REPORT_FILE" << EOF

## Recommendations

EOF

if [ $CRASHES_FOUND -gt 0 ]; then
    cat >> "$REPORT_FILE" << EOF
1. **Fix Crashes**: Investigate and fix the $CRASHES_FOUND crashes found
2. **Re-run Tests**: After fixes, re-run fuzzing to verify
EOF
fi

if [ $FAILED_TESTS -gt 0 ]; then
    cat >> "$REPORT_FILE" << EOF
3. **Review Failures**: Check logs for the $FAILED_TESTS failed tests
4. **Timeout Analysis**: Some failures may be due to timeouts
EOF
fi

cat >> "$REPORT_FILE" << EOF

## Next Steps
1. Review crash logs if any crashes were found
2. Analyze coverage of fuzzed functions
3. Add seed corpus from interesting inputs
4. Consider extending fuzz duration for critical functions

## Log Files
All detailed logs available in: $LOG_DIR

---
*Generated by Enhanced Overnight Fuzzing Script*
EOF

# Print summary
echo -e "\n${CYAN}===========================================${NC}"
echo -e "${CYAN}           FUZZING SUMMARY                 ${NC}"
echo -e "${CYAN}===========================================${NC}"
echo ""
echo -e "Total Tests:     $TOTAL_TESTS"
echo -e "${GREEN}Passed:          $PASSED_TESTS${NC}"
echo -e "${RED}Failed:          $FAILED_TESTS${NC}"
echo -e "${RED}Crashes Found:   $CRASHES_FOUND${NC}"
echo -e "Total Executions: $TOTAL_EXECS"
echo -e "Duration:        $((TOTAL_DURATION / 3600))h $((TOTAL_DURATION % 3600 / 60))m"
echo ""

# Send notifications if configured
if [ "$EMAIL_REPORT" = "true" ] && [ -n "$EMAIL_ADDRESS" ]; then
    echo -e "${BLUE}📧 Sending email report...${NC}"
    mail -s "Eos Fuzzing Report - $CRASHES_FOUND crashes found" "$EMAIL_ADDRESS" < "$REPORT_FILE"
fi

if [ -n "$SLACK_WEBHOOK" ]; then
    echo -e "${BLUE}💬 Sending Slack notification...${NC}"
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"Eos Fuzzing Complete: $PASSED_TESTS passed, $FAILED_TESTS failed, $CRASHES_FOUND crashes found\"}" \
        "$SLACK_WEBHOOK" 2>/dev/null
fi

echo -e "${BLUE}📄 Full report: $REPORT_FILE${NC}"

if [ $CRASHES_FOUND -gt 0 ]; then
    echo -e "${RED}⚠️  Crashes detected! See: $LOG_DIR/crashes_$TIMESTAMP.log${NC}"
    exit 1
else
    echo -e "${GREEN} Fuzzing completed successfully!${NC}"
    exit 0
fi