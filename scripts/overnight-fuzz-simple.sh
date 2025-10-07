#!/bin/bash
# Simplified overnight fuzzing script for macOS compatibility
# This version runs tests sequentially for better compatibility

set -e

# Source common preflight checks
source "$(dirname "${BASH_SOURCE[0]}")/fuzz-preflight-common.sh"

# Run preflight checks
eos_run_preflight_checks

# Configuration with environment variable overrides
FUZZTIME_LONG="${FUZZTIME_LONG:-8h}"
FUZZTIME_MEDIUM="${FUZZTIME_MEDIUM:-2h}" 
FUZZTIME_SHORT="${FUZZTIME_SHORT:-30m}"
LOG_DIR="${LOG_DIR:-/tmp/eos-fuzz-logs}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${LOG_DIR}/fuzz-report-${TIMESTAMP}.md"

# Create log directory
mkdir -p "${LOG_DIR}"

echo -e "${CYAN}🧪 Starting Overnight Eos Fuzzing at $(date)${NC}"
echo -e " Logs will be saved to: ${YELLOW}${LOG_DIR}${NC}"
echo -e "⏰ Long duration: ${YELLOW}${FUZZTIME_LONG}${NC}"
echo "⏰ Medium duration: ${FUZZTIME_MEDIUM}"
echo "⏰ Short duration: ${FUZZTIME_SHORT}"
echo ""

# Initialize report
cat > "${REPORT_FILE}" << EOF
# Eos Overnight Fuzz Testing Report

**Generated:** $(date)  
**Test Session:** ${TIMESTAMP}  
**Configuration:**
- Long Duration: ${FUZZTIME_LONG}
- Medium Duration: ${FUZZTIME_MEDIUM} 
- Short Duration: ${FUZZTIME_SHORT}
- Log Directory: ${LOG_DIR}

## Test Results

EOF

# Enhanced test runner function
run_fuzz_test() {
    local test_name="$1"
    local package="$2"
    local duration="$3"
    local priority="${4:-medium}"
    local log_file="${LOG_DIR}/${test_name}_${TIMESTAMP}.log"
    local start_time=$(date +%s)
    
    echo "🚀 Running ${test_name} (${duration}, priority: ${priority})..."
    echo "Package: ${package}"
    echo "⏱️  Started at: $(date)"
    echo "📄 Log: ${log_file}"
    
    # Check if test exists first
    if ! go test -list=Fuzz "${package}" 2>/dev/null | grep -q "^${test_name}$"; then
        echo "Test ${test_name} not found in ${package}, skipping..."
        echo "- **${test_name}** (${package}): SKIPPED - test not found" >> "${REPORT_FILE}"
        echo ""
        return 0
    fi
    
    # Run the test
    if go test -v -run=^$ -fuzz=^${test_name}$ -fuzztime="${duration}" "${package}" > "${log_file}" 2>&1; then
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        local inputs=$(grep -c "new interesting input" "${log_file}" 2>/dev/null || echo "0")
        local executions=$(grep -o 'execs: [0-9]*' "${log_file}" | tail -1 | sed 's/execs: //' || echo "0")
        
        echo "${test_name} completed successfully"
        echo "📊 Found ${inputs} new inputs, executed ${executions} cases in ${elapsed}s"
        
        # Update report
        echo "- **${test_name}** (${package}): SUCCESS - ${inputs} inputs, ${executions} executions, ${elapsed}s" >> "${REPORT_FILE}"
        echo ""
        return 0
    else
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        
        echo "❌ ${test_name} failed - check ${log_file}"
        echo " CRASH DETECTED in ${test_name}!" | tee -a "${LOG_DIR}/crashes_${TIMESTAMP}.log"
        
        # Extract crash details
        local crash_line=$(grep -n "panic\|FAIL\|fatal error" "${log_file}" | head -1 || echo "Unknown crash")
        echo "💥 Crash details: ${crash_line}" | tee -a "${LOG_DIR}/crashes_${TIMESTAMP}.log"
        
        # Update report
        echo "- ❌ **${test_name}** (${package}): FAILED - ${elapsed}s, crash: ${crash_line}" >> "${REPORT_FILE}"
        echo ""
        return 1
    fi
}

# Phase 1: Critical System Tests (Sequential)
echo "🔥 Phase 1: Critical System Tests"
echo "### Phase 1: Critical System Tests" >> "${REPORT_FILE}"

run_fuzz_test "FuzzAllEosCommands" "./test" "${FUZZTIME_LONG}" "critical"
run_fuzz_test "FuzzDelphiServicesCommands" "./test" "${FUZZTIME_LONG}" "critical"

# Phase 2: Security-Focused Tests
echo "🛡️ Phase 2: Security-Focused Tests"
echo -e "\n### Phase 2: Security-Focused Tests" >> "${REPORT_FILE}"

run_fuzz_test "FuzzValidateStrongPassword" "./pkg/crypto" "${FUZZTIME_MEDIUM}" "high"
run_fuzz_test "FuzzHashString" "./pkg/crypto" "${FUZZTIME_MEDIUM}" "high"
run_fuzz_test "FuzzRedact" "./pkg/crypto" "${FUZZTIME_MEDIUM}" "high"
run_fuzz_test "FuzzInjectSecretsFromPlaceholders" "./pkg/crypto" "${FUZZTIME_MEDIUM}" "high"

# Phase 3: Command Processing Tests
echo "⚙️ Phase 3: Command Processing Tests"
echo -e "\n### Phase 3: Command Processing Tests" >> "${REPORT_FILE}"

run_fuzz_test "FuzzUpdateCommand" "./cmd/delphi/services" "${FUZZTIME_MEDIUM}" "high"
run_fuzz_test "FuzzServiceWorkerPaths" "./cmd/delphi/services" "${FUZZTIME_SHORT}" "medium"
run_fuzz_test "FuzzCommandParsing" "./pkg/eos_cli" "${FUZZTIME_SHORT}" "medium"
run_fuzz_test "FuzzEosCommandFlags" "./test" "${FUZZTIME_SHORT}" "medium"

# Phase 4: Input Validation Tests
echo "📝 Phase 4: Input Validation Tests"
echo -e "\n### Phase 4: Input Validation Tests" >> "${REPORT_FILE}"

run_fuzz_test "FuzzNormalizeYesNoInput" "./pkg/interaction" "${FUZZTIME_SHORT}" "medium"
run_fuzz_test "FuzzValidateUsername" "./pkg/interaction" "${FUZZTIME_SHORT}" "medium"
run_fuzz_test "FuzzValidateEmail" "./pkg/interaction" "${FUZZTIME_SHORT}" "medium"
run_fuzz_test "FuzzValidateNoShellMeta" "./pkg/interaction" "${FUZZTIME_SHORT}" "medium"

# Phase 5: Parsing & I/O Tests
echo "🗂️ Phase 5: Parsing & I/O Tests"
echo -e "\n### Phase 5: Parsing & I/O Tests" >> "${REPORT_FILE}"

run_fuzz_test "FuzzSplitAndTrim" "./pkg/parse" "${FUZZTIME_SHORT}" "medium"
run_fuzz_test "FuzzYAMLParsing" "./pkg/eos_io" "${FUZZTIME_SHORT}" "medium"
run_fuzz_test "FuzzJSONParsing" "./pkg/parse" "${FUZZTIME_SHORT}" "medium"

# Phase 6: Filesystem & Database Tests
echo "💾 Phase 6: Filesystem & Database Tests"
echo -e "\n### Phase 6: Filesystem & Database Tests" >> "${REPORT_FILE}"

run_fuzz_test "FuzzMkdirP" "./pkg/eos_unix" "${FUZZTIME_SHORT}" "medium"
run_fuzz_test "FuzzExecuteCommand" "./pkg/execute" "${FUZZTIME_SHORT}" "high"
run_fuzz_test "FuzzDatabaseOperations" "./pkg/database_management" "${FUZZTIME_SHORT}" "medium"

# Generate final summary
echo "🏁 Overnight fuzzing completed at $(date)"

# Calculate statistics
total_tests=0
passed_tests=0
failed_tests=0
skipped_tests=0

if [ -f "${REPORT_FILE}" ]; then
    total_tests=$(grep -c "^- " "${REPORT_FILE}" || echo "0")
    passed_tests=$(grep -c "" "${REPORT_FILE}" || echo "0")
    failed_tests=$(grep -c "❌" "${REPORT_FILE}" || echo "0")
    skipped_tests=$(grep -c "" "${REPORT_FILE}" || echo "0")
fi

# Add final summary to report
cat >> "${REPORT_FILE}" << EOF

## Final Summary

**Completion Time:** $(date)  
**Total Tests:** ${total_tests}  
**Passed:** ${passed_tests}  
**Failed:** ${failed_tests}  
**Skipped:** ${skipped_tests}
**Success Rate:** $(if [ ${total_tests} -gt 0 ]; then echo "scale=1; ${passed_tests} * 100 / ${total_tests}" | bc -l; else echo "N/A"; fi)%

**Files Generated:**
- Main Report: ${REPORT_FILE}
- Individual Logs: ${LOG_DIR}/*_${TIMESTAMP}.log
- Crash Log: ${LOG_DIR}/crashes_${TIMESTAMP}.log (if applicable)

EOF

# Check for crashes
if [ -f "${LOG_DIR}/crashes_${TIMESTAMP}.log" ]; then
    crash_count=$(wc -l < "${LOG_DIR}/crashes_${TIMESTAMP}.log" 2>/dev/null || echo "0")
    echo " CRITICAL: ${crash_count} CRASHES DETECTED!"
    echo ""
    echo "Crash Summary:"
    cat "${LOG_DIR}/crashes_${TIMESTAMP}.log"
    echo ""
    
    # Add crashes to report
    echo -e "\n##  CRITICAL ISSUES DETECTED\n" >> "${REPORT_FILE}"
    echo "\`\`\`" >> "${REPORT_FILE}"
    cat "${LOG_DIR}/crashes_${TIMESTAMP}.log" >> "${REPORT_FILE}"
    echo "\`\`\`" >> "${REPORT_FILE}"
    
    exit_code=1
else
    echo "SUCCESS: No crashes detected during overnight fuzzing"
    echo -e "\n## All Tests Passed Successfully\n" >> "${REPORT_FILE}"
    echo "No crashes or critical issues were detected during this fuzzing session." >> "${REPORT_FILE}"
    exit_code=0
fi

echo ""
echo "📊 COMPREHENSIVE SUMMARY:"
echo "========================="
echo " Log directory: ${LOG_DIR}"
echo "📄 Main report: ${REPORT_FILE}"
echo "📈 Tests executed: ${total_tests} (${passed_tests} passed, ${failed_tests} failed, ${skipped_tests} skipped)"
echo ""

echo "🚀 NEXT STEPS:"
echo "=============="
echo "1. Review detailed report: cat '${REPORT_FILE}'"
echo "2. Examine individual logs: ls '${LOG_DIR}'/*_${TIMESTAMP}.log"
echo "3. Quick test run: FUZZTIME_LONG=1m FUZZTIME_MEDIUM=30s FUZZTIME_SHORT=10s ./assets/overnight-fuzz-simple.sh"
echo ""

if [ "${failed_tests}" -eq 0 ]; then
    echo "🎉 Eos framework passed all fuzz tests!"
else
    echo "Please address the ${failed_tests} failed tests before production deployment."
fi

exit ${exit_code}