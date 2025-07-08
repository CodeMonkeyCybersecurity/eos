#!/bin/bash
# Enhanced overnight fuzzing script for comprehensive Eos security testing
# This script runs extended fuzz tests with detailed reporting and monitoring

set -e

# Source common preflight checks
source "$(dirname "${BASH_SOURCE[0]}")/fuzz-preflight-common.sh"

# Run preflight checks
eos_run_preflight_checks

# Configuration
FUZZTIME_LONG="${FUZZTIME_LONG:-8h}"     # 8 hours per critical test
FUZZTIME_MEDIUM="${FUZZTIME_MEDIUM:-2h}" # 2 hours per important test  
FUZZTIME_SHORT="${FUZZTIME_SHORT:-30m}"  # 30 minutes for basic tests
LOG_DIR="${LOG_DIR:-/tmp/eos-fuzz-logs}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${LOG_DIR}/fuzz-report-${TIMESTAMP}.md"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"
EMAIL_REPORT="${EMAIL_REPORT:-false}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"

# Create log directory
mkdir -p "${LOG_DIR}"

echo -e "${CYAN}🌙 Starting overnight Eos fuzzing at $(date)${NC}"
echo -e " Logs will be saved to: ${YELLOW}${LOG_DIR}${NC}"
echo -e "⏰ Long fuzz duration: ${YELLOW}${FUZZTIME_LONG}${NC}"
echo -e "⏰ Medium fuzz duration: ${YELLOW}${FUZZTIME_MEDIUM}${NC}"
echo -e "⏰ Short fuzz duration: ${YELLOW}${FUZZTIME_SHORT}${NC}"
echo ""

# Enhanced fuzz test runner with parallel execution and detailed logging
run_fuzz_test() {
    local test_name="$1"
    local package="$2"
    local duration="$3"
    local priority="${4:-medium}"
    local log_file="${LOG_DIR}/${test_name}_${TIMESTAMP}.log"
    local start_time=$(date +%s)
    
    echo "🚀 Starting ${test_name} (${duration}, priority: ${priority})..."
    echo "Package: ${package}"
    echo "⏱️  Started at: $(date)"
    echo "📄 Log: ${log_file}"
    
    # Run test with timeout protection (macOS compatible)
    timeout_cmd="timeout"
    if command -v gtimeout >/dev/null 2>&1; then
        timeout_cmd="gtimeout"
    elif ! command -v timeout >/dev/null 2>&1; then
        timeout_cmd=""  # No timeout available
    fi
    
    if [ -n "${timeout_cmd}" ]; then
        timeout_duration="$(($(echo ${duration} | sed 's/[^0-9]*//g') + 300))"
        ${timeout_cmd} "${timeout_duration}" go test -run=^$ -fuzz=^${test_name}$ -fuzztime="${duration}" -parallel="${PARALLEL_JOBS}" "${package}" > "${log_file}" 2>&1
        test_result=$?
    else
        go test -run=^$ -fuzz=^${test_name}$ -fuzztime="${duration}" -parallel="${PARALLEL_JOBS}" "${package}" > "${log_file}" 2>&1
        test_result=$?
    fi
    
    if [ ${test_result} -eq 0 ]; then
        
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        local inputs=$(grep -c "new interesting input" "${log_file}" 2>/dev/null || echo "0")
        local executions=$(grep -oP 'elapsed: \d+.*?execs: \K\d+' "${log_file}" | tail -1 || echo "0")
        
        echo "${test_name} completed successfully"
        echo "📊 Found ${inputs} new interesting inputs"
        echo "🔄 Executed ${executions} test cases"
        echo "⏰ Duration: ${elapsed}s"
        
        # Update report
        echo "- **${test_name}** (${package}): SUCCESS - ${inputs} inputs, ${executions} executions, ${elapsed}s" >> "${REPORT_FILE}"
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
    fi
    echo ""
}

# Parallel test runner for improved performance (bash 3.x compatible)
run_parallel_tests() {
    local array_name="$1"
    local max_parallel=$2
    
    # Get array contents dynamically (bash 3.x compatible)
    eval "local test_array=(\"\${${array_name}[@]}\")"
    
    echo "🔄 Running ${#test_array[@]} tests with ${max_parallel} parallel jobs..."
    
    local pids=()
    local active_jobs=0
    
    for test_spec in "${test_array[@]}"; do
        # Wait if we've reached max parallel jobs
        while [[ ${active_jobs} -ge ${max_parallel} ]]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[i]}" 2>/dev/null; then
                    wait "${pids[i]}"
                    unset "pids[i]"
                    ((active_jobs--))
                fi
            done
            sleep 1
        done
        
        # Parse test specification: "test_name|package|duration|priority"
        IFS='|' read -r test_name package duration priority <<< "${test_spec}"
        
        # Start test in background
        run_fuzz_test "${test_name}" "${package}" "${duration}" "${priority}" &
        local pid=$!
        pids+=("${pid}")
        ((active_jobs++))
        
        sleep 2  # Brief delay between test starts
    done
    
    # Wait for all remaining jobs
    for pid in "${pids[@]}"; do
        wait "${pid}"
    done
}

# Initialize comprehensive report
cat > "${REPORT_FILE}" << EOF
# Eos Overnight Fuzz Testing Report

**Generated:** $(date)  
**Test Session:** ${TIMESTAMP}  
**Configuration:**
- Long Duration: ${FUZZTIME_LONG}
- Medium Duration: ${FUZZTIME_MEDIUM} 
- Short Duration: ${FUZZTIME_SHORT}
- Parallel Jobs: ${PARALLEL_JOBS}
- Log Directory: ${LOG_DIR}

## Test Results

EOF

echo "Initializing comprehensive fuzz test suite..."
echo " Report will be saved to: ${REPORT_FILE}"

# Define test suites with priorities
declare -a critical_tests=(
    "FuzzAllEosCommands|./test|${FUZZTIME_LONG}|critical"
    "FuzzDelphiServicesCommands|./test|${FUZZTIME_LONG}|critical"
)

declare -a security_tests=(
    "FuzzValidateStrongPassword|./pkg/crypto|${FUZZTIME_MEDIUM}|high"
    "FuzzHashString|./pkg/crypto|${FUZZTIME_MEDIUM}|high"
    "FuzzRedact|./pkg/crypto|${FUZZTIME_MEDIUM}|high"
    "FuzzInjectSecretsFromPlaceholders|./pkg/crypto|${FUZZTIME_MEDIUM}|high"
    "FuzzHashStrings|./pkg/crypto|${FUZZTIME_SHORT}|medium"
    "FuzzAllUnique|./pkg/crypto|${FUZZTIME_SHORT}|medium"
    "FuzzSecureZero|./pkg/crypto|${FUZZTIME_SHORT}|medium"
)

declare -a command_tests=(
    "FuzzUpdateCommand|./cmd/delphi/services|${FUZZTIME_MEDIUM}|high"
    "FuzzServiceWorkerPaths|./cmd/delphi/services|${FUZZTIME_SHORT}|medium"
    "FuzzCommandParsing|./pkg/eos_cli|${FUZZTIME_SHORT}|medium"
    "FuzzEosCommandFlags|./test|${FUZZTIME_SHORT}|medium"
)

declare -a input_validation_tests=(
    "FuzzNormalizeYesNoInput|./pkg/interaction|${FUZZTIME_SHORT}|medium"
    "FuzzValidateUsername|./pkg/interaction|${FUZZTIME_SHORT}|medium"
    "FuzzValidateEmail|./pkg/interaction|${FUZZTIME_SHORT}|medium"
    "FuzzValidateNoShellMeta|./pkg/interaction|${FUZZTIME_SHORT}|medium"
    "FuzzValidateNonEmpty|./pkg/interaction|${FUZZTIME_SHORT}|low"
    "FuzzValidateURL|./pkg/interaction|${FUZZTIME_SHORT}|low"
    "FuzzValidateIP|./pkg/interaction|${FUZZTIME_SHORT}|low"
)

declare -a parsing_tests=(
    "FuzzSplitAndTrim|./pkg/parse|${FUZZTIME_SHORT}|medium"
    "FuzzYAMLParsing|./pkg/eos_io|${FUZZTIME_SHORT}|medium"
    "FuzzJSONParsing|./pkg/parse|${FUZZTIME_SHORT}|medium"
)

declare -a filesystem_tests=(
    "FuzzMkdirP|./pkg/eos_unix|${FUZZTIME_SHORT}|medium"
    "FuzzExecuteCommand|./pkg/execute|${FUZZTIME_SHORT}|high"
)

declare -a database_tests=(
    "FuzzDatabaseOperations|./pkg/database_management|${FUZZTIME_SHORT}|medium"
)

# Execute test suites sequentially for critical tests, parallel for others
echo "🔥 Phase 1: Critical System Tests (Sequential)"
echo "### Phase 1: Critical System Tests" >> "${REPORT_FILE}"
for test_spec in "${critical_tests[@]}"; do
    IFS='|' read -r test_name package duration priority <<< "${test_spec}"
    run_fuzz_test "${test_name}" "${package}" "${duration}" "${priority}"
done

echo "🛡️ Phase 2: Security-Focused Tests (Parallel)"
echo -e "\n### Phase 2: Security-Focused Tests" >> "${REPORT_FILE}"
run_parallel_tests security_tests 3

echo "⚙️ Phase 3: Command Processing Tests (Parallel)" 
echo -e "\n### Phase 3: Command Processing Tests" >> "${REPORT_FILE}"
run_parallel_tests command_tests 4

echo "📝 Phase 4: Input Validation Tests (Parallel)"
echo -e "\n### Phase 4: Input Validation Tests" >> "${REPORT_FILE}"
run_parallel_tests input_validation_tests 4

echo "🗂️ Phase 5: Parsing & I/O Tests (Parallel)"
echo -e "\n### Phase 5: Parsing & I/O Tests" >> "${REPORT_FILE}"
run_parallel_tests parsing_tests 4

echo "💾 Phase 6: Filesystem & Database Tests (Parallel)"
echo -e "\n### Phase 6: Filesystem & Database Tests" >> "${REPORT_FILE}"
run_parallel_tests filesystem_tests 2
run_parallel_tests database_tests 2

# Generate comprehensive final report
echo "🏁 Overnight fuzzing completed at $(date)"

# Calculate comprehensive statistics
total_tests=0
passed_tests=0
failed_tests=0
total_inputs=0
total_executions=0
total_duration=0

for log_file in "${LOG_DIR}"/*_"${TIMESTAMP}".log; do
    if [ -f "$log_file" ]; then
        ((total_tests++))
        inputs=$(grep -c "new interesting input" "$log_file" 2>/dev/null || echo "0")
        total_inputs=$((total_inputs + inputs))
        
        executions=$(grep -oP 'elapsed: \d+.*?execs: \K\d+' "$log_file" | tail -1 || echo "0")
        total_executions=$((total_executions + executions))
    fi
done

# Count passed/failed from report file
if [ -f "${REPORT_FILE}" ]; then
    passed_tests=$(grep -c "✅" "${REPORT_FILE}" || echo "0")
    failed_tests=$(grep -c "❌" "${REPORT_FILE}" || echo "0")
fi

# Calculate estimated total duration
estimated_hours=$(echo "scale=1; (${FUZZTIME_LONG%h} * 2) + (${FUZZTIME_MEDIUM%h} * 7) + (${FUZZTIME_SHORT%m} * 15 / 60)" | bc -l)

# Add final summary to report
cat >> "${REPORT_FILE}" << EOF

## Final Summary

**Completion Time:** $(date)  
**Total Tests:** ${total_tests}  
**Passed:** ${passed_tests}  
**Failed:** ${failed_tests}  
**Success Rate:** $(echo "scale=1; ${passed_tests} * 100 / ${total_tests}" | bc -l)%  

**Performance Metrics:**
- Total Interesting Inputs: ${total_inputs}
- Total Test Executions: ${total_executions}  
- Estimated Duration: ${estimated_hours}h

**Files Generated:**
- Main Report: ${REPORT_FILE}
- Individual Logs: ${LOG_DIR}/*_${TIMESTAMP}.log
- Crash Log: ${LOG_DIR}/crashes_${TIMESTAMP}.log (if applicable)

EOF

# Check for crashes and generate alerts
if [ -f "${LOG_DIR}/crashes_${TIMESTAMP}.log" ]; then
    crash_count=$(wc -l < "${LOG_DIR}/crashes_${TIMESTAMP}.log")
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
    
    # Send alert if configured
    if [ "${EMAIL_REPORT}" = "true" ] && [ -n "${EMAIL_ADDRESS}" ]; then
        echo "📧 Sending crash alert email..."
        mail -s " Eos Fuzz Testing: ${crash_count} Crashes Detected" "${EMAIL_ADDRESS}" < "${REPORT_FILE}"
    fi
    
    if [ -n "${SLACK_WEBHOOK}" ]; then
        echo "📱 Sending Slack alert..."
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\" Eos Fuzz Testing Alert: ${crash_count} crashes detected in overnight testing session ${TIMESTAMP}\"}" \
            "${SLACK_WEBHOOK}"
    fi
    
    exit 1
else
    echo "SUCCESS: No crashes detected during overnight fuzzing"
    
    # Add success summary to report
    echo -e "\n## All Tests Passed Successfully\n" >> "${REPORT_FILE}"
    echo "No crashes or critical issues were detected during this fuzzing session." >> "${REPORT_FILE}"
fi

echo ""
echo "📊 COMPREHENSIVE SUMMARY:"
echo "========================="
echo " Log directory: ${LOG_DIR}"
echo "📄 Main report: ${REPORT_FILE}"
echo "📈 Tests executed: ${total_tests} (${passed_tests} passed, ${failed_tests} failed)"
echo "🔍 New inputs discovered: ${total_inputs}"
echo "⚡ Total executions: ${total_executions}"
echo "⏰ Estimated duration: ${estimated_hours}h"
echo ""

# Generate next steps
echo "🚀 NEXT STEPS:"
echo "=============="
echo "1. Review detailed report: cat '${REPORT_FILE}'"
echo "2. Examine individual logs: ls '${LOG_DIR}'/*_${TIMESTAMP}.log"
echo "3. Quick test run: ./assets/overnight-fuzz.sh (set FUZZTIME_LONG=1m for quick test)"
echo "4. Specific test: go test -run=^$ -fuzz=^FuzzAllEosCommands$ -fuzztime=1h ./test"
echo ""

if [ "${failed_tests}" -eq 0 ]; then
    echo "🎉 Eos framework is ready for extended production fuzzing!"
    
    # Send success notification if configured
    if [ "${EMAIL_REPORT}" = "true" ] && [ -n "${EMAIL_ADDRESS}" ]; then
        echo "📧 Sending success report email..."
        mail -s "Eos Fuzz Testing: All Tests Passed" "${EMAIL_ADDRESS}" < "${REPORT_FILE}"
    fi
else
    echo "Please address the ${failed_tests} failed tests before production deployment."
fi