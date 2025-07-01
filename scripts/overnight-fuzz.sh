#!/bin/bash
# Overnight fuzzing script for Ubuntu deployment
# This script runs comprehensive fuzz tests for extended periods to catch edge cases

set -e

# Configuration
FUZZTIME_LONG="8h"  # 8 hours per test
FUZZTIME_SHORT="30m" # 30 minutes for quick tests
LOG_DIR="/tmp/eos-fuzz-logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create log directory
mkdir -p "${LOG_DIR}"

echo " Starting overnight EOS fuzzing at $(date)"
echo "📁 Logs will be saved to: ${LOG_DIR}"
echo "⏰ Long fuzz duration: ${FUZZTIME_LONG}"
echo "⏰ Short fuzz duration: ${FUZZTIME_SHORT}"
echo ""

# Function to run a fuzz test with logging
run_fuzz_test() {
    local test_name="$1"
    local package="$2"
    local duration="$3"
    local log_file="${LOG_DIR}/${test_name}_${TIMESTAMP}.log"
    
    echo " Starting ${test_name} (${duration})..."
    echo " Command: go test -run=^$ -fuzz=^${test_name}$ -fuzztime=${duration} ${package}"
    echo "📄 Log: ${log_file}"
    
    if go test -run=^$ -fuzz=^${test_name}$ -fuzztime="${duration}" "${package}" > "${log_file}" 2>&1; then
        echo " ${test_name} completed successfully"
        # Count interesting inputs found
        local inputs=$(grep -c "new interesting input" "${log_file}" 2>/dev/null || echo "0")
        echo " Found ${inputs} new interesting inputs"
    else
        echo " ${test_name} failed - check ${log_file}"
        echo "🚨 CRASH DETECTED in ${test_name}!" | tee -a "${LOG_DIR}/crashes_${TIMESTAMP}.log"
    fi
    echo ""
}

# High-priority comprehensive tests (long duration)
echo " Running comprehensive tests with long duration..."
run_fuzz_test "FuzzAllEOSCommands" "./test" "${FUZZTIME_LONG}"
run_fuzz_test "FuzzDelphiServicesCommands" "./test" "${FUZZTIME_LONG}"

# Medium-priority specific tests (medium duration)
echo "🔧 Running specific component tests..."
run_fuzz_test "FuzzUpdateCommand" "./cmd/delphi/services" "${FUZZTIME_SHORT}"
run_fuzz_test "FuzzServiceWorkerPaths" "./cmd/delphi/services" "${FUZZTIME_SHORT}"
run_fuzz_test "FuzzCommandParsing" "./pkg/eos_cli" "${FUZZTIME_SHORT}"
run_fuzz_test "FuzzEOSCommandFlags" "./test" "${FUZZTIME_SHORT}"

# Security-focused crypto tests (medium duration)
echo "🔐 Running security-focused crypto tests..."
run_fuzz_test "FuzzValidateStrongPassword" "./pkg/crypto" "${FUZZTIME_SHORT}"
run_fuzz_test "FuzzHashString" "./pkg/crypto" "${FUZZTIME_SHORT}"
run_fuzz_test "FuzzRedact" "./pkg/crypto" "${FUZZTIME_SHORT}"
run_fuzz_test "FuzzInjectSecretsFromPlaceholders" "./pkg/crypto" "${FUZZTIME_SHORT}"

# Input validation tests (short duration)
echo "📝 Running input validation tests..."
run_fuzz_test "FuzzNormalizeYesNoInput" "./pkg/interaction" "15m"
run_fuzz_test "FuzzValidateUsername" "./pkg/interaction" "15m"
run_fuzz_test "FuzzValidateEmail" "./pkg/interaction" "15m"
run_fuzz_test "FuzzValidateNoShellMeta" "./pkg/interaction" "15m"
run_fuzz_test "FuzzSplitAndTrim" "./pkg/parse" "15m"

# Final summary
echo "🏁 Overnight fuzzing completed at $(date)"
echo ""
echo " SUMMARY:"
echo "==========="
echo "📁 Log directory: ${LOG_DIR}"
echo "🕐 Total duration: ~$(echo "8*2 + 0.5*4 + 0.25*5" | bc)h estimated"

# Check for crashes
if [ -f "${LOG_DIR}/crashes_${TIMESTAMP}.log" ]; then
    echo "🚨 CRASHES DETECTED! Check:"
    cat "${LOG_DIR}/crashes_${TIMESTAMP}.log"
    exit 1
else
    echo " No crashes detected during overnight fuzzing"
fi

# Count total interesting inputs
total_inputs=0
for log_file in "${LOG_DIR}"/*_"${TIMESTAMP}".log; do
    if [ -f "$log_file" ]; then
        inputs=$(grep -c "new interesting input" "$log_file" 2>/dev/null || echo "0")
        total_inputs=$((total_inputs + inputs))
    fi
done

echo " Total interesting inputs found: ${total_inputs}"
echo ""
echo "💡 To run a quick test: ./scripts/run-fuzz-tests.sh 30s"
echo "💡 To run specific test: go test -run=^$ -fuzz=^FuzzAllEOSCommands$ -fuzztime=1h ./test"
echo ""
echo " Ready for production deployment!"