#!/bin/bash
# Quick fuzzing validation script for Eos framework
# Runs essential fuzz tests with short durations to validate setup

set -e

DURATION="${1:-5s}"
LOG_DIR="${LOG_DIR:-/tmp/eos-fuzz-logs}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

mkdir -p "${LOG_DIR}"

echo "🧪 Quick Eos Fuzz Validation (${DURATION} per test)"
echo "================================================="

# Essential tests for validation
tests=(
    "FuzzAllEosCommands ./test"
    "FuzzValidateStrongPassword ./pkg/crypto"
    "FuzzHashString ./pkg/crypto"
    "FuzzNormalizeYesNoInput ./pkg/interaction"
    "FuzzSplitAndTrim ./pkg/parse"
    "FuzzCommandParsing ./pkg/eos_cli"
)

passed=0
failed=0
total=${#tests[@]}

for test_spec in "${tests[@]}"; do
    test_name=$(echo ${test_spec} | cut -d' ' -f1)
    package=$(echo ${test_spec} | cut -d' ' -f2)
    
    echo "🚀 Testing ${test_name} (${package}) for ${DURATION}..."
    
    # Check if test exists
    if ! go test -list=Fuzz "${package}" 2>/dev/null | grep -q "^${test_name}$"; then
        echo "⚠️  Test ${test_name} not found in ${package}, skipping..."
        ((total--))
        continue
    fi
    
    # Run test
    log_file="${LOG_DIR}/${test_name}_quick_${TIMESTAMP}.log"
    if go test -run=^$ -fuzz=^${test_name}$ -fuzztime="${DURATION}" "${package}" > "${log_file}" 2>&1; then
        executions=$(grep -o 'execs: [0-9]*' "${log_file}" | tail -1 | sed 's/execs: //' || echo "0")
        echo "✅ ${test_name}: PASSED (${executions} executions)"
        ((passed++))
    else
        echo "❌ ${test_name}: FAILED (check ${log_file})"
        ((failed++))
    fi
done

echo ""
echo "📊 Quick Validation Results:"
echo "=========================="
echo "✅ Passed: ${passed}/${total}"
echo "❌ Failed: ${failed}/${total}"

if [ ${failed} -eq 0 ]; then
    echo ""
    echo "🎉 SUCCESS: All essential fuzz tests are working!"
    echo "🚀 Ready for overnight fuzzing:"
    echo "   ./assets/overnight-fuzz-simple.sh"
    echo "   # or with custom durations:"
    echo "   FUZZTIME_LONG=1h FUZZTIME_MEDIUM=30m FUZZTIME_SHORT=10m ./assets/overnight-fuzz-simple.sh"
    exit 0
else
    echo ""
    echo "⚠️  ${failed} test(s) failed. Check logs in ${LOG_DIR}"
    echo "🔍 Debug with: go test -v -run=^$ -fuzz=^TestName$ -fuzztime=10s ./package"
    exit 1
fi