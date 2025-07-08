#!/bin/bash
# Quick fuzzing validation script for Eos framework
# Runs essential fuzz tests with short durations to validate setup

set -e

# Source the common preflight checks
source "$(dirname "${BASH_SOURCE[0]}")/fuzz-preflight-common.sh"

# Run preflight checks
eos_run_preflight_checks

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
        echo "Test ${test_name} not found in ${package}, skipping..."
        ((total--))
        continue
    fi
    
    # Run test
    log_file="${LOG_DIR}/${test_name}_quick_${TIMESTAMP}.log"
    if go test -run=^$ -fuzz=^${test_name}$ -fuzztime="${DURATION}" "${package}" > "${log_file}" 2>&1; then
        executions=$(grep -o 'execs: [0-9]*' "${log_file}" | tail -1 | sed 's/execs: //' || echo "0")
        echo "${test_name}: PASSED (${executions} executions)"
        ((passed++))
    else
        echo "❌ ${test_name}: FAILED (check ${log_file})"
        ((failed++))
    fi
done

echo ""
echo -e "${PURPLE}📊 Quick Validation Results:${NC}"
echo -e "${PURPLE}==========================${NC}"
echo -e "${GREEN}Passed: ${passed}/${total}${NC}"
echo -e "${RED}❌ Failed: ${failed}/${total}${NC}"

if [ ${failed} -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 SUCCESS: All essential fuzz tests are working!${NC}"
    echo -e "${CYAN}🚀 Ready for overnight fuzzing:${NC}"
    echo -e "   ${GREEN}./assets/overnight-fuzz-simple.sh${NC}"
    echo -e "   ${YELLOW}# or with custom durations:${NC}"
    echo -e "   ${GREEN}FUZZTIME_LONG=1h FUZZTIME_MEDIUM=30m FUZZTIME_SHORT=10m ./assets/overnight-fuzz-simple.sh${NC}"
    exit 0
else
    echo ""
    echo -e "${YELLOW}${failed} test(s) failed. Check logs in ${LOG_DIR}${NC}"
    echo -e "${CYAN}🔍 Debug with: ${GREEN}go test -v -run=^$ -fuzz=^TestName$ -fuzztime=10s ./package${NC}"
    exit 1
fi