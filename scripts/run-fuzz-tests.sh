#!/bin/bash
# Enhanced fuzz test runner for Eos CLI
# Supports individual test execution, reporting, and integration with overnight fuzzing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Preflight check function
preflight_check() {
    echo -e "${CYAN}🔍 Running preflight checks...${NC}"
    
    # Check if we're in the project root or can find it
    local current_dir="$(pwd)"
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local expected_root="$(cd "$script_dir/.." && pwd)"
    
    # Check for go.mod file as indicator of project root
    if [ -f "go.mod" ] && grep -q "module github.com/CodeMonkeyCybersecurity/eos" "go.mod" 2>/dev/null; then
        echo -e "${GREEN}Already in EOS project root${NC}"
        return 0
    elif [ -f "$expected_root/go.mod" ] && grep -q "module github.com/CodeMonkeyCybersecurity/eos" "$expected_root/go.mod" 2>/dev/null; then
        echo -e "${YELLOW}📂 Changing to project root: $expected_root${NC}"
        cd "$expected_root" || { 
            echo -e "${RED}❌ Failed to change to project root${NC}"
            exit 1
        }
        return 0
    else
        echo -e "${RED}❌ ERROR: Not in EOS project directory${NC}"
        echo -e "${RED}Current directory: $current_dir${NC}"
        echo ""
        echo -e "${YELLOW}To run this script correctly:${NC}"
        echo ""
        echo -e "  1. ${CYAN}Change to the EOS project root:${NC}"
        echo -e "     ${GREEN}cd /opt/eos${NC}  ${YELLOW}# or wherever you cloned the EOS repository${NC}"
        echo ""
        echo -e "  2. ${CYAN}Then run the script:${NC}"
        echo -e "     ${GREEN}./scripts/$(basename "$0")${NC} [duration] [package] [function]"
        echo ""
        echo -e "${YELLOW}💡 Examples:${NC}"
        echo -e "   ${GREEN}./scripts/$(basename "$0")${NC}              # Run all tests for 10s"
        echo -e "   ${GREEN}./scripts/$(basename "$0") 30s${NC}          # Run all tests for 30s"
        echo -e "   ${GREEN}./scripts/$(basename "$0") 1m ./pkg/security${NC}  # Run security tests for 1m"
        echo ""
        exit 1
    fi
}

# Verify required tools
verify_tools() {
    echo -e "${CYAN}Verifying required tools...${NC}"
    
    if ! command -v go &> /dev/null; then
        echo -e "${RED}❌ ERROR: Go is not installed${NC}"
        echo ""
        echo -e "${YELLOW}To install Go:${NC}"
        echo -e "   ${GREEN}sudo apt-get update && sudo apt-get install -y golang-go${NC}"
        echo ""
        exit 1
    fi
    
    echo -e "${GREEN}Required tools verified${NC}"
}

# Run preflight checks
echo -e "${PURPLE}🚀 EOS Fuzz Test Runner - Preflight${NC}"
echo "===================================="
echo ""

preflight_check
verify_tools

echo ""
echo -e "${GREEN}Preflight checks passed!${NC}"
echo ""

# Configuration with environment variable overrides
FUZZTIME="${1:-10s}"
PACKAGE="${2:-}"
FUNCTION="${3:-}"
LOG_DIR="${LOG_DIR:-/tmp/eos-fuzz-logs}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${LOG_DIR}/quick-fuzz-${TIMESTAMP}.md"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"

# Create log directory
mkdir -p "${LOG_DIR}"

echo -e "${CYAN}🧪 Eos Fuzz Test Runner${NC}"
echo "======================="
echo -e "📂 Working directory: ${YELLOW}$(pwd)${NC}"
echo -e "⏰ Duration: ${YELLOW}${FUZZTIME}${NC}"
echo -e "🔄 Parallel jobs: ${YELLOW}${PARALLEL_JOBS}${NC}"
echo -e " Logs: ${YELLOW}${LOG_DIR}${NC}"
echo ""

# Initialize report
cat > "${REPORT_FILE}" << EOF
# Eos Quick Fuzz Test Report

**Generated:** $(date)  
**Duration:** ${FUZZTIME}  
**Session:** ${TIMESTAMP}

## Test Results

EOF

# Enhanced test runner function
run_single_fuzz_test() {
    local test_function="$1"
    local test_package="$2"
    local duration="$3"
    local log_file="${LOG_DIR}/${test_function}_${TIMESTAMP}.log"
    local start_time=$(date +%s)
    
    echo "🚀 Running ${test_function} in ${test_package} for ${duration}..."
    
    if go test -v -run=^$ -fuzz=^${test_function}$ -fuzztime="${duration}" "${test_package}" > "${log_file}" 2>&1; then
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        local inputs=$(grep -c "new interesting input" "${log_file}" 2>/dev/null || echo "0")
        local executions=$(grep -o 'execs: [0-9]*' "${log_file}" | tail -1 | grep -o '[0-9]*' || echo "0")
        
        echo "${test_function} completed successfully"
        echo "📊 Found ${inputs} new inputs, executed ${executions} cases in ${elapsed}s"
        
        # Update report
        echo "- **${test_function}** (${test_package}): SUCCESS - ${inputs} inputs, ${executions} executions, ${elapsed}s" >> "${REPORT_FILE}"
        return 0
    else
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        local crash_info=$(grep -n "panic\|FAIL\|fatal error" "${log_file}" | head -1 || echo "Unknown error")
        
        echo "❌ ${test_function} failed after ${elapsed}s"
        echo "💥 Error: ${crash_info}"
        
        # Update report
        echo "- ❌ **${test_function}** (${test_package}): FAILED - ${elapsed}s, error: ${crash_info}" >> "${REPORT_FILE}"
        return 1
    fi
}

# Function to discover all available fuzz tests
discover_fuzz_tests() {
    echo "🔍 Discovering available fuzz tests..."
    
    # Create temporary file for test mappings (bash 3.x compatible)
    local test_list="/tmp/eos_fuzz_tests_$$.txt"
    cat > "${test_list}" << 'EOF'
FuzzValidateStrongPassword ./pkg/crypto
FuzzHashString ./pkg/crypto
FuzzHashStrings ./pkg/crypto
FuzzAllUnique ./pkg/crypto
FuzzAllHashesPresent ./pkg/crypto
FuzzRedact ./pkg/crypto
FuzzInjectSecretsFromPlaceholders ./pkg/crypto
FuzzSecureZero ./pkg/crypto
FuzzNormalizeYesNoInput ./pkg/interaction
FuzzValidateNonEmpty ./pkg/interaction
FuzzValidateUsername ./pkg/interaction
FuzzValidateEmail ./pkg/interaction
FuzzValidateURL ./pkg/interaction
FuzzValidateIP ./pkg/interaction
FuzzValidateNoShellMeta ./pkg/interaction
FuzzSplitAndTrim ./pkg/parse
FuzzJSONParsing ./pkg/parse
FuzzCommandParsing ./pkg/eos_cli
FuzzUpdateCommand ./cmd/delphi/services
FuzzServiceWorkerPaths ./cmd/delphi/services
FuzzFileOperations ./cmd/delphi/services
FuzzAllEosCommands ./test
FuzzEosCommandFlags ./test
FuzzDelphiServicesCommands ./test
FuzzYAMLParsing ./pkg/eos_io
FuzzMkdirP ./pkg/eos_unix
FuzzExecuteCommand ./pkg/execute
FuzzDatabaseOperations ./pkg/database_management
EOF
    
    echo "Available fuzz tests:"
    while read -r test_func package; do
        echo "   ${test_func} (${package})"
    done < "${test_list}" | sort
    echo ""
    
    # Return just the test function names
    awk '{print $1}' "${test_list}"
    rm -f "${test_list}"
}

# Helper function to get package for test function
get_test_package() {
    local test_func="$1"
    case "${test_func}" in
        FuzzValidateStrongPassword|FuzzHashString|FuzzHashStrings|FuzzAllUnique|FuzzAllHashesPresent|FuzzRedact|FuzzInjectSecretsFromPlaceholders|FuzzSecureZero)
            echo "./pkg/crypto" ;;
        FuzzNormalizeYesNoInput|FuzzValidateNonEmpty|FuzzValidateUsername|FuzzValidateEmail|FuzzValidateURL|FuzzValidateIP|FuzzValidateNoShellMeta)
            echo "./pkg/interaction" ;;
        FuzzSplitAndTrim|FuzzJSONParsing)
            echo "./pkg/parse" ;;
        FuzzCommandParsing)
            echo "./pkg/eos_cli" ;;
        FuzzUpdateCommand|FuzzServiceWorkerPaths|FuzzFileOperations)
            echo "./cmd/delphi/services" ;;
        FuzzAllEosCommands|FuzzEosCommandFlags|FuzzDelphiServicesCommands)
            echo "./test" ;;
        FuzzYAMLParsing)
            echo "./pkg/eos_io" ;;
        FuzzMkdirP)
            echo "./pkg/eos_unix" ;;
        FuzzExecuteCommand)
            echo "./pkg/execute" ;;
        FuzzDatabaseOperations)
            echo "./pkg/database_management" ;;
        *)
            echo "unknown" ;;
    esac
}

# Main execution logic
if [ -n "${FUNCTION}" ] && [ -n "${PACKAGE}" ]; then
    echo "🎯 Running specific test: ${FUNCTION} in ${PACKAGE}"
    run_single_fuzz_test "${FUNCTION}" "${PACKAGE}" "${FUZZTIME}"
    exit_code=$?
elif [ -n "${PACKAGE}" ]; then
    echo "Running all fuzz tests in package: ${PACKAGE}"
    
    # Discover tests in the specific package
    available_tests=($(discover_fuzz_tests))
    package_tests=()
    
    for test_func in "${available_tests[@]}"; do
        if [[ "$(get_test_package "${test_func}")" == "${PACKAGE}" ]]; then
            package_tests+=("${test_func}")
        fi
    done
    
    if [ ${#package_tests[@]} -eq 0 ]; then
        echo "❌ No fuzz tests found in package ${PACKAGE}"
        exit 1
    fi
    
    echo "Found ${#package_tests[@]} tests in ${PACKAGE}"
    failed_tests=0
    
    for test_func in "${package_tests[@]}"; do
        if ! run_single_fuzz_test "${test_func}" "${PACKAGE}" "${FUZZTIME}"; then
            ((failed_tests++))
        fi
        echo ""
    done
    
    exit_code=$failed_tests
else
    echo "🌐 Running ALL available fuzz tests (quick mode)"
    echo "💡 Use specific package/function for targeted testing"
    echo ""
    
    # Use representative test set for quick execution
    representative_tests=(
        "FuzzValidateStrongPassword"
        "FuzzHashString" 
        "FuzzRedact"
        "FuzzNormalizeYesNoInput"
        "FuzzValidateEmail"
        "FuzzSplitAndTrim"
        "FuzzCommandParsing"
        "FuzzUpdateCommand"
        "FuzzAllEosCommands"
        "FuzzYAMLParsing"
        "FuzzMkdirP"
        "FuzzExecuteCommand"
    )
    
    echo "Running ${#representative_tests[@]} representative tests with ${FUZZTIME} duration each..."
    failed_tests=0
    
    # Run tests with some parallelism for speed
    pids=()
    active_jobs=0
    max_parallel=3
    
    for test_func in "${representative_tests[@]}"; do
        # Wait if we've reached max parallel jobs
        while [[ ${active_jobs} -ge ${max_parallel} ]]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[i]}" 2>/dev/null; then
                    wait "${pids[i]}"
                    exit_status=$?
                    if [ ${exit_status} -ne 0 ]; then
                        ((failed_tests++))
                    fi
                    unset "pids[i]"
                    ((active_jobs--))
                fi
            done
            sleep 1
        done
        
        # Start test in background
        test_package=$(get_test_package "${test_func}")
        (run_single_fuzz_test "${test_func}" "${test_package}" "${FUZZTIME}") &
        pid=$!
        pids+=("${pid}")
        ((active_jobs++))
        
        sleep 1  # Brief delay between starts
    done
    
    # Wait for all remaining jobs
    for pid in "${pids[@]}"; do
        wait "${pid}"
        exit_status=$?
        if [ ${exit_status} -ne 0 ]; then
            ((failed_tests++))
        fi
    done
    
    exit_code=$failed_tests
fi

# Generate final summary
total_tests=$(grep -c "^- " "${REPORT_FILE}" || echo "0")
passed_tests=$(grep -c "" "${REPORT_FILE}" || echo "0")
failed_tests=$(grep -c "❌" "${REPORT_FILE}" || echo "0")

# Add summary to report
cat >> "${REPORT_FILE}" << EOF

## Summary

**Total Tests:** ${total_tests}  
**Passed:** ${passed_tests}  
**Failed:** ${failed_tests}  
**Success Rate:** $(echo "scale=1; ${passed_tests} * 100 / ${total_tests}" | bc -l 2>/dev/null || echo "N/A")%

**Generated:** $(date)  
**Logs Location:** ${LOG_DIR}/*_${TIMESTAMP}.log

EOF

echo ""
echo "📊 SUMMARY:"
echo "==========="
echo "📈 Tests: ${total_tests} total, ${passed_tests} passed, ${failed_tests} failed"
echo "📄 Report: ${REPORT_FILE}"
echo " Logs: ${LOG_DIR}/*_${TIMESTAMP}.log"
echo ""

if [ ${exit_code} -eq 0 ]; then
    echo "All fuzz tests completed successfully!"
    echo "🚀 Ready for overnight fuzzing: ./assets/overnight-fuzz.sh"
else
    echo "${exit_code} test(s) failed. Review logs for details."
    echo "🔍 Check specific logs: ls ${LOG_DIR}/*_${TIMESTAMP}.log"
fi

echo ""
echo "Usage examples:"
echo "  $0 30s                              # Run all tests for 30 seconds each"
echo "  $0 1m ./pkg/crypto                  # Run crypto tests for 1 minute each"
echo "  $0 5m ./pkg/crypto FuzzHashString   # Run specific test for 5 minutes"
echo "  $0 10s ./test FuzzAllEosCommands    # Run comprehensive test for 10 seconds"

exit ${exit_code}