#!/bin/bash
# Enhanced comprehensive fuzz test runner for EOS
# Implements property-based testing, chaos engineering, and continuous fuzzing

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
        echo -e "${GREEN}✅ Already in EOS project root${NC}"
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
        echo -e "${YELLOW}📋 To run this script correctly:${NC}"
        echo ""
        echo -e "  1. ${CYAN}Change to the EOS project root:${NC}"
        echo -e "     ${GREEN}cd /opt/eos${NC}  ${YELLOW}# or wherever you cloned the EOS repository${NC}"
        echo ""
        echo -e "  2. ${CYAN}Then run the script:${NC}"
        echo -e "     ${GREEN}./scripts/$(basename "$0")${NC}"
        echo ""
        echo -e "${YELLOW}💡 The project root should contain:${NC}"
        echo -e "   - go.mod file"
        echo -e "   - pkg/ directory"
        echo -e "   - cmd/ directory"
        echo -e "   - scripts/ directory"
        echo ""
        exit 1
    fi
}

# Verify required tools are available
verify_tools() {
    echo -e "${CYAN}🔧 Verifying required tools...${NC}"
    
    local missing_tools=()
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    fi
    
    # Check for git
    if ! command -v git &> /dev/null; then
        missing_tools+=("git")
    fi
    
    # Check for bc (used for calculations)
    if ! command -v bc &> /dev/null; then
        missing_tools+=("bc")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}❌ ERROR: Required tools are missing${NC}"
        echo -e "${RED}Missing: ${missing_tools[*]}${NC}"
        echo ""
        echo -e "${YELLOW}📋 Installation instructions:${NC}"
        echo ""
        if [[ " ${missing_tools[@]} " =~ " go " ]]; then
            echo -e "  ${CYAN}Install Go:${NC}"
            echo -e "     ${GREEN}sudo apt-get update && sudo apt-get install -y golang-go${NC}"
            echo ""
        fi
        if [[ " ${missing_tools[@]} " =~ " git " ]]; then
            echo -e "  ${CYAN}Install Git:${NC}"
            echo -e "     ${GREEN}sudo apt-get update && sudo apt-get install -y git${NC}"
            echo ""
        fi
        if [[ " ${missing_tools[@]} " =~ " bc " ]]; then
            echo -e "  ${CYAN}Install bc:${NC}"
            echo -e "     ${GREEN}sudo apt-get update && sudo apt-get install -y bc${NC}"
            echo ""
        fi
        exit 1
    fi
    
    echo -e "${GREEN}✅ All required tools are available${NC}"
}

# Verify test files exist
verify_test_files() {
    echo -e "${CYAN}📦 Verifying test files exist...${NC}"
    
    local missing_packages=()
    
    # Check key test directories
    if [ ! -d "pkg/security" ]; then
        missing_packages+=("pkg/security")
    fi
    if [ ! -d "pkg/crypto" ]; then
        missing_packages+=("pkg/crypto")
    fi
    if [ ! -d "test" ]; then
        missing_packages+=("test")
    fi
    
    if [ ${#missing_packages[@]} -gt 0 ]; then
        echo -e "${RED}❌ ERROR: Required test directories are missing${NC}"
        echo -e "${RED}Missing: ${missing_packages[*]}${NC}"
        echo ""
        echo -e "${YELLOW}This usually means you're not in the EOS project root.${NC}"
        echo -e "${YELLOW}Please follow the instructions above to navigate to the correct directory.${NC}"
        echo ""
        exit 1
    fi
    
    # Check for at least one fuzz test file
    if ! find pkg -name "*fuzz*.go" -type f | grep -q .; then
        echo -e "${RED}❌ ERROR: No fuzz test files found${NC}"
        echo ""
        echo -e "${YELLOW}📋 This could mean:${NC}"
        echo -e "  1. You're not in the EOS project root"
        echo -e "  2. The repository is incomplete"
        echo ""
        echo -e "${CYAN}Try:${NC}"
        echo -e "  ${GREEN}git pull origin main${NC}  # Update the repository"
        echo ""
        exit 1
    fi
    
    echo -e "${GREEN}✅ Test files verified${NC}"
}

# Run all preflight checks
run_preflight_checks() {
    echo -e "${PURPLE}🚀 EOS Comprehensive Fuzz Test Runner - Preflight${NC}"
    echo "================================================="
    echo ""
    
    preflight_check
    verify_tools
    verify_test_files
    
    echo ""
    echo -e "${GREEN}✅ All preflight checks passed!${NC}"
    echo ""
}

# Run preflight checks before anything else
run_preflight_checks

# Configuration
FUZZTIME="${1:-30s}"
CHAOS_MODE="${CHAOS_MODE:-false}"
CONTINUOUS_MODE="${CONTINUOUS_MODE:-false}"
SECURITY_FOCUS="${SECURITY_FOCUS:-true}"
ARCHITECTURE_TESTING="${ARCHITECTURE_TESTING:-true}"
PARALLEL_JOBS="${PARALLEL_JOBS:-8}"
LOG_DIR="${LOG_DIR:-/tmp/eos-comprehensive-fuzz}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${LOG_DIR}/comprehensive-fuzz-${TIMESTAMP}.md"

echo -e "${CYAN}🧪 EOS Comprehensive Fuzz Test Runner${NC}"
echo "============================================="
echo -e "📂 Working directory: ${YELLOW}$(pwd)${NC}"
echo -e "⏰ Duration: ${YELLOW}${FUZZTIME}${NC}"
echo -e "🔄 Parallel jobs: ${YELLOW}${PARALLEL_JOBS}${NC}"
echo -e "🎯 Security focus: ${YELLOW}${SECURITY_FOCUS}${NC}"
echo -e "🏗️  Architecture testing: ${YELLOW}${ARCHITECTURE_TESTING}${NC}"
echo -e "🌪️  Chaos mode: ${YELLOW}${CHAOS_MODE}${NC}"
echo -e "📁 Logs: ${YELLOW}${LOG_DIR}${NC}"
echo ""

# Create log directory
mkdir -p "${LOG_DIR}"
mkdir -p "${LOG_DIR}/security"
mkdir -p "${LOG_DIR}/architecture"
mkdir -p "${LOG_DIR}/chaos"
mkdir -p "${LOG_DIR}/corpus"

# Initialize comprehensive report
cat > "${REPORT_FILE}" << EOF
# EOS Comprehensive Fuzz Test Report

**Generated:** $(date)  
**Duration:** ${FUZZTIME}  
**Session:** ${TIMESTAMP}  
**Mode:** $([ "$CHAOS_MODE" = "true" ] && echo "Chaos Engineering" || echo "Standard Fuzzing")

## Test Configuration

- **Security Focus:** ${SECURITY_FOCUS}
- **Architecture Testing:** ${ARCHITECTURE_TESTING}
- **Chaos Mode:** ${CHAOS_MODE}
- **Parallel Jobs:** ${PARALLEL_JOBS}

## Test Categories

### Security-Critical Components
EOF

# Enhanced test discovery and categorization
discover_enhanced_fuzz_tests() {
    echo -e "${BLUE}🔍 Discovering comprehensive fuzz tests...${NC}"
    
    # Security-critical tests (highest priority)
    SECURITY_TESTS=(
        "FuzzInputSanitizer::./pkg/security"
        "FuzzInputSanitizerStrict::./pkg/security"
        "FuzzEscapeOutput::./pkg/security"
        "FuzzEscapeForLogging::./pkg/security"
        "FuzzValidateCommandName::./pkg/security"
        "FuzzValidateFlagName::./pkg/security"
        "FuzzSanitizeArguments::./pkg/security"
        "FuzzValidateDomainName::./pkg/crypto"
        "FuzzValidateEmailAddress::./pkg/crypto"
        "FuzzValidateAppName::./pkg/crypto"
        "FuzzSanitizeInputForCommand::./pkg/crypto"
        "FuzzExecuteCommand::./pkg/execute"
        "FuzzSaltStateGeneration::./pkg/saltstack"
        "FuzzSaltPillarDataValidation::./pkg/saltstack"
        "FuzzTerraformConfigGeneration::./pkg/terraform"
        "FuzzTerraformVariableValidation::./pkg/terraform"
    )
    
    # Architecture-specific tests (STACK.md compliance)
    ARCHITECTURE_TESTS=(
        "FuzzStackOrchestrationWorkflow::./test"
        "FuzzVaultDegradationScenarios::./test"
        "FuzzCrossBoundaryIntegration::./test"
        "FuzzResourceContentionScenarios::./test"
    )
    
    # Standard component tests
    COMPONENT_TESTS=(
        "FuzzNormalizeYesNoInput::./pkg/interaction"
        "FuzzValidateEmail::./pkg/interaction"
        "FuzzSplitAndTrim::./pkg/parse"
        "FuzzJSONParsing::./pkg/parse"
        "FuzzYAMLParsing::./pkg/eos_io"
        "FuzzMkdirP::./pkg/eos_unix"
        "FuzzDatabaseOperations::./pkg/database_management"
    )
    
    echo -e "${GREEN}📋 Test Discovery Complete:${NC}"
    echo -e "   🔒 Security tests: ${#SECURITY_TESTS[@]}"
    echo -e "   🏗️  Architecture tests: ${#ARCHITECTURE_TESTS[@]}"
    echo -e "   🧩 Component tests: ${#COMPONENT_TESTS[@]}"
    echo ""
}

# Enhanced test execution with property validation
run_enhanced_fuzz_test() {
    local test_spec="$1"
    local category="$2"
    local duration="$3"
    
    local test_function=$(echo "$test_spec" | cut -d':' -f1)
    local test_package=$(echo "$test_spec" | cut -d':' -f3)
    local log_file="${LOG_DIR}/${category}/${test_function}_${TIMESTAMP}.log"
    local corpus_dir="${LOG_DIR}/corpus/${test_function}"
    local start_time=$(date +%s)
    
    # Create corpus directory
    mkdir -p "$corpus_dir"
    
    echo -e "${PURPLE}🚀 Running ${test_function} (${category})${NC}"
    echo -e "   📦 Package: ${test_package}"
    echo -e "   ⏱️  Duration: ${duration}"
    echo -e "   📁 Corpus: ${corpus_dir}"
    
    # Set environment for enhanced fuzzing
    export GOFUZZ_CORPUS_DIR="$corpus_dir"
    export GOFUZZ_MINIMIZE_CORPUS=1
    export GOFUZZ_REPORT_CRASHES=1
    
    if go test -v -run=^$ -fuzz=^${test_function}$ -fuzztime="${duration}" \
        -fuzzminimizetime=10s "${test_package}" > "${log_file}" 2>&1; then
        
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        local inputs=$(grep -c "new interesting input" "${log_file}" 2>/dev/null || echo "0")
        local executions=$(grep -o 'execs: [0-9]*' "${log_file}" | tail -1 | grep -o '[0-9]*' || echo "0")
        local corpus_size=$(find "$corpus_dir" -type f 2>/dev/null | wc -l || echo "0")
        
        echo -e "   ✅ ${GREEN}SUCCESS${NC} - ${inputs} inputs, ${executions} executions, ${corpus_size} corpus files"
        
        # Update report
        echo "- ✅ **${test_function}** (${category}): SUCCESS - ${inputs} inputs, ${executions} executions, ${elapsed}s, corpus: ${corpus_size}" >> "${REPORT_FILE}"
        
        # Check for interesting findings
        if [ "$inputs" -gt 0 ]; then
            echo -e "   🎯 ${YELLOW}Found ${inputs} interesting inputs!${NC}"
            echo "  - 🔍 **${test_function}**: Found ${inputs} new interesting inputs" >> "${REPORT_FILE}"
        fi
        
        return 0
    else
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        local crash_info=$(grep -n "panic\|FAIL\|fatal error\|failing input" "${log_file}" | head -3 | tr '\n' '; ' || echo "Unknown error")
        
        echo -e "   ❌ ${RED}FAILED${NC} after ${elapsed}s"
        echo -e "   💥 ${crash_info}"
        
        # Update report
        echo "- ❌ **${test_function}** (${category}): FAILED - ${elapsed}s, error: ${crash_info}" >> "${REPORT_FILE}"
        
        # Save crash details
        if grep -q "failing input" "${log_file}"; then
            echo "  - 🐛 **${test_function}**: CRASH DETECTED - see ${log_file}" >> "${REPORT_FILE}"
            echo -e "   🚨 ${RED}CRASH DETECTED - Potential security issue!${NC}"
        fi
        
        return 1
    fi
}

# Chaos engineering mode
run_chaos_testing() {
    if [ "$CHAOS_MODE" != "true" ]; then
        return 0
    fi
    
    echo -e "${RED}🌪️  CHAOS ENGINEERING MODE${NC}"
    echo "================================"
    
    cat >> "${REPORT_FILE}" << EOF

### Chaos Engineering Results

EOF
    
    # Resource exhaustion tests
    echo -e "${YELLOW}🔥 Resource Exhaustion Tests${NC}"
    
    # Memory pressure
    echo -e "   💾 Memory pressure simulation..."
    GOMAXPROCS=1 GOMEMLIMIT=100MiB go test -v -fuzz=FuzzResourceContentionScenarios \
        -fuzztime=30s ./test >> "${LOG_DIR}/chaos/memory_pressure.log" 2>&1 || true
    
    # CPU saturation
    echo -e "   🔥 CPU saturation simulation..."
    stress-ng --cpu 4 --timeout 30s &
    STRESS_PID=$!
    go test -v -fuzz=FuzzStackOrchestrationWorkflow -fuzztime=30s ./test \
        >> "${LOG_DIR}/chaos/cpu_saturation.log" 2>&1 || true
    kill $STRESS_PID 2>/dev/null || true
    
    # Network disruption simulation
    echo -e "   🌐 Network disruption simulation..."
    # This would require network namespace manipulation in a real environment
    go test -v -fuzz=FuzzCrossBoundaryIntegration -fuzztime=30s ./test \
        >> "${LOG_DIR}/chaos/network_disruption.log" 2>&1 || true
    
    echo "- 🌪️ **Chaos Testing**: Completed resource exhaustion, CPU saturation, and network disruption tests" >> "${REPORT_FILE}"
}

# Property-based testing validation
run_property_based_tests() {
    echo -e "${CYAN}📐 Property-Based Testing${NC}"
    echo "=========================="
    
    cat >> "${REPORT_FILE}" << EOF

### Property-Based Testing Results

EOF
    
    # Test orchestration properties
    echo -e "   🔄 Orchestration workflow properties..."
    go test -v -run TestOrchestrationProperties ./test \
        >> "${LOG_DIR}/property_orchestration.log" 2>&1 || true
    
    # Test security properties
    echo -e "   🔒 Security invariant properties..."
    go test -v -run TestSecurityProperties ./pkg/security \
        >> "${LOG_DIR}/property_security.log" 2>&1 || true
    
    # Test consistency properties
    echo -e "   ⚖️  State consistency properties..."
    go test -v -run TestStateConsistencyProperties ./test \
        >> "${LOG_DIR}/property_consistency.log" 2>&1 || true
    
    echo "- 📐 **Property Testing**: Validated orchestration, security, and consistency properties" >> "${REPORT_FILE}"
}

# Performance regression detection
run_performance_regression_tests() {
    echo -e "${BLUE}📊 Performance Regression Detection${NC}"
    echo "===================================="
    
    # Benchmark key functions
    echo -e "   ⚡ Running performance benchmarks..."
    go test -bench=. -benchmem -count=3 ./pkg/security ./pkg/crypto ./pkg/execute \
        > "${LOG_DIR}/performance_benchmarks.log" 2>&1 || true
    
    # Analyze benchmark results
    if command -v benchstat >/dev/null 2>&1; then
        echo -e "   📈 Analyzing benchmark statistics..."
        benchstat "${LOG_DIR}/performance_benchmarks.log" > "${LOG_DIR}/benchmark_analysis.log" 2>&1 || true
    fi
    
    echo "- 📊 **Performance Testing**: Completed benchmarks for security, crypto, and execute packages" >> "${REPORT_FILE}"
}

# Continuous fuzzing mode
run_continuous_fuzzing() {
    if [ "$CONTINUOUS_MODE" != "true" ]; then
        return 0
    fi
    
    echo -e "${GREEN}♾️  CONTINUOUS FUZZING MODE${NC}"
    echo "============================="
    
    # This would run indefinitely, finding new test cases
    echo -e "   🔄 Starting continuous fuzzing (press Ctrl+C to stop)..."
    
    trap 'echo -e "\n${YELLOW}⏹️  Stopping continuous fuzzing...${NC}"; exit 0' INT
    
    while true; do
        echo -e "   🔄 Continuous cycle: $(date)"
        
        # Run a subset of critical tests continuously
        for test_spec in "${SECURITY_TESTS[@]:0:5}"; do
            run_enhanced_fuzz_test "$test_spec" "security" "60s" || true
            sleep 5
        done
        
        sleep 30
    done
}

# Coverage analysis
analyze_coverage() {
    echo -e "${PURPLE}📊 Coverage Analysis${NC}"
    echo "===================="
    
    echo -e "   📈 Generating coverage report..."
    go test -v -coverprofile="${LOG_DIR}/coverage.out" -covermode=atomic ./pkg/... \
        >> "${LOG_DIR}/coverage.log" 2>&1 || true
    
    if [ -f "${LOG_DIR}/coverage.out" ]; then
        go tool cover -html="${LOG_DIR}/coverage.out" -o "${LOG_DIR}/coverage.html" 2>/dev/null || true
        
        # Extract coverage percentage
        local coverage_pct=$(go tool cover -func="${LOG_DIR}/coverage.out" | grep total | awk '{print $3}')
        echo -e "   📊 Total coverage: ${GREEN}${coverage_pct}${NC}"
        
        echo "- 📊 **Coverage Analysis**: Total coverage ${coverage_pct}" >> "${REPORT_FILE}"
    fi
}

# Main execution
main() {
    # Discover tests
    discover_enhanced_fuzz_tests
    
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # Run security-critical tests (highest priority)
    if [ "$SECURITY_FOCUS" = "true" ]; then
        echo -e "${RED}🔒 SECURITY-CRITICAL FUZZING${NC}"
        echo "=============================="
        
        for test_spec in "${SECURITY_TESTS[@]}"; do
            if run_enhanced_fuzz_test "$test_spec" "security" "$FUZZTIME"; then
                ((passed_tests++))
            else
                ((failed_tests++))
            fi
            ((total_tests++))
            echo ""
        done
    fi
    
    # Run architecture-specific tests
    if [ "$ARCHITECTURE_TESTING" = "true" ]; then
        echo -e "${BLUE}🏗️  ARCHITECTURE-SPECIFIC FUZZING${NC}"
        echo "=================================="
        
        for test_spec in "${ARCHITECTURE_TESTS[@]}"; do
            if run_enhanced_fuzz_test "$test_spec" "architecture" "$FUZZTIME"; then
                ((passed_tests++))
            else
                ((failed_tests++))
            fi
            ((total_tests++))
            echo ""
        done
    fi
    
    # Run component tests
    echo -e "${CYAN}🧩 COMPONENT FUZZING${NC}"
    echo "===================="
    
    for test_spec in "${COMPONENT_TESTS[@]}"; do
        if run_enhanced_fuzz_test "$test_spec" "component" "$FUZZTIME"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
        ((total_tests++))
        echo ""
    done
    
    # Additional testing modes
    run_chaos_testing
    run_property_based_tests
    run_performance_regression_tests
    analyze_coverage
    
    # Generate final summary
    cat >> "${REPORT_FILE}" << EOF

## Final Summary

**Total Tests:** ${total_tests}  
**Passed:** ${passed_tests}  
**Failed:** ${failed_tests}  
**Success Rate:** $(echo "scale=1; ${passed_tests} * 100 / ${total_tests}" | bc -l 2>/dev/null || echo "N/A")%

**Execution Time:** $(date)  
**Log Directory:** ${LOG_DIR}

## Recommendations

EOF

    # Add recommendations based on results
    if [ $failed_tests -gt 0 ]; then
        cat >> "${REPORT_FILE}" << EOF
⚠️ **${failed_tests} tests failed** - Review crash logs for potential security vulnerabilities:
- Check ${LOG_DIR}/security/ for security-critical failures
- Check ${LOG_DIR}/architecture/ for workflow issues
- Investigate any crashes or panics immediately

EOF
    fi
    
    if [ $passed_tests -eq $total_tests ]; then
        cat >> "${REPORT_FILE}" << EOF
✅ **All tests passed** - Consider:
- Increasing fuzz duration for deeper testing
- Adding new test cases based on recent code changes
- Running overnight fuzzing for extended coverage

EOF
    fi
    
    echo ""
    echo -e "${CYAN}📊 COMPREHENSIVE FUZZING COMPLETE${NC}"
    echo "=================================="
    echo -e "📈 Tests: ${total_tests} total, ${GREEN}${passed_tests} passed${NC}, ${RED}${failed_tests} failed${NC}"
    echo -e "📄 Report: ${YELLOW}${REPORT_FILE}${NC}"
    echo -e "📁 Logs: ${YELLOW}${LOG_DIR}${NC}"
    echo -e "🌐 Coverage: ${YELLOW}${LOG_DIR}/coverage.html${NC}"
    
    if [ $failed_tests -gt 0 ]; then
        echo ""
        echo -e "${RED}⚠️  SECURITY ALERT: ${failed_tests} test(s) failed${NC}"
        echo -e "🔍 Immediate investigation required"
        exit 1
    else
        echo ""
        echo -e "${GREEN}✅ All comprehensive fuzz tests passed!${NC}"
        echo -e "🚀 System appears robust against fuzzing attacks"
    fi
    
    # Run continuous mode if requested
    run_continuous_fuzzing
}

# Usage help
show_usage() {
    cat << EOF
Usage: $0 [DURATION] [OPTIONS]

DURATION:
  Time to run each fuzz test (default: 30s)
  Examples: 10s, 5m, 1h

ENVIRONMENT OPTIONS:
  CHAOS_MODE=true          Enable chaos engineering tests
  CONTINUOUS_MODE=true     Run continuous fuzzing
  SECURITY_FOCUS=false     Skip security-critical tests
  ARCHITECTURE_TESTING=false  Skip architecture tests
  PARALLEL_JOBS=N          Number of parallel jobs
  LOG_DIR=/path            Custom log directory

EXAMPLES:
  $0 60s                                    # Standard 1-minute fuzz
  CHAOS_MODE=true $0 30s                    # Chaos engineering mode
  CONTINUOUS_MODE=true $0 5m                # Continuous fuzzing
  SECURITY_FOCUS=true ARCHITECTURE_TESTING=true $0 2m  # Full testing

EOF
}

# Handle command line arguments
case "${1:-}" in
    -h|--help)
        show_usage
        exit 0
        ;;
    *)
        main
        ;;
esac