#!/bin/bash
# EOS CI/CD Fuzzing Integration - Optimized for Automated Environments
# Implements STACK.md Section 4.1 compliance for continuous integration
# Version: 2.0.0

set -euo pipefail
IFS=$'\n\t'

# Source the common preflight checks
source "$(dirname "${BASH_SOURCE[0]}")/fuzz-preflight-common.sh"

# Run preflight checks
eos_run_preflight_checks

# ============================================================================
# CI/CD SPECIFIC CONFIGURATION
# ============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# CI-optimized defaults
readonly CI_FUZZTIME="${CI_FUZZTIME:-60s}"
readonly CI_PARALLEL_JOBS="${CI_PARALLEL_JOBS:-4}"
readonly CI_LOG_DIR="${CI_LOG_DIR:-${GITHUB_WORKSPACE:-${PWD}}/fuzz-results}"
readonly CI_TIMEOUT_MULTIPLIER=2

# CI environment detection
readonly IS_CI="${CI:-false}"
readonly IS_GITHUB_ACTIONS="${GITHUB_ACTIONS:-false}"
readonly IS_PULL_REQUEST="${GITHUB_EVENT_NAME:-}" 

# Security settings for CI
readonly MAX_CI_DURATION="10m"
readonly MAX_CI_PARALLEL=8
readonly CI_MEMORY_LIMIT_MB=2048

# ============================================================================
# CI-SPECIFIC LOGGING AND OUTPUT
# ============================================================================

# Structured logging for CI environments
ci_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    case "$level" in
        "ERROR")
            echo "::error::$message" >&2
            ;;
        "WARNING")
            echo "::warning::$message" >&2
            ;;
        "INFO")
            echo "::notice::$message" >&2
            ;;
        "DEBUG")
            [[ "${RUNNER_DEBUG:-}" == "1" ]] && echo "::debug::$message" >&2 || true
            ;;
    esac
    
    # Also log to stderr for non-GitHub CI systems
    echo "[$timestamp] [$level] $message" >&2
}

# GitHub Actions specific annotations
github_set_output() {
    local name="$1"
    local value="$2"
    
    if [[ "$IS_GITHUB_ACTIONS" == "true" ]]; then
        echo "$name=$value" >> "${GITHUB_OUTPUT:-/dev/null}"
    fi
}

github_step_summary() {
    local content="$1"
    
    if [[ "$IS_GITHUB_ACTIONS" == "true" && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "$content" >> "$GITHUB_STEP_SUMMARY"
    fi
}

# ============================================================================
# CI ENVIRONMENT VALIDATION
# ============================================================================

validate_ci_environment() {
    ci_log "INFO" "Validating CI environment..."
    
    # Check CI-specific environment variables
    if [[ "$IS_CI" == "true" ]]; then
        ci_log "INFO" "Running in CI environment"
        
        # Validate CI-specific constraints
        if [[ ! "$CI_FUZZTIME" =~ ^[0-9]+[smh]$ ]]; then
            ci_log "ERROR" "Invalid CI_FUZZTIME: $CI_FUZZTIME"
            return 1
        fi
        
        # Convert to seconds for timeout calculation
        local duration_seconds
        duration_seconds=$(echo "$CI_FUZZTIME" | sed 's/s$//' | sed 's/m$/*60/' | sed 's/h$/*3600/' | bc -l)
        
        if (( $(echo "$duration_seconds > 600" | bc -l) )); then
            ci_log "WARNING" "CI_FUZZTIME ($CI_FUZZTIME) exceeds recommended 10m limit"
        fi
        
        if (( CI_PARALLEL_JOBS > MAX_CI_PARALLEL )); then
            ci_log "WARNING" "CI_PARALLEL_JOBS ($CI_PARALLEL_JOBS) exceeds maximum ($MAX_CI_PARALLEL)"
            CI_PARALLEL_JOBS=$MAX_CI_PARALLEL
        fi
    fi
    
    # Check for required CI tools
    local missing_tools=()
    for tool in go find grep awk; do
        if ! command -v "$tool" >/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if (( ${#missing_tools[@]} > 0 )); then
        ci_log "ERROR" "Missing required tools: ${missing_tools[*]}"
        return 1
    fi
    
    # Validate workspace permissions
    if [[ ! -w "$PROJECT_ROOT" ]]; then
        ci_log "ERROR" "Project root is not writable: $PROJECT_ROOT"
        return 1
    fi
    
    return 0
}

# ============================================================================
# LIGHTWEIGHT FUZZ TEST DISCOVERY
# ============================================================================

discover_ci_fuzz_tests() {
    local test_category="$1"
    local output_file="$2"
    
    ci_log "INFO" "Discovering $test_category fuzz tests..."
    
    # Fast discovery optimized for CI
    case "$test_category" in
        "security-critical")
            # High-priority security tests only
            find "$PROJECT_ROOT" \( \
                -path "*/pkg/security/*_fuzz_test.go" -o \
                -path "*/pkg/crypto/*_fuzz_test.go" -o \
                -path "*/pkg/execute/*_fuzz_test.go" \
                \) -type f 2>/dev/null | \
            head -20 > "$output_file"  # Limit for CI speed
            ;;
        "architecture")
            # STACK.md compliance tests
            find "$PROJECT_ROOT" \( \
                -path "*/test/*architecture*_fuzz_test.go" -o \
                -path "*/pkg/saltstack/*_fuzz_test.go" \
                \) -type f 2>/dev/null | \
            head -10 > "$output_file"  # Smaller set for CI
            ;;
        "quick")
            # Fastest subset for PR validation
            find "$PROJECT_ROOT" -path "*/pkg/*" -name "*_fuzz_test.go" -type f 2>/dev/null | \
            head -5 > "$output_file"  # Very limited for speed
            ;;
        *)
            ci_log "ERROR" "Unknown test category: $test_category"
            return 1
            ;;
    esac
    
    local count
    count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    ci_log "INFO" "Found $count $test_category tests"
    
    return 0
}

# Extract fuzz functions from test files (CI-optimized)
extract_fuzz_functions() {
    local test_files_list="$1"
    local output_file="$2"
    
    > "$output_file"  # Clear output file
    
    while IFS= read -r test_file; do
        if [[ -f "$test_file" && -r "$test_file" ]]; then
            local package_path
            package_path=$(dirname "$test_file" | sed "s|^$PROJECT_ROOT/||")
            
            # Fast grep for fuzz functions
            grep -o '^func \(Fuzz[A-Za-z0-9_]*\)(' "$test_file" 2>/dev/null | \
            sed 's/^func \([^(]*\)(.*/\1/' | \
            while read -r func_name; do
                echo "${func_name}::${package_path}" >> "$output_file"
            done
        fi
    done < "$test_files_list"
}

# ============================================================================
# CI-OPTIMIZED FUZZ EXECUTION
# ============================================================================

run_ci_fuzz_test() {
    local test_spec="$1"
    local log_file="$2"
    local timeout_seconds="$3"
    
    local test_name="${test_spec%%::*}"
    local package_path="${test_spec##*::}"
    
    # Input validation
    if [[ ! "$test_name" =~ ^Fuzz[A-Za-z0-9_]+$ ]]; then
        ci_log "ERROR" "Invalid test name: $test_name"
        return 1
    fi
    
    ci_log "INFO" "Running $test_name (timeout: ${timeout_seconds}s)"
    
    # CI-optimized go test command
    local go_cmd=(
        timeout "${timeout_seconds}s"
        go test
        -v
        -run='^$'
        -fuzz="^${test_name}$"
        -fuzztime="$CI_FUZZTIME"
        "./$package_path"
    )
    
    local start_time
    start_time=$(date +%s)
    
    # Execute with comprehensive error handling
    local exit_code=0
    if "${go_cmd[@]}" > "$log_file" 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi
    
    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    # Extract key metrics for CI
    local new_inputs=0
    local executions=0
    local crashes=0
    
    if [[ -f "$log_file" ]]; then
        new_inputs=$(grep -c "new interesting input" "$log_file" 2>/dev/null || echo "0")
        executions=$(grep -o 'execs: [0-9]*' "$log_file" | tail -1 | grep -o '[0-9]*' || echo "0")
        crashes=$(grep -c "failing input\|panic:" "$log_file" 2>/dev/null || echo "0")
    fi
    
    # CI-specific result handling
    if (( exit_code == 0 )); then
        ci_log "INFO" "$test_name: ${new_inputs} inputs, ${executions} execs, ${elapsed}s"
    else
        ci_log "ERROR" "❌ $test_name failed: exit $exit_code, ${crashes} crashes, ${elapsed}s"
        
        # Security alert for crashes
        if (( crashes > 0 )); then
            ci_log "ERROR" " SECURITY: $test_name found $crashes crashes!"
            github_set_output "security_alert" "true"
            github_set_output "security_test" "$test_name"
            github_set_output "crash_count" "$crashes"
        fi
    fi
    
    # Output metrics for CI processing
    echo "$test_name,$exit_code,$new_inputs,$executions,$crashes,$elapsed" >> "$CI_LOG_DIR/metrics.csv"
    
    return $exit_code
}

# ============================================================================
# CI WORKFLOW EXECUTION
# ============================================================================

run_pr_validation() {
    ci_log "INFO" "Running PR validation fuzzing..."
    
    local test_files="$CI_LOG_DIR/pr-tests.txt"
    local test_specs="$CI_LOG_DIR/pr-specs.txt"
    
    # Quick discovery for PR validation
    discover_ci_fuzz_tests "quick" "$test_files"
    extract_fuzz_functions "$test_files" "$test_specs"
    
    local failed_tests=0
    local total_tests=0
    local timeout_seconds=120  # 2 minutes max per test
    
    # Execute tests sequentially for PR (faster than parallel for small sets)
    while IFS= read -r test_spec; do
        if [[ -n "$test_spec" ]]; then
            ((total_tests++))
            local test_name="${test_spec%%::*}"
            local log_file="$CI_LOG_DIR/pr-${test_name}.log"
            
            if ! run_ci_fuzz_test "$test_spec" "$log_file" "$timeout_seconds"; then
                ((failed_tests++))
            fi
        fi
    done < "$test_specs"
    
    # PR summary
    local success_rate=0
    if (( total_tests > 0 )); then
        success_rate=$(( ((total_tests - failed_tests) * 100) / total_tests ))
    fi
    
    ci_log "INFO" "PR validation: $((total_tests - failed_tests))/$total_tests passed ($success_rate%)"
    
    # GitHub Actions integration
    github_set_output "pr_tests_total" "$total_tests"
    github_set_output "pr_tests_failed" "$failed_tests"
    github_set_output "pr_success_rate" "$success_rate"
    
    return $failed_tests
}

run_security_focused_ci() {
    ci_log "INFO" "Running security-focused CI fuzzing..."
    
    local test_files="$CI_LOG_DIR/security-tests.txt"
    local test_specs="$CI_LOG_DIR/security-specs.txt"
    
    # Discover security tests
    discover_ci_fuzz_tests "security-critical" "$test_files"
    extract_fuzz_functions "$test_files" "$test_specs"
    
    local failed_tests=0
    local total_tests=0
    local security_alerts=0
    local timeout_seconds=300  # 5 minutes max per test
    
    # Parallel execution for security tests
    local pids=()
    local job_specs=()
    
    while IFS= read -r test_spec; do
        if [[ -n "$test_spec" ]]; then
            ((total_tests++))
            local test_name="${test_spec%%::*}"
            local log_file="$CI_LOG_DIR/security-${test_name}.log"
            
            # Start background job
            run_ci_fuzz_test "$test_spec" "$log_file" "$timeout_seconds" &
            local pid=$!
            pids+=("$pid")
            job_specs+=("$test_spec")
            
            # Limit parallel jobs
            if (( ${#pids[@]} >= CI_PARALLEL_JOBS )); then
                # Wait for first job to complete
                wait "${pids[0]}" || ((failed_tests++))
                pids=("${pids[@]:1}")  # Remove first element
                job_specs=("${job_specs[@]:1}")
            fi
        fi
    done < "$test_specs"
    
    # Wait for remaining jobs
    for pid in "${pids[@]}"; do
        wait "$pid" || ((failed_tests++))
    done
    
    # Check for security alerts
    if [[ -f "$CI_LOG_DIR/metrics.csv" ]]; then
        security_alerts=$(awk -F',' '$5 > 0 {count++} END {print count+0}' "$CI_LOG_DIR/metrics.csv")
    fi
    
    ci_log "INFO" "Security fuzzing: $((total_tests - failed_tests))/$total_tests passed"
    
    if (( security_alerts > 0 )); then
        ci_log "ERROR" " $security_alerts security alerts detected!"
        github_set_output "security_alerts_count" "$security_alerts"
    fi
    
    github_set_output "security_tests_total" "$total_tests"
    github_set_output "security_tests_failed" "$failed_tests"
    
    return $failed_tests
}

run_architecture_ci() {
    ci_log "INFO" "Running architecture compliance fuzzing..."
    
    local test_files="$CI_LOG_DIR/arch-tests.txt"
    local test_specs="$CI_LOG_DIR/arch-specs.txt"
    
    # Discover architecture tests
    discover_ci_fuzz_tests "architecture" "$test_files"
    extract_fuzz_functions "$test_files" "$test_specs"
    
    local failed_tests=0
    local total_tests=0
    local timeout_seconds=240  # 4 minutes max per test
    
    while IFS= read -r test_spec; do
        if [[ -n "$test_spec" ]]; then
            ((total_tests++))
            local test_name="${test_spec%%::*}"
            local log_file="$CI_LOG_DIR/arch-${test_name}.log"
            
            if ! run_ci_fuzz_test "$test_spec" "$log_file" "$timeout_seconds"; then
                ((failed_tests++))
            fi
        fi
    done < "$test_specs"
    
    ci_log "INFO" "Architecture fuzzing: $((total_tests - failed_tests))/$total_tests passed"
    
    github_set_output "arch_tests_total" "$total_tests"
    github_set_output "arch_tests_failed" "$failed_tests"
    
    return $failed_tests
}

# ============================================================================
# CI REPORT GENERATION
# ============================================================================

generate_ci_report() {
    local total_failed="$1"
    
    ci_log "INFO" "Generating CI fuzz report..."
    
    local report_file="$CI_LOG_DIR/fuzz-report.md"
    local metrics_file="$CI_LOG_DIR/metrics.csv"
    
    # Initialize CSV header
    echo "test_name,exit_code,new_inputs,executions,crashes,elapsed_seconds" > "$metrics_file"
    
    # Calculate summary statistics
    local total_tests=0
    local total_crashes=0
    local total_inputs=0
    
    if [[ -f "$metrics_file" ]] && (( $(wc -l < "$metrics_file") > 1 )); then
        total_tests=$(tail -n +2 "$metrics_file" | wc -l)
        total_crashes=$(tail -n +2 "$metrics_file" | awk -F',' '{sum+=$5} END {print sum+0}')
        total_inputs=$(tail -n +2 "$metrics_file" | awk -F',' '{sum+=$3} END {print sum+0}')
    fi
    
    local success_rate=0
    if (( total_tests > 0 )); then
        success_rate=$(( ((total_tests - total_failed) * 100) / total_tests ))
    fi
    
    # Generate markdown report
    cat > "$report_file" << EOF
# EOS CI Fuzz Test Report

**Environment:** $IS_PULL_REQUEST  
**Timestamp:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")  
**Duration:** $CI_FUZZTIME per test  
**Parallel Jobs:** $CI_PARALLEL_JOBS  

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | $total_tests |
| Passed | $((total_tests - total_failed)) |
| Failed | $total_failed |
| Success Rate | ${success_rate}% |
| New Inputs Found | $total_inputs |
| Potential Crashes | $total_crashes |

EOF
    
    # Add security alerts if any
    if (( total_crashes > 0 )); then
        cat >> "$report_file" << EOF
##  Security Alerts

**$total_crashes potential security issues detected!**

Immediate investigation required:
1. Review crash logs in the CI artifacts
2. Analyze failing inputs for exploitability  
3. Update security measures before merging

EOF
    fi
    
    # Add recommendations
    if (( total_failed == 0 && total_crashes == 0 )); then
        cat >> "$report_file" << EOF
## All Tests Passed

The code changes appear to maintain security standards.
Consider running extended fuzzing before deployment.

EOF
    elif (( total_failed > 0 && total_crashes == 0 )); then
        cat >> "$report_file" << EOF
## Test Failures Detected

Some tests failed without security implications.
Review logs for configuration or logic issues.

EOF
    fi
    
    cat >> "$report_file" << EOF
## CI Integration

This report was generated by the EOS CI fuzzing framework.
- **Logs:** Check CI artifacts for detailed logs
- **Metrics:** \`$metrics_file\`
- **Configuration:** STACK.md Section 4.1 compliant

EOF
    
    # GitHub Actions step summary
    if [[ "$IS_GITHUB_ACTIONS" == "true" ]]; then
        github_step_summary "$(cat "$report_file")"
    fi
    
    ci_log "INFO" "CI report generated: $report_file"
}

# ============================================================================
# MAIN CI EXECUTION
# ============================================================================

show_ci_usage() {
    cat << EOF
USAGE: $SCRIPT_NAME [MODE]

EOS CI/CD Fuzzing Integration

MODES:
  pr-validation     Quick validation for pull requests (default)
  security-focused  Comprehensive security testing
  architecture      STACK.md architecture compliance testing
  full             Complete fuzzing suite

ENVIRONMENT VARIABLES:
  CI_FUZZTIME=duration     Duration per test (default: $CI_FUZZTIME)
  CI_PARALLEL_JOBS=N       Parallel jobs (default: $CI_PARALLEL_JOBS)
  CI_LOG_DIR=path          Log directory (default: $CI_LOG_DIR)

EXAMPLES:
  $SCRIPT_NAME pr-validation    # Fast PR validation
  $SCRIPT_NAME security-focused # Security-focused testing
  $SCRIPT_NAME architecture     # Architecture compliance
  $SCRIPT_NAME full            # Complete test suite

GITHUB ACTIONS INTEGRATION:
  Sets outputs: security_alert, tests_total, tests_failed, success_rate
  Creates step summary with results
  Generates CI artifacts

EOF
}

main() {
    local mode="${1:-pr-validation}"
    
    ci_log "INFO" "Starting EOS CI Fuzzing v2.0.0 (mode: $mode)"
    
    # Validate CI environment
    if ! validate_ci_environment; then
        ci_log "ERROR" "CI environment validation failed"
        return 1
    fi
    
    # Create log directory
    mkdir -p "$CI_LOG_DIR"
    
    # Initialize metrics file
    echo "test_name,exit_code,new_inputs,executions,crashes,elapsed_seconds" > "$CI_LOG_DIR/metrics.csv"
    
    local total_failed=0
    
    # Execute based on mode
    case "$mode" in
        "pr-validation")
            run_pr_validation || total_failed=$?
            ;;
        "security-focused")
            run_security_focused_ci || total_failed=$?
            ;;
        "architecture")
            run_architecture_ci || total_failed=$?
            ;;
        "full")
            run_pr_validation || ((total_failed += $?))
            run_security_focused_ci || ((total_failed += $?))
            run_architecture_ci || ((total_failed += $?))
            ;;
        *)
            ci_log "ERROR" "Unknown mode: $mode"
            show_ci_usage
            return 1
            ;;
    esac
    
    # Generate CI report
    generate_ci_report "$total_failed"
    
    # Final status
    if (( total_failed == 0 )); then
        ci_log "INFO" "CI fuzzing completed successfully"
        github_set_output "fuzzing_status" "success"
    else
        ci_log "ERROR" "❌ CI fuzzing detected issues ($total_failed failures)"
        github_set_output "fuzzing_status" "failure"
    fi
    
    return $total_failed
}

# Handle command line arguments
case "${1:-}" in
    -h|--help|help)
        show_ci_usage
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac