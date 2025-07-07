#!/bin/bash
# EOS Fuzzing Framework - Architecturally Aligned and Operationally Sane
# Implements STACK.md Section 4.1 (Testing Strategy Framework) requirements
# Version: 2.0.0

set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# CONFIGURATION AND VALIDATION
# ============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default configuration (STACK.md Section 4.3 - Operational Procedures)
readonly DEFAULT_FUZZTIME="30s"
readonly DEFAULT_PARALLEL_JOBS=4
readonly DEFAULT_LOG_RETENTION_DAYS=7
readonly MAX_PARALLEL_JOBS=16
readonly MAX_LOG_SIZE_MB=100

# Environment-based configuration with validation
FUZZTIME="${1:-${FUZZTIME:-$DEFAULT_FUZZTIME}}"
PARALLEL_JOBS="${PARALLEL_JOBS:-$DEFAULT_PARALLEL_JOBS}"
LOG_DIR="${LOG_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/eos-fuzz}"
SECURITY_FOCUS="${SECURITY_FOCUS:-true}"
ARCHITECTURE_TESTING="${ARCHITECTURE_TESTING:-false}"
VERBOSE="${VERBOSE:-false}"

# Security: Validate and sanitize inputs
readonly TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
readonly SESSION_DIR="${LOG_DIR}/${TIMESTAMP}"
readonly REPORT_FILE="${SESSION_DIR}/fuzz-report.md"
readonly PID_FILE="${SESSION_DIR}/fuzz.pid"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Logging with structured output (STACK.md observability requirements)
log() {
    local level="$1"
    shift
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $*" >&2
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { 
    [[ "$VERBOSE" == "true" ]] && log "DEBUG" "$@" || true
}

# Error handling with proper cleanup (STACK.md Section 3.5 - Failure Scenarios)
cleanup() {
    local exit_code=$?
    log_info "Cleaning up fuzzing session..."
    
    # Kill any remaining background jobs
    if [[ -f "$PID_FILE" ]]; then
        while read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                log_debug "Terminating background job: $pid"
                kill -TERM "$pid" 2>/dev/null || true
                sleep 2
                kill -KILL "$pid" 2>/dev/null || true
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    
    # Clean up temporary files older than retention period
    find "$LOG_DIR" -type f -name "*.tmp" -mtime +1 -delete 2>/dev/null || true
    
    # Archive old sessions
    find "$LOG_DIR" -type d -name "20*" -mtime +$DEFAULT_LOG_RETENTION_DAYS -exec rm -rf {} + 2>/dev/null || true
    
    log_info "Cleanup completed (exit code: $exit_code)"
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Input validation (Security hardening)
validate_inputs() {
    # Validate fuzz time format
    if ! [[ "$FUZZTIME" =~ ^[0-9]+[smh]$ ]]; then
        log_error "Invalid FUZZTIME format: $FUZZTIME (expected: 10s, 5m, 1h)"
        return 1
    fi
    
    # Validate parallel jobs
    if ! [[ "$PARALLEL_JOBS" =~ ^[0-9]+$ ]] || (( PARALLEL_JOBS < 1 || PARALLEL_JOBS > MAX_PARALLEL_JOBS )); then
        log_error "Invalid PARALLEL_JOBS: $PARALLEL_JOBS (expected: 1-$MAX_PARALLEL_JOBS)"
        return 1
    fi
    
    # Validate log directory permissions
    if [[ ! -d "$(dirname "$LOG_DIR")" ]]; then
        log_error "Parent directory of LOG_DIR does not exist: $(dirname "$LOG_DIR")"
        return 1
    fi
    
    return 0
}

# System resource validation (STACK.md Section 3.2 - Resource Gotchas)
check_system_resources() {
    local available_memory_mb
    local available_disk_mb
    
    # Check available memory (Linux/macOS compatible)
    if command -v free >/dev/null; then
        available_memory_mb=$(free -m | awk '/^Mem:/ {print $7}')
    elif [[ "$(uname)" == "Darwin" ]]; then
        available_memory_mb=$(( $(vm_stat | awk '/free:/ {print $3}' | tr -d '.') * 4096 / 1024 / 1024 ))
    else
        log_warn "Cannot determine available memory, proceeding anyway"
        return 0
    fi
    
    # Check available disk space
    available_disk_mb=$(df "$LOG_DIR" 2>/dev/null | awk 'NR==2 {print int($4/1024)}' || echo "1000")
    
    # Resource requirements based on parallel jobs
    local required_memory_mb=$((PARALLEL_JOBS * 256))  # 256MB per fuzz job
    local required_disk_mb=$((MAX_LOG_SIZE_MB * 2))    # Double for safety
    
    if (( available_memory_mb < required_memory_mb )); then
        log_warn "Low memory: ${available_memory_mb}MB available, ${required_memory_mb}MB recommended"
        log_warn "Consider reducing PARALLEL_JOBS or freeing memory"
    fi
    
    if (( available_disk_mb < required_disk_mb )); then
        log_error "Insufficient disk space: ${available_disk_mb}MB available, ${required_disk_mb}MB required"
        return 1
    fi
    
    log_debug "Resource check passed: ${available_memory_mb}MB memory, ${available_disk_mb}MB disk"
    return 0
}

# Dependency checking with graceful degradation
check_dependencies() {
    local missing_deps=()
    local optional_deps=()
    
    # Required dependencies
    for cmd in go find grep awk; do
        if ! command -v "$cmd" >/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    # Optional dependencies for enhanced features
    for cmd in bc stress-ng; do
        if ! command -v "$cmd" >/dev/null; then
            optional_deps+=("$cmd")
        fi
    done
    
    if (( ${#missing_deps[@]} > 0 )); then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Please install missing dependencies and try again"
        return 1
    fi
    
    if (( ${#optional_deps[@]} > 0 )); then
        log_warn "Missing optional dependencies: ${optional_deps[*]}"
        log_warn "Some advanced features may be unavailable"
    fi
    
    # Check Go version
    local go_version
    if ! go_version=$(go version 2>/dev/null); then
        log_error "Go is not properly installed or configured"
        return 1
    fi
    
    log_debug "Dependencies validated: $go_version"
    return 0
}

# ============================================================================
# FUZZ TEST DISCOVERY (Dynamic and Secure)
# ============================================================================

# Dynamically discover fuzz tests (STACK.md Section 4.1 compliance)
discover_fuzz_tests() {
    local test_type="$1"
    local tests_file="${SESSION_DIR}/discovered-tests-${test_type}.txt"
    
    log_info "Discovering $test_type fuzz tests..."
    
    # Security: Use safe find with explicit constraints
    case "$test_type" in
        "security")
            # Security-critical packages (STACK.md Section 3 - Security focus)
            find "$PROJECT_ROOT" -path "*/pkg/security/*" -name "*_fuzz_test.go" -o \
                                -path "*/pkg/crypto/*" -name "*_fuzz_test.go" -o \
                                -path "*/pkg/execute/*" -name "*_fuzz_test.go" \
                                2>/dev/null | sort > "$tests_file.tmp"
            ;;
        "architecture") 
            # Architecture-specific tests (STACK.md Section 1.2 compliance)
            find "$PROJECT_ROOT" -path "*/test/*" -name "*architecture*_fuzz_test.go" -o \
                                -path "*/pkg/saltstack/*" -name "*_fuzz_test.go" -o \
                                -path "*/pkg/terraform/*" -name "*_fuzz_test.go" \
                                2>/dev/null | sort > "$tests_file.tmp"
            ;;
        "component")
            # Standard component tests
            find "$PROJECT_ROOT" -path "*/pkg/*" -name "*_fuzz_test.go" \
                                ! -path "*/pkg/security/*" \
                                ! -path "*/pkg/crypto/*" \
                                ! -path "*/pkg/execute/*" \
                                ! -path "*/pkg/saltstack/*" \
                                ! -path "*/pkg/terraform/*" \
                                2>/dev/null | sort > "$tests_file.tmp"
            ;;
        *)
            log_error "Invalid test type: $test_type"
            return 1
            ;;
    esac
    
    # Extract fuzz function names securely
    local count=0
    while IFS= read -r test_file; do
        if [[ -f "$test_file" ]]; then
            # Security: Validate file paths and extract function names safely
            local package_path
            package_path=$(dirname "$test_file" | sed "s|^$PROJECT_ROOT/||")
            
            # Extract fuzz function names using safe grep
            grep -o '^func \(Fuzz[A-Za-z0-9_]*\)(' "$test_file" 2>/dev/null | \
            sed 's/^func \([^(]*\)(.*/\1/' | \
            while read -r func_name; do
                if [[ "$func_name" =~ ^Fuzz[A-Za-z0-9_]+$ ]]; then
                    echo "${func_name}::${package_path}"
                    ((count++))
                fi
            done >> "$tests_file"
        fi
    done < "$tests_file.tmp"
    
    rm -f "$tests_file.tmp"
    
    local final_count
    final_count=$(wc -l < "$tests_file" 2>/dev/null || echo "0")
    log_info "Discovered $final_count $test_type fuzz tests"
    
    return 0
}

# ============================================================================
# FUZZ TEST EXECUTION ENGINE
# ============================================================================

# Execute individual fuzz test with comprehensive monitoring
run_fuzz_test() {
    local test_spec="$1"
    local test_category="$2"
    local duration="$3"
    
    # Parse test specification securely
    local test_name="${test_spec%%::*}"
    local package_path="${test_spec##*::}"
    
    # Validate inputs
    if [[ ! "$test_name" =~ ^Fuzz[A-Za-z0-9_]+$ ]]; then
        log_error "Invalid test name format: $test_name"
        return 1
    fi
    
    if [[ "$package_path" =~ \.\. ]] || [[ "$package_path" =~ ^/ ]]; then
        log_error "Unsafe package path: $package_path"
        return 1
    fi
    
    local log_file="${SESSION_DIR}/${test_category}/${test_name}.log"
    local corpus_dir="${SESSION_DIR}/corpus/${test_name}"
    local metrics_file="${SESSION_DIR}/${test_category}/${test_name}.metrics"
    
    # Ensure directories exist
    mkdir -p "$(dirname "$log_file")" "$corpus_dir"
    
    log_info "Starting $test_name in ./$package_path (duration: $duration)"
    
    local start_time
    start_time=$(date +%s)
    
    # Enhanced fuzz execution with monitoring
    local go_cmd=(
        go test
        -v
        -run='^$'
        -fuzz="^${test_name}$"
        -fuzztime="$duration"
        -fuzzminimizetime=5s
        "./$package_path"
    )
    
    # Security: Set resource limits
    if command -v ulimit >/dev/null; then
        # Limit memory to 1GB per test
        ulimit -v 1048576 2>/dev/null || log_warn "Could not set memory limit"
    fi
    
    # Execute test with timeout protection
    local exit_code=0
    if timeout $(($(echo "$duration" | sed 's/[^0-9]*//g') * 2 + 60)) "${go_cmd[@]}" > "$log_file" 2>&1; then
        exit_code=0
    else
        exit_code=$?
        log_warn "$test_name failed with exit code $exit_code"
    fi
    
    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    # Extract metrics safely
    local inputs=0
    local executions=0
    local crashes=0
    
    if [[ -f "$log_file" ]]; then
        inputs=$(grep -c "new interesting input" "$log_file" 2>/dev/null || echo "0")
        executions=$(grep -o 'execs: [0-9]*' "$log_file" | tail -1 | grep -o '[0-9]*' || echo "0")
        crashes=$(grep -c "failing input\|panic:" "$log_file" 2>/dev/null || echo "0")
    fi
    
    # Write metrics
    cat > "$metrics_file" << EOF
test_name=$test_name
package_path=$package_path
category=$test_category
duration=$duration
elapsed_seconds=$elapsed
exit_code=$exit_code
new_inputs=$inputs
executions=$executions
crashes=$crashes
timestamp=$start_time
EOF
    
    # Report results
    if (( exit_code == 0 )); then
        log_info "✅ $test_name completed: ${inputs} inputs, ${executions} execs, ${elapsed}s"
        echo "- ✅ **$test_name** ($test_category): SUCCESS - ${inputs} inputs, ${executions} executions, ${elapsed}s" >> "$REPORT_FILE"
    else
        log_warn "❌ $test_name failed: exit $exit_code, ${crashes} crashes, ${elapsed}s"
        echo "- ❌ **$test_name** ($test_category): FAILED - exit $exit_code, ${crashes} crashes, ${elapsed}s" >> "$REPORT_FILE"
        
        # Security alert for crashes
        if (( crashes > 0 )); then
            log_error "🚨 SECURITY ALERT: $test_name found $crashes potential crashes!"
            echo "  - 🚨 **SECURITY ALERT**: $crashes potential crashes detected" >> "$REPORT_FILE"
        fi
    fi
    
    return $exit_code
}

# ============================================================================
# EXECUTION ORCHESTRATION
# ============================================================================

# Job queue management with proper resource control
execute_fuzz_tests() {
    local test_type="$1"
    local tests_file="${SESSION_DIR}/discovered-tests-${test_type}.txt"
    
    if [[ ! -f "$tests_file" ]]; then
        log_warn "No tests file found for $test_type"
        return 0
    fi
    
    local total_tests
    total_tests=$(wc -l < "$tests_file")
    
    if (( total_tests == 0 )); then
        log_warn "No $test_type tests discovered"
        return 0
    fi
    
    log_info "Executing $total_tests $test_type tests with $PARALLEL_JOBS parallel jobs"
    
    # Job control arrays
    local pids=()
    local active_jobs=0
    local completed_jobs=0
    local failed_jobs=0
    
    # Process each test
    while IFS= read -r test_spec; do
        # Wait for available slot
        while (( active_jobs >= PARALLEL_JOBS )); do
            for i in "${!pids[@]}"; do
                local pid="${pids[i]}"
                if ! kill -0 "$pid" 2>/dev/null; then
                    # Job completed
                    local job_exit_code=0
                    wait "$pid" || job_exit_code=$?
                    
                    if (( job_exit_code == 0 )); then
                        ((completed_jobs++))
                    else
                        ((failed_jobs++))
                    fi
                    
                    # Remove from tracking
                    unset "pids[i]"
                    ((active_jobs--))
                    
                    # Remove from PID file
                    if [[ -f "$PID_FILE" ]]; then
                        grep -v "^$pid$" "$PID_FILE" > "$PID_FILE.tmp" || true
                        mv "$PID_FILE.tmp" "$PID_FILE"
                    fi
                fi
            done
            
            # Brief sleep to prevent busy waiting
            sleep 0.5
        done
        
        # Start new test job
        (
            run_fuzz_test "$test_spec" "$test_type" "$FUZZTIME"
        ) &
        
        local job_pid=$!
        pids+=("$job_pid")
        echo "$job_pid" >> "$PID_FILE"
        ((active_jobs++))
        
        log_debug "Started job $job_pid for test: $test_spec"
        
        # Brief delay to prevent overwhelming the system
        sleep 0.1
        
    done < "$tests_file"
    
    # Wait for all remaining jobs
    log_info "Waiting for remaining $active_jobs jobs to complete..."
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            local job_exit_code=0
            wait "$pid" || job_exit_code=$?
            
            if (( job_exit_code == 0 )); then
                ((completed_jobs++))
            else
                ((failed_jobs++))
            fi
        fi
    done
    
    log_info "$test_type tests completed: $completed_jobs passed, $failed_jobs failed"
    
    return $failed_jobs
}

# ============================================================================
# REPORTING AND ANALYSIS
# ============================================================================

# Generate comprehensive report (STACK.md Section 4.2 - Observability)
generate_report() {
    log_info "Generating comprehensive fuzz test report..."
    
    # Calculate summary statistics
    local total_passed=0
    local total_failed=0
    local total_crashes=0
    local total_inputs=0
    
    # Aggregate metrics from all categories
    for category in security architecture component; do
        local metrics_dir="${SESSION_DIR}/${category}"
        if [[ -d "$metrics_dir" ]]; then
            while IFS= read -r metrics_file; do
                if [[ -f "$metrics_file" ]]; then
                    # Safely parse metrics
                    local exit_code crashes new_inputs
                    exit_code=$(grep "^exit_code=" "$metrics_file" | cut -d= -f2 || echo "1")
                    crashes=$(grep "^crashes=" "$metrics_file" | cut -d= -f2 || echo "0")
                    new_inputs=$(grep "^new_inputs=" "$metrics_file" | cut -d= -f2 || echo "0")
                    
                    if (( exit_code == 0 )); then
                        ((total_passed++))
                    else
                        ((total_failed++))
                    fi
                    
                    ((total_crashes += crashes))
                    ((total_inputs += new_inputs))
                fi
            done < <(find "$metrics_dir" -name "*.metrics" 2>/dev/null)
        fi
    done
    
    local total_tests=$((total_passed + total_failed))
    local success_rate=0
    
    if (( total_tests > 0 )); then
        success_rate=$(( (total_passed * 100) / total_tests ))
    fi
    
    # Generate final report
    cat >> "$REPORT_FILE" << EOF

## Executive Summary

**Total Tests:** $total_tests  
**Passed:** $total_passed  
**Failed:** $total_failed  
**Success Rate:** ${success_rate}%  
**New Inputs Found:** $total_inputs  
**Potential Crashes:** $total_crashes  

**Configuration:**
- Duration per test: $FUZZTIME
- Parallel jobs: $PARALLEL_JOBS
- Security focus: $SECURITY_FOCUS
- Architecture testing: $ARCHITECTURE_TESTING

**System Information:**
- Hostname: $(hostname)
- OS: $(uname -s) $(uname -r)
- Go version: $(go version | cut -d' ' -f3)
- Session: $TIMESTAMP

## Recommendations

EOF
    
    # Add security recommendations
    if (( total_crashes > 0 )); then
        cat >> "$REPORT_FILE" << EOF
🚨 **IMMEDIATE ACTION REQUIRED**
- $total_crashes potential security issues detected
- Review crash logs in ${SESSION_DIR}/*/
- Investigate failing inputs for exploitability
- Update security measures before deployment

EOF
    fi
    
    if (( total_failed > 0 && total_crashes == 0 )); then
        cat >> "$REPORT_FILE" << EOF
⚠️ **INVESTIGATION RECOMMENDED**
- $total_failed tests failed without crashes
- Review logs for configuration or logic issues
- Consider increasing test duration or resources

EOF
    fi
    
    if (( total_tests > 0 && total_failed == 0 )); then
        cat >> "$REPORT_FILE" << EOF
✅ **GOOD SECURITY POSTURE**
- All fuzz tests passed successfully
- Consider increasing test duration for deeper coverage
- Regular fuzzing schedule recommended

EOF
    fi
    
    # Add technical details
    cat >> "$REPORT_FILE" << EOF
## Technical Details

**Log Directory:** \`$SESSION_DIR\`  
**Report Generated:** $(date)  
**Command Used:** \`$0 $*\`

EOF
    
    log_info "Report generated: $REPORT_FILE"
}

# ============================================================================
# MAIN EXECUTION FLOW
# ============================================================================

show_usage() {
    cat << EOF
USAGE: $SCRIPT_NAME [DURATION] [OPTIONS]

EOS Fuzzing Framework - Architecturally aligned with STACK.md

DURATION:
  Time per fuzz test (default: $DEFAULT_FUZZTIME)
  Format: <number><unit> where unit is s/m/h
  Examples: 30s, 5m, 1h

ENVIRONMENT VARIABLES:
  PARALLEL_JOBS=N          Parallel jobs (1-$MAX_PARALLEL_JOBS, default: $DEFAULT_PARALLEL_JOBS)
  LOG_DIR=path             Log directory (default: ~/.cache/eos-fuzz)
  SECURITY_FOCUS=true      Focus on security-critical tests (default: true)
  ARCHITECTURE_TESTING=X   Enable architecture testing (default: false)
  VERBOSE=true             Enable debug logging (default: false)

EXAMPLES:
  $SCRIPT_NAME 60s                               # Standard 1-minute fuzz
  SECURITY_FOCUS=true $SCRIPT_NAME 5m            # Security-focused 5-minute fuzz
  PARALLEL_JOBS=8 ARCHITECTURE_TESTING=true $SCRIPT_NAME 2m
  VERBOSE=true $SCRIPT_NAME 30s                  # Debug mode

SECURITY:
  - All inputs are validated and sanitized
  - Resource limits are enforced
  - Temporary files are cleaned up automatically
  - Crash detection with security alerts

COMPLIANCE:
  - Implements STACK.md Section 4.1 (Testing Strategy)
  - Addresses Section 3 (Operational Challenges)
  - Follows Section 4.3 (Operational Procedures)

EOF
}

main() {
    log_info "Starting EOS Fuzzing Framework v2.0.0"
    log_info "Session: $TIMESTAMP"
    
    # Validate inputs and environment
    if ! validate_inputs; then
        show_usage
        return 1
    fi
    
    # Check system resources and dependencies
    if ! check_dependencies || ! check_system_resources; then
        log_error "Pre-flight checks failed"
        return 1
    fi
    
    # Create session directory structure
    mkdir -p "$SESSION_DIR"/{security,architecture,component,corpus}
    
    # Initialize report
    cat > "$REPORT_FILE" << EOF
# EOS Fuzz Test Report

**Generated:** $(date)  
**Session:** $TIMESTAMP  
**Duration:** $FUZZTIME  
**Parallel Jobs:** $PARALLEL_JOBS  

## Test Results

EOF
    
    local overall_exit_code=0
    
    # Execute security tests (highest priority - STACK.md Section 3)
    if [[ "$SECURITY_FOCUS" == "true" ]]; then
        log_info "=== SECURITY-CRITICAL FUZZING ==="
        discover_fuzz_tests "security"
        if ! execute_fuzz_tests "security"; then
            overall_exit_code=1
        fi
    fi
    
    # Execute architecture tests (STACK.md Section 1.2 compliance)
    if [[ "$ARCHITECTURE_TESTING" == "true" ]]; then
        log_info "=== ARCHITECTURE-SPECIFIC FUZZING ==="
        discover_fuzz_tests "architecture"
        if ! execute_fuzz_tests "architecture"; then
            overall_exit_code=1
        fi
    fi
    
    # Execute component tests
    log_info "=== COMPONENT FUZZING ==="
    discover_fuzz_tests "component"
    if ! execute_fuzz_tests "component"; then
        overall_exit_code=1
    fi
    
    # Generate comprehensive report
    generate_report
    
    # Final summary
    log_info "Fuzzing session completed"
    log_info "Report: $REPORT_FILE"
    log_info "Logs: $SESSION_DIR"
    
    if (( overall_exit_code == 0 )); then
        log_info "✅ All fuzz tests completed successfully"
    else
        log_error "❌ Some fuzz tests failed - review logs and report"
    fi
    
    return $overall_exit_code
}

# Handle command line arguments
case "${1:-}" in
    -h|--help|help)
        show_usage
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac