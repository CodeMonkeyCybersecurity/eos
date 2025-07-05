#!/bin/bash
# scripts/check-coverage.sh
# Quick coverage check script for developers

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Coverage thresholds
OVERALL_THRESHOLD=70
CRITICAL_THRESHOLD=90

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    if ! command_exists go; then
        print_color $RED "Error: Go is not installed"
        exit 1
    fi
    
    if ! command_exists bc; then
        print_color $YELLOW "Warning: bc not found, using awk for calculations"
    fi
}

# Run coverage for a specific package
check_package_coverage() {
    local pkg=$1
    local threshold=$2
    local pkg_path="./pkg/${pkg}/..."
    
    if [ ! -d "./pkg/${pkg}" ]; then
        print_color $YELLOW "  ⚠️  ${pkg}: Package not found"
        return 1
    fi
    
    # Run tests with coverage
    if go test -coverprofile="${pkg}.coverage.out" "${pkg_path}" >/dev/null 2>&1; then
        local coverage=$(go tool cover -func="${pkg}.coverage.out" | grep total | awk '{print $3}' | sed 's/%//')
        
        # Check threshold
        local passed=false
        if command_exists bc; then
            [ $(echo "$coverage >= $threshold" | bc -l) -eq 1 ] && passed=true
        else
            awk "BEGIN {exit !($coverage >= $threshold)}" && passed=true
        fi
        
        if $passed; then
            print_color $GREEN "   ${pkg}: ${coverage}% (threshold: ${threshold}%)"
        else
            print_color $RED "  ❌ ${pkg}: ${coverage}% (threshold: ${threshold}%)"
            return 1
        fi
        
        # Cleanup
        rm -f "${pkg}.coverage.out"
    else
        print_color $RED "  ❌ ${pkg}: Test failed"
        return 1
    fi
    
    return 0
}

# Main execution
main() {
    print_color $BLUE "🧪 Eos Coverage Check"
    print_color $BLUE "===================="
    
    check_prerequisites
    
    # Change to repository root
    cd "$(git rev-parse --show-toplevel)" || exit 1
    
    print_color $BLUE "\n Running overall coverage check..."
    
    # Run overall coverage
    if go test -coverprofile=coverage.out -covermode=atomic ./pkg/... >/dev/null 2>&1; then
        OVERALL_COV=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
        
        # Check overall threshold
        local overall_passed=false
        if command_exists bc; then
            [ $(echo "$OVERALL_COV >= $OVERALL_THRESHOLD" | bc -l) -eq 1 ] && overall_passed=true
        else
            awk "BEGIN {exit !($OVERALL_COV >= $OVERALL_THRESHOLD)}" && overall_passed=true
        fi
        
        if $overall_passed; then
            print_color $GREEN "\n Overall coverage: ${OVERALL_COV}% (threshold: ${OVERALL_THRESHOLD}%)"
        else
            print_color $RED "\n❌ Overall coverage: ${OVERALL_COV}% (threshold: ${OVERALL_THRESHOLD}%)"
        fi
    else
        print_color $RED "\n❌ Overall coverage test failed"
        exit 1
    fi
    
    print_color $BLUE "\n🔒 Checking critical packages (${CRITICAL_THRESHOLD}% required)..."
    
    # Check critical packages
    CRITICAL_PACKAGES=("vault" "crypto" "eos_io" "eos_err")
    CRITICAL_FAILED=0
    
    for pkg in "${CRITICAL_PACKAGES[@]}"; do
        if ! check_package_coverage "$pkg" "$CRITICAL_THRESHOLD"; then
            CRITICAL_FAILED=$((CRITICAL_FAILED + 1))
        fi
    done
    
    # Summary
    print_color $BLUE "\n📈 Coverage Summary"
    print_color $BLUE "=================="
    echo "Overall Coverage: ${OVERALL_COV}%"
    echo "Critical Packages Failed: ${CRITICAL_FAILED}/${#CRITICAL_PACKAGES[@]}"
    
    # Generate HTML report if requested
    if [[ "${1:-}" == "--html" ]]; then
        print_color $BLUE "\n📄 Generating HTML report..."
        go tool cover -html=coverage.out -o coverage.html
        print_color $GREEN " Report saved to coverage.html"
        
        # Try to open in browser
        if command_exists open; then
            open coverage.html
        elif command_exists xdg-open; then
            xdg-open coverage.html
        fi
    fi
    
    # Show low coverage packages if requested
    if [[ "${1:-}" == "--low" ]]; then
        print_color $YELLOW "\n⚠️  Packages with coverage below ${OVERALL_THRESHOLD}%:"
        go tool cover -func=coverage.out | \
            awk -v threshold=$OVERALL_THRESHOLD \
            '$3 ~ /%/ { 
                gsub(/%/, "", $3); 
                if ($3 < threshold && $1 != "total:") 
                    printf "  %-50s %s%%\n", $1, $3 
            }' | sort -k2 -n
    fi
    
    # Cleanup
    rm -f coverage.out
    
    # Exit with appropriate code
    if ! $overall_passed || [ $CRITICAL_FAILED -gt 0 ]; then
        print_color $RED "\n❌ Coverage check failed!"
        print_color $YELLOW " Tip: Run '$0 --html' to see detailed coverage report"
        exit 1
    else
        print_color $GREEN "\n All coverage checks passed!"
        exit 0
    fi
}

# Show help if requested
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --html    Generate and open HTML coverage report"
    echo "  --low     Show packages with low coverage"
    echo "  --help    Show this help message"
    echo ""
    echo "Thresholds:"
    echo "  Overall coverage: ${OVERALL_THRESHOLD}%"
    echo "  Critical packages: ${CRITICAL_THRESHOLD}%"
    exit 0
fi

# Run main function
main "$@"