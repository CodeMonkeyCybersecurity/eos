#!/bin/bash
# Common preflight checks for all EOS fuzz testing scripts
# Source this file from other scripts: source "$(dirname "${BASH_SOURCE[0]}")/fuzz-preflight-common.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Preflight check function
eos_fuzz_preflight_check() {
    local script_name="$(basename "${BASH_SOURCE[1]}")"
    
    echo -e "${CYAN}🔍 Running preflight checks...${NC}"
    
    # Check if we're in the project root or can find it
    local current_dir="$(pwd)"
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
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
        echo -e "     ${GREEN}./scripts/${script_name}${NC} [arguments]"
        echo ""
        echo -e "${YELLOW}💡 The project root should contain:${NC}"
        echo -e "   - go.mod file"
        echo -e "   - pkg/ directory with fuzz tests"
        echo -e "   - cmd/ directory"
        echo -e "   - scripts/ directory"
        echo ""
        echo -e "${CYAN}Alternatively, you can run from anywhere:${NC}"
        echo -e "   ${GREEN}/opt/eos/scripts/${script_name}${NC} [arguments]"
        echo ""
        exit 1
    fi
}

# Verify required tools are available
eos_fuzz_verify_tools() {
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
    
    # Check for bc (used for calculations in some scripts)
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
            echo -e "     ${YELLOW}Or install latest Go from https://golang.org/dl/${NC}"
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
eos_fuzz_verify_test_files() {
    echo -e "${CYAN}📦 Verifying test files exist...${NC}"
    
    local missing_packages=()
    
    # Check key test directories
    if [ ! -d "pkg/security" ]; then
        missing_packages+=("pkg/security")
    fi
    if [ ! -d "pkg/crypto" ]; then
        missing_packages+=("pkg/crypto")
    fi
    
    if [ ${#missing_packages[@]} -gt 0 ]; then
        echo -e "${RED}❌ ERROR: Required test directories are missing${NC}"
        echo -e "${RED}Missing: ${missing_packages[*]}${NC}"
        echo ""
        echo -e "${YELLOW}This usually means:${NC}"
        echo -e "  1. You're not in the EOS project root"
        echo -e "  2. The repository is incomplete"
        echo ""
        echo -e "${CYAN}Try:${NC}"
        echo -e "  ${GREEN}git pull origin main${NC}  # Update the repository"
        echo ""
        exit 1
    fi
    
    # Check for at least one fuzz test file
    if ! find pkg -name "*fuzz*.go" -type f 2>/dev/null | grep -q .; then
        echo -e "${RED}❌ ERROR: No fuzz test files found${NC}"
        echo ""
        echo -e "${YELLOW}📋 This could mean:${NC}"
        echo -e "  1. You're not in the EOS project root"
        echo -e "  2. The repository is incomplete"
        echo -e "  3. Fuzz tests haven't been written yet"
        echo ""
        echo -e "${CYAN}Try:${NC}"
        echo -e "  ${GREEN}cd /opt/eos${NC}  # Navigate to project root"
        echo -e "  ${GREEN}git pull origin main${NC}  # Update the repository"
        echo ""
        exit 1
    fi
    
    echo -e "${GREEN}✅ Test files verified${NC}"
}

# Run all preflight checks
eos_run_preflight_checks() {
    local script_name="$(basename "${BASH_SOURCE[1]}")"
    
    echo -e "${PURPLE}🚀 EOS Fuzz Testing - Preflight Check${NC}"
    echo -e "${PURPLE}Script: ${script_name}${NC}"
    echo "========================================"
    echo ""
    
    eos_fuzz_preflight_check
    eos_fuzz_verify_tools
    eos_fuzz_verify_test_files
    
    echo ""
    echo -e "${GREEN}✅ All preflight checks passed!${NC}"
    echo -e "${GREEN}📂 Working directory: $(pwd)${NC}"
    echo ""
}

# Export functions so they can be used by sourcing scripts
export -f eos_fuzz_preflight_check
export -f eos_fuzz_verify_tools
export -f eos_fuzz_verify_test_files
export -f eos_run_preflight_checks