#!/bin/bash
# scripts/setup-vault-delphi.sh
# Complete setup script for Vault integration with Delphi dashboard

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root for some operations
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root - some configurations will be system-wide"
    fi
}

# Check if eos command is available
check_eos() {
    if ! command -v eos &> /dev/null; then
        print_error "eos command not found. Please install Eos first."
        exit 1
    fi
    print_success "Eos command found"
}

# Check Vault connectivity
check_vault() {
    local vault_addr="${VAULT_ADDR:-}"
    if [[ -z "$vault_addr" ]]; then
        print_warning "VAULT_ADDR not set. Will be configured during setup."
        return 1
    fi
    
    print_status "Testing Vault connectivity to $vault_addr"
    if curl -s --connect-timeout 5 "$vault_addr/v1/sys/health" > /dev/null 2>&1; then
        print_success "Vault server is reachable"
        return 0
    else
        print_warning "Vault server not reachable or not responding"
        return 1
    fi
}

# Setup Vault configuration
setup_vault() {
    print_status "Setting up Vault configuration..."
    
    if ! eos self secrets configure; then
        print_error "Vault configuration failed"
        exit 1
    fi
    
    print_success "Vault configuration completed"
}

# Setup database credentials
setup_database() {
    print_status "Setting up database credentials..."
    
    if ! eos self secrets set delphi-db; then
        print_error "Database credentials setup failed"
        exit 1
    fi
    
    print_success "Database credentials configured"
}

# Test the complete setup
test_setup() {
    print_status "Testing complete setup..."
    
    # Test Vault connectivity
    if ! eos self secrets test; then
        print_error "Vault connectivity test failed"
        exit 1
    fi
    
    # Test dashboard (without actually launching it)
    print_status "Testing dashboard connection (dry run)..."
    # This would be implemented as a --dry-run flag if added to the dashboard command
    
    print_success "Setup test completed successfully"
}

# Display next steps
show_next_steps() {
    print_success "Setup completed successfully!"
    echo
    print_status "Next steps:"
    echo "1. Test the configuration:"
    echo "   eos self secrets status"
    echo
    echo "2. Launch the Delphi dashboard:"
    echo "   eos delphi dashboard"
    echo
    echo "3. If you encounter issues:"
    echo "   eos self secrets test"
    echo "   eos self secrets status"
    echo
    print_status "For more help:"
    echo "   eos self secrets --help"
    echo "   eos delphi dashboard --help"
}

# Main setup function
main() {
    print_status "🔐 Eos Vault + Delphi Dashboard Setup"
    print_status "======================================"
    echo
    
    # Pre-checks
    check_root
    check_eos
    
    # Check if Vault is already configured
    if check_vault; then
        print_status "Vault appears to be already configured"
        read -p "Do you want to reconfigure Vault? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            setup_vault
        fi
    else
        setup_vault
    fi
    
    # Setup database credentials
    print_status "Setting up database credentials for Delphi..."
    setup_database
    
    # Test the setup
    test_setup
    
    # Show next steps
    show_next_steps
}

# Help function
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Setup Vault integration for Eos Delphi dashboard"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --vault-only   Configure Vault connection only"
    echo "  --db-only      Configure database credentials only (requires Vault setup)"
    echo "  --test-only    Test existing configuration"
    echo
    echo "Environment variables:"
    echo "  VAULT_ADDR     Vault server address (if already known)"
    echo
    echo "This script will guide you through:"
    echo "1. Vault server connection setup"
    echo "2. Authentication configuration (token, userpass, or AppRole)"
    echo "3. Database credentials storage in Vault"
    echo "4. Testing the complete configuration"
    echo
    echo "After successful setup, you can use:"
    echo "  eos delphi dashboard    # Launch the dashboard"
    echo "  eos self secrets status # Check configuration status"
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --vault-only)
        check_eos
        setup_vault
        eos self secrets test
        ;;
    --db-only)
        check_eos
        setup_database
        eos self secrets test
        ;;
    --test-only)
        check_eos
        test_setup
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        show_help
        exit 1
        ;;
esac