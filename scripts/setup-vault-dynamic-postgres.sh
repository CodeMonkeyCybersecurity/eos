#!/bin/bash
# scripts/setup-vault-dynamic-postgres.sh
# Setup script for Vault dynamic PostgreSQL credentials

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

print_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# Configuration variables
VAULT_ADDR="${VAULT_ADDR:-}"
GUEST_DB_HOST="${GUEST_DB_HOST:-localhost}"
GUEST_DB_PORT="${GUEST_DB_PORT:-5432}"
GUEST_DB_NAME="${GUEST_DB_NAME:-delphi}"
GUEST_DB_ADMIN="${GUEST_DB_ADMIN:-postgres}"

# Function to check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check if eos command exists
    if ! command -v eos &> /dev/null; then
        print_error "eos command not found. Please install Eos first."
        exit 1
    fi
    print_success "Eos command found"
    
    # Check if vault command exists
    if ! command -v vault &> /dev/null; then
        print_error "vault command not found. Please install Vault CLI."
        exit 1
    fi
    print_success "Vault CLI found"
}

# Function to configure Vault connection
configure_vault_connection() {
    print_step "Configuring Vault connection..."
    
    if [[ -z "$VAULT_ADDR" ]]; then
        print_status "VAULT_ADDR not set. Please run 'eos self secrets configure' first."
        read -p "Would you like to configure it now? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            eos self secrets configure
        else
            print_error "Vault configuration required. Exiting."
            exit 1
        fi
    else
        print_success "VAULT_ADDR configured: $VAULT_ADDR"
    fi
}

# Function to set database configuration
set_database_config() {
    print_step "Setting database connection configuration..."
    
    echo "This will configure the connection parameters for your PostgreSQL database."
    echo "This should point to your guest VM where PostgreSQL is running."
    echo
    
    read -p "Database host [$GUEST_DB_HOST]: " input_host
    GUEST_DB_HOST="${input_host:-$GUEST_DB_HOST}"
    
    read -p "Database port [$GUEST_DB_PORT]: " input_port
    GUEST_DB_PORT="${input_port:-$GUEST_DB_PORT}"
    
    read -p "Database name [$GUEST_DB_NAME]: " input_name
    GUEST_DB_NAME="${input_name:-$GUEST_DB_NAME}"
    
    print_status "Database configuration:"
    echo "  Host: $GUEST_DB_HOST"
    echo "  Port: $GUEST_DB_PORT"
    echo "  Database: $GUEST_DB_NAME"
    echo
    
    # Use eos to set the configuration
    export GUEST_DB_HOST GUEST_DB_PORT GUEST_DB_NAME
    eos self secrets set delphi-db-config
}

# Function to setup database secrets engine
setup_database_engine() {
    print_step "Setting up Vault database secrets engine..."
    
    read -p "Database admin username [$GUEST_DB_ADMIN]: " input_admin
    GUEST_DB_ADMIN="${input_admin:-$GUEST_DB_ADMIN}"
    
    read -s -p "Database admin password: " admin_password
    echo
    
    if [[ -z "$admin_password" ]]; then
        print_error "Admin password is required"
        exit 1
    fi
    
    print_status "Configuring Vault database secrets engine..."
    
    # Enable database secrets engine
    print_status "Enabling database secrets engine..."
    if vault secrets list | grep -q "^database/"; then
        print_warning "Database secrets engine already enabled"
    else
        vault secrets enable database
        print_success "Database secrets engine enabled"
    fi
    
    # Configure PostgreSQL connection
    print_status "Configuring PostgreSQL connection..."
    vault write database/config/delphi-postgresql \
        plugin_name=postgresql-database-plugin \
        connection_url="postgresql://{{username}}:{{password}}@${GUEST_DB_HOST}:${GUEST_DB_PORT}/${GUEST_DB_NAME}?sslmode=disable" \
        allowed_roles="delphi-readonly" \
        username="$GUEST_DB_ADMIN" \
        password="$admin_password"
    
    print_success "PostgreSQL connection configured"
    
    # Create read-only role
    print_status "Creating read-only role for Delphi..."
    vault write database/roles/delphi-readonly \
        db_name=delphi-postgresql \
        creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
                              GRANT CONNECT ON DATABASE ${GUEST_DB_NAME} TO \"{{name}}\"; \
                              GRANT USAGE ON SCHEMA public TO \"{{name}}\"; \
                              GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
                              ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{name}}\";" \
        default_ttl="1h" \
        max_ttl="24h"
    
    print_success "Read-only role configured"
}

# Function to test dynamic credentials
test_dynamic_credentials() {
    print_step "Testing dynamic credential generation..."
    
    # Test credential generation
    if vault read database/creds/delphi-readonly > /dev/null 2>&1; then
        print_success "Dynamic credentials generated successfully"
        
        # Show credential info (without actual values)
        print_status "Credential information:"
        vault read -format=json database/creds/delphi-readonly | jq -r '.data | "Username: " + .username + "\nLease Duration: " + (.lease_duration | tostring) + " seconds"'
    else
        print_error "Failed to generate dynamic credentials"
        print_status "Possible issues:"
        echo "  - PostgreSQL not accessible from Vault server"
        echo "  - Admin credentials incorrect"
        echo "  - Network connectivity issues"
        exit 1
    fi
}

# Function to test Eos integration
test_eos_integration() {
    print_step "Testing Eos integration..."
    
    # Test Eos secrets functionality
    if eos self secrets test > /dev/null 2>&1; then
        print_success "Eos Vault integration working"
    else
        print_warning "Eos Vault integration test failed - check configuration"
    fi
    
    # Show status
    print_status "Current secret status:"
    eos self secrets status
}

# Function to show completion summary
show_completion_summary() {
    print_success "🎉 Vault Dynamic PostgreSQL Credentials Setup Complete!"
    echo
    print_status "What was configured:"
    echo "   Vault database secrets engine enabled"
    echo "   PostgreSQL connection configured for guest VM"
    echo "   Read-only role 'delphi-readonly' created"
    echo "   Dynamic credential generation tested"
    echo
    print_status "Next steps:"
    echo "  1. Launch the Delphi dashboard:"
    echo "     eos delphi dashboard"
    echo
    echo "  2. Monitor dynamic credentials:"
    echo "     vault read database/creds/delphi-readonly"
    echo
    echo "  3. Check lease information:"
    echo "     vault list sys/leases/lookup/database/creds/delphi-readonly"
    echo
    echo "  4. Monitor PostgreSQL for temporary users:"
    echo "     psql -h $GUEST_DB_HOST -U $GUEST_DB_ADMIN -d $GUEST_DB_NAME -c \"\\du\""
    echo
    print_status "Credential Details:"
    echo "  • TTL: 1 hour (auto-renewed by Eos)"
    echo "  • Max TTL: 24 hours"
    echo "  • Permissions: Read-only on all tables"
    echo "  • Automatic cleanup: Yes"
    echo
    print_status "Troubleshooting:"
    echo "  • Check status: eos self secrets status"
    echo "  • Test connection: eos self secrets test"
    echo "  • View logs: tail -f /var/log/eos/eos.log"
}

# Function to show help
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Setup Vault dynamic PostgreSQL credentials for Eos Delphi dashboard"
    echo
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  --host HOST          Database host (default: localhost)"
    echo "  --port PORT          Database port (default: 5432)"
    echo "  --database DB        Database name (default: delphi)"
    echo "  --admin-user USER    Admin username (default: postgres)"
    echo "  --vault-addr ADDR    Vault server address"
    echo
    echo "Environment variables:"
    echo "  VAULT_ADDR           Vault server address"
    echo "  GUEST_DB_HOST        Database host"
    echo "  GUEST_DB_PORT        Database port"
    echo "  GUEST_DB_NAME        Database name"
    echo "  GUEST_DB_ADMIN       Admin username"
    echo
    echo "Examples:"
    echo "  # Interactive setup"
    echo "  $0"
    echo
    echo "  # Setup with specific guest VM"
    echo "  $0 --host 100.88.69.11 --admin-user postgres"
    echo
    echo "  # Setup with environment variables"
    echo "  GUEST_DB_HOST=192.168.1.100 $0"
}

# Main function
main() {
    print_status "🔐 Vault Dynamic PostgreSQL Credentials Setup"
    print_status "=============================================="
    echo
    
    check_prerequisites
    configure_vault_connection
    set_database_config
    setup_database_engine
    test_dynamic_credentials
    test_eos_integration
    show_completion_summary
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        --host)
            GUEST_DB_HOST="$2"
            shift 2
            ;;
        --port)
            GUEST_DB_PORT="$2"
            shift 2
            ;;
        --database)
            GUEST_DB_NAME="$2"
            shift 2
            ;;
        --admin-user)
            GUEST_DB_ADMIN="$2"
            shift 2
            ;;
        --vault-addr)
            VAULT_ADDR="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Run main function
main