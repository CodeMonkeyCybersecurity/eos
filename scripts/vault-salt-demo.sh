#!/bin/bash
# Vault Salt-based deployment demonstration script
# This script shows how to use Salt states for complete Vault lifecycle management

set -e

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                  VAULT SALT-BASED DEPLOYMENT DEMO                            ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Check if Salt is installed
if ! command -v salt-call &> /dev/null; then
    echo "❌ Salt is not installed. Please install Salt first with:"
    echo "   eos create saltstack"
    exit 1
fi

echo "✅ Salt is installed and available"
echo

# Function to run Salt state and show output
run_salt_state() {
    local state=$1
    local pillar=$2
    
    echo "🧂 Running Salt state: $state"
    if [ -n "$pillar" ]; then
        echo "   With pillar: $pillar"
        salt-call --local state.apply "$state" pillar="$pillar" --output=mixed
    else
        salt-call --local state.apply "$state" --output=mixed
    fi
}

# Menu for different deployment options
echo "Select Vault deployment option:"
echo "1. Complete Lifecycle (Create + Enable + Harden) - Recommended"
echo "2. Create only (Install and Initialize)"
echo "3. Enable only (Configure auth, policies, etc.)"
echo "4. Harden only (Apply security hardening)"
echo "5. Check current Vault status"
echo "6. Unseal Vault"
echo

read -p "Enter your choice (1-6): " choice

case $choice in
    1)
        echo
        echo "🚀 Starting complete Vault lifecycle deployment..."
        echo "This will:"
        echo "  • Install and configure Vault"
        echo "  • Generate TLS certificates"
        echo "  • Initialize with 5 keys (3 threshold)"
        echo "  • Enable auth methods (userpass, approle)"
        echo "  • Configure policies and audit logging"
        echo "  • Apply comprehensive security hardening"
        echo
        read -p "Continue? (y/n): " confirm
        if [[ $confirm == "y" ]]; then
            run_salt_state "hashicorp.vault.complete_lifecycle" '{"vault":{"enable_userpass":true,"enable_approle":true,"enable_mfa":true,"enable_agent":true}}'
        fi
        ;;
        
    2)
        echo
        echo "📦 Starting Vault creation (install and initialize)..."
        read -p "Continue? (y/n): " confirm
        if [[ $confirm == "y" ]]; then
            run_salt_state "hashicorp.vault.eos_complete"
        fi
        ;;
        
    3)
        echo
        echo "🔓 Starting Vault enablement..."
        echo "Note: Vault must be already created and initialized"
        echo
        
        # Check if init file exists
        if [ ! -f "/var/lib/eos/secret/vault_init.json" ]; then
            echo "❌ Vault initialization file not found. Please create Vault first."
            exit 1
        fi
        
        # Get root token
        ROOT_TOKEN=$(jq -r .root_token /var/lib/eos/secret/vault_init.json 2>/dev/null)
        if [ -z "$ROOT_TOKEN" ]; then
            echo "❌ Could not read root token from init file"
            exit 1
        fi
        
        read -p "Continue with enablement? (y/n): " confirm
        if [[ $confirm == "y" ]]; then
            run_salt_state "hashicorp.vault.enable" "{\"vault\":{\"root_token\":\"$ROOT_TOKEN\",\"enable_userpass\":true,\"enable_approle\":true,\"enable_mfa\":true,\"enable_agent\":true}}"
        fi
        ;;
        
    4)
        echo
        echo "🛡️ Starting Vault hardening..."
        echo "Note: This will apply comprehensive security hardening"
        echo
        
        # Get root token if available
        ROOT_TOKEN=$(jq -r .root_token /var/lib/eos/secret/vault_init.json 2>/dev/null || echo "")
        
        read -p "Continue with hardening? (y/n): " confirm
        if [[ $confirm == "y" ]]; then
            run_salt_state "hashicorp.vault.harden" "{\"vault\":{\"root_token\":\"$ROOT_TOKEN\",\"allowed_subnets\":[\"10.0.0.0/8\",\"172.16.0.0/12\",\"192.168.0.0/16\"]}}"
        fi
        ;;
        
    5)
        echo
        echo "📊 Checking Vault status..."
        echo
        
        # Service status
        echo "=== Service Status ==="
        systemctl status vault --no-pager | head -10 || echo "Vault service not found"
        echo
        
        # API status
        echo "=== API Status ==="
        export VAULT_ADDR="https://127.0.0.1:8179"
        export VAULT_SKIP_VERIFY="true"
        vault status 2>/dev/null || echo "Vault API not responding"
        echo
        
        # Check if initialized
        if [ -f "/var/lib/eos/secret/vault_init.json" ]; then
            echo "✅ Vault initialization file found"
        else
            echo "❌ Vault not initialized (no init file)"
        fi
        
        # Check Salt states available
        echo
        echo "=== Available Salt States ==="
        ls -la /opt/eos/salt/states/hashicorp/vault/*.sls 2>/dev/null | awk '{print $NF}' | xargs -n1 basename | sed 's/.sls$//' | sort
        ;;
        
    6)
        echo
        echo "🔓 Unsealing Vault..."
        run_salt_state "hashicorp.vault.unseal"
        ;;
        
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "For more information, see the documentation at:"
echo "  • /var/lib/eos/vault-lifecycle-complete.md"
echo "  • /opt/eos/salt/states/hashicorp/vault/README.md"
echo