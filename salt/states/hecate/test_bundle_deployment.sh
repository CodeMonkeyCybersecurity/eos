#!/bin/bash
# Test script for Hecate bundle deployment with and without Vault
# Tests the random string generator functionality

set -e

echo "=== Hecate Bundle Deployment Test ==="
echo

# Function to test module availability
test_module() {
    echo "Testing eos_random module availability..."
    if salt-call eos_random.get_str 16 --local > /dev/null 2>&1; then
        echo "✓ Module is available"
        return 0
    else
        echo "✗ Module not available"
        return 1
    fi
}

# Function to test all random functions
test_functions() {
    echo
    echo "Testing random string functions..."
    
    echo -n "1. get_str: "
    salt-call eos_random.get_str 32 --local --out=json | jq -r '.local' || echo "FAILED"
    
    echo -n "2. hex_str: "
    salt-call eos_random.hex_str 16 --local --out=json | jq -r '.local' || echo "FAILED"
    
    echo -n "3. password: "
    salt-call eos_random.password 20 include_special=True --local --out=json | jq -r '.local' || echo "FAILED"
    
    echo -n "4. api_key: "
    salt-call eos_random.api_key prefix='test_' --local --out=json | jq -r '.local' || echo "FAILED"
    
    echo -n "5. uuid: "
    salt-call eos_random.uuid --local --out=json | jq -r '.local' || echo "FAILED"
    
    echo -n "6. get_or_create: "
    salt-call eos_random.get_or_create 'test_persistent_key' 24 --local --out=json | jq -r '.local' || echo "FAILED"
}

# Function to test persistence
test_persistence() {
    echo
    echo "Testing secret persistence..."
    
    # Generate a persistent secret
    SECRET1=$(salt-call eos_random.get_or_create 'persistence_test' 32 --local --out=json | jq -r '.local')
    echo "First call: $SECRET1"
    
    # Call again - should get same value
    SECRET2=$(salt-call eos_random.get_or_create 'persistence_test' 32 --local --out=json | jq -r '.local')
    echo "Second call: $SECRET2"
    
    if [ "$SECRET1" = "$SECRET2" ]; then
        echo "✓ Persistence working correctly"
    else
        echo "✗ Persistence failed - values don't match"
        return 1
    fi
    
    # Check file permissions
    if [ -f "/etc/eos/salt_secrets.json" ]; then
        PERMS=$(stat -c %a /etc/eos/salt_secrets.json)
        if [ "$PERMS" = "600" ]; then
            echo "✓ Secrets file has correct permissions (600)"
        else
            echo "✗ Secrets file has incorrect permissions: $PERMS"
        fi
    fi
}

# Function to test bundle deployment
test_bundle_deployment() {
    echo
    echo "Testing bundle deployment..."
    
    # First sync modules manually to ensure eos_random is available
    echo "Syncing Salt modules..."
    salt-call saltutil.sync_modules --local
    
    # Test with Vault disabled
    echo
    echo "=== Testing WITHOUT Vault integration ==="
    salt-call state.apply hecate_bundle pillar='{"hecate": {"vault_integration": false}}' --local test=True
    
    # Test with Vault enabled (dry run)
    echo
    echo "=== Testing WITH Vault integration ==="
    salt-call state.apply hecate_bundle pillar='{"hecate": {"vault_integration": true}}' --local test=True
}

# Main test execution
main() {
    # Ensure we're running as root
    if [ "$EUID" -ne 0 ]; then 
        echo "This script must be run as root"
        exit 1
    fi
    
    # Create required directories
    mkdir -p /etc/eos
    mkdir -p /srv/salt/_modules
    
    # Copy the module to the correct location if it exists
    if [ -f "/opt/eos/salt/_modules/eos_random.py" ]; then
        echo "Copying eos_random module to Salt modules directory..."
        cp /opt/eos/salt/_modules/eos_random.py /srv/salt/_modules/
        echo "Syncing Salt modules..."
        salt-call saltutil.sync_modules --local || echo "Note: Module sync may require sudo permissions"
    else
        echo "Warning: eos_random.py not found in /opt/eos/salt/_modules/"
    fi
    
    # Run tests
    if test_module; then
        test_functions
        test_persistence
    else
        echo "Module not available, attempting to deploy..."
        test_bundle_deployment
    fi
    
    echo
    echo "=== Test Complete ==="
}

# Run main function
main "$@"