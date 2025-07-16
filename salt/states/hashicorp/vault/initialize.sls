# Vault Initialization
# Replicates functionality from phase6a_init.go
# Handles secure initialization with 5 unseal keys and 3-key threshold

{% set vault = pillar.get('vault', {}) %}
{% set vault_user = vault.get('user', 'vault') %}
{% set vault_group = vault.get('group', 'vault') %}
{% set port = vault.get('port', '8179') %}
{% set hostname = grains.get('fqdn', grains.get('id', 'localhost')) %}
{% set init_file = '/var/lib/eos/secret/vault_init.json' %}

# Ensure prerequisites
include:
  - hashicorp.vault.service_eos

# Check if Vault is already initialized
vault_init_check:
  cmd.run:
    - name: |
        export VAULT_ADDR="https://{{ hostname }}:{{ port }}"
        export VAULT_CACERT="/etc/vault.d/ca.crt"
        
        echo "Checking if Vault is already initialized..."
        
        # Check if init file already exists
        if [ -f "{{ init_file }}" ]; then
          echo "Vault initialization file already exists at {{ init_file }}"
          echo "Vault appears to be already initialized"
          exit 0
        fi
        
        # Check Vault status
        STATUS_OUTPUT=$(vault status -format=json 2>/dev/null)
        if [ $? -eq 0 ]; then
          INITIALIZED=$(echo "$STATUS_OUTPUT" | jq -r '.initialized // false')
          if [ "$INITIALIZED" = "true" ]; then
            echo "Vault is already initialized according to API"
            exit 0
          fi
        fi
        
        echo "Vault is not initialized - proceeding with initialization"
        exit 1  # This will trigger the initialization
    - require:
      - cmd: vault_health_check_tcp
      - pkg: eos_dependencies
    # This check should always run but only fail if we can't determine status

# Initialize Vault (only if not already initialized)
vault_initialize:
  cmd.run:
    - name: |
        export VAULT_ADDR="https://{{ hostname }}:{{ port }}"
        export VAULT_CACERT="/etc/vault.d/ca.crt"
        
        echo "Initializing Vault with 5 unseal keys and 3-key threshold..."
        
        # Initialize with JSON output for easier parsing
        INIT_OUTPUT=$(vault operator init -key-shares=5 -key-threshold=3 -format=json 2>/dev/null)
        INIT_EXIT_CODE=$?
        
        if [ $INIT_EXIT_CODE -ne 0 ]; then
          echo "ERROR: Failed to initialize Vault"
          echo "This may indicate Vault is already initialized or there's a connectivity issue"
          vault status || true
          exit 1
        fi
        
        echo "Vault initialization completed successfully"
        echo "Saving initialization data securely..."
        
        # Ensure secrets directory exists with proper permissions
        mkdir -p /var/lib/eos/secret
        chown {{ vault_user }}:{{ vault_group }} /var/lib/eos/secret
        chmod 700 /var/lib/eos/secret
        
        # Save initialization output with restrictive permissions
        echo "$INIT_OUTPUT" > {{ init_file }}
        chown {{ vault_user }}:{{ vault_group }} {{ init_file }}
        chmod 600 {{ init_file }}
        
        # Extract root token for verification (without logging sensitive data)
        ROOT_TOKEN=$(echo "$INIT_OUTPUT" | jq -r '.root_token')
        if [ -n "$ROOT_TOKEN" ] && [ "$ROOT_TOKEN" != "null" ]; then
          echo "Root token successfully extracted (length: ${#ROOT_TOKEN})"
        else
          echo "ERROR: Failed to extract root token from initialization output"
          exit 1
        fi
        
        # Log success without sensitive data
        echo "Vault initialization data saved to {{ init_file }}"
        echo "File permissions set to 600 for security"
        echo "CRITICAL: Save the unseal keys and root token securely!"
        
    - onfail:
      - cmd: vault_init_check
    - require:
      - service: vault_service_start

# Create initialization status tracking
vault_init_status_update:
  file.managed:
    - name: /var/lib/eos/vault-init-status.json
    - contents: |
        {
          "initialized": true,
          "initialized_at": "{{ salt['cmd.run']('date -Iseconds') }}",
          "init_file": "{{ init_file }}",
          "managed_by": "salt",
          "unseal_keys": 5,
          "key_threshold": 3,
          "warning": "Initialization data contains sensitive information - handle securely"
        }
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 640
    - require:
      - cmd: vault_initialize

# Create unseal script for manual operations
vault_unseal_script:
  file.managed:
    - name: /usr/local/bin/eos-vault-unseal
    - contents: |
        #!/bin/bash
        # Eos Vault unseal script
        
        export VAULT_ADDR="https://{{ hostname }}:{{ port }}"
        export VAULT_CACERT="/etc/vault.d/ca.crt"
        
        INIT_FILE="{{ init_file }}"
        
        if [ ! -f "$INIT_FILE" ]; then
          echo "ERROR: Vault initialization file not found at $INIT_FILE"
          echo "Vault may not be properly initialized"
          exit 1
        fi
        
        echo "Reading unseal keys from $INIT_FILE..."
        
        # Extract unseal keys (need 3 out of 5)
        UNSEAL_KEYS=$(jq -r '.unseal_keys_b64[]' "$INIT_FILE" | head -3)
        
        if [ -z "$UNSEAL_KEYS" ]; then
          echo "ERROR: Could not read unseal keys from initialization file"
          exit 1
        fi
        
        echo "Unsealing Vault with 3 keys..."
        echo "$UNSEAL_KEYS" | while read -r KEY; do
          if [ -n "$KEY" ]; then
            vault operator unseal "$KEY"
          fi
        done
        
        # Check final status
        echo "Checking Vault status after unsealing:"
        vault status
        
    - mode: 750  # Executable by owner and group only
    - user: root
    - group: {{ vault_group }}
    - require:
      - file: vault_init_status_update

# Display initialization summary (without sensitive data)
vault_init_summary:
  cmd.run:
    - name: |
        echo ""
        echo "╔═══════════════════════════════════════════════════════════════════════╗"
        echo "║                    VAULT INITIALIZATION COMPLETED                    ║"
        echo "╚═══════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "🔐 Vault has been successfully initialized"
        echo "🔑 Initialization data saved to: {{ init_file }}"
        echo "🛡️  File permissions: 600 (vault:vault)"
        echo "🔓 To unseal Vault: /usr/local/bin/eos-vault-unseal"
        echo "📊 Vault status: eos-vault status"
        echo ""
        echo "⚠️  IMPORTANT SECURITY NOTICE:"
        echo "   • The initialization file contains sensitive unseal keys and root token"
        echo "   • Back up this file securely and consider splitting keys among administrators"
        echo "   • Never commit this file to version control"
        echo "   • Consider setting up auto-unseal for production environments"
        echo ""
    - require:
      - file: vault_unseal_script