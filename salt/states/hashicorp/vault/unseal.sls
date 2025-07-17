# Vault Unseal State
# Handles unsealing of Vault using stored keys or manual input
# Replicates functionality from phase6b_unseal.go
#
# Usage: salt-call --local state.apply hashicorp.vault.unseal

{% set vault = pillar.get('vault', {}) %}
{% set port = vault.get('port', '8179') %}
{% set hostname = grains.get('fqdn', grains.get('id', 'localhost')) %}
{% set init_file = '/var/lib/eos/secret/vault_init.json' %}

# Check current seal status
vault_check_seal_status:
  cmd.run:
    - name: |
        export VAULT_ADDR="https://{{ hostname }}:{{ port }}"
        export VAULT_CACERT="/etc/vault.d/ca.crt"
        
        echo "Checking Vault seal status..."
        
        STATUS_JSON=$(vault status -format=json 2>/dev/null || echo '{"sealed": true, "initialized": false}')
        SEALED=$(echo "$STATUS_JSON" | jq -r '.sealed')
        INITIALIZED=$(echo "$STATUS_JSON" | jq -r '.initialized')
        
        if [ "$INITIALIZED" != "true" ]; then
          echo "ERROR: Vault is not initialized. Run initialization first."
          exit 1
        fi
        
        if [ "$SEALED" != "true" ]; then
          echo "Vault is already unsealed"
          vault status
          exit 0
        fi
        
        echo "Vault is sealed and needs to be unsealed"
        echo "Current status:"
        vault status || true
    - stateful: True
    - require:
      - pkg: jq

# Unseal Vault using stored keys
vault_unseal_with_stored_keys:
  cmd.run:
    - name: |
        export VAULT_ADDR="https://{{ hostname }}:{{ port }}"
        export VAULT_CACERT="/etc/vault.d/ca.crt"
        
        INIT_FILE="{{ init_file }}"
        
        # Check if we have initialization file
        if [ ! -f "$INIT_FILE" ]; then
          echo "ERROR: No initialization file found at $INIT_FILE"
          echo "Cannot auto-unseal without stored keys"
          echo "Please provide unseal keys manually or run initialization first"
          exit 1
        fi
        
        echo "Reading unseal keys from initialization file..."
        
        # We need 3 out of 5 keys (threshold = 3)
        UNSEAL_KEYS=$(jq -r '.unseal_keys_b64[]' "$INIT_FILE" 2>/dev/null | head -3)
        
        if [ -z "$UNSEAL_KEYS" ]; then
          echo "ERROR: Could not read unseal keys from $INIT_FILE"
          echo "File may be corrupted or have incorrect format"
          exit 1
        fi
        
        KEY_COUNT=$(echo "$UNSEAL_KEYS" | wc -l)
        echo "Found $KEY_COUNT unseal keys (need 3 for threshold)"
        
        # Unseal progress tracking
        UNSEAL_COUNT=0
        echo "$UNSEAL_KEYS" | while read -r KEY; do
          if [ -n "$KEY" ]; then
            UNSEAL_COUNT=$((UNSEAL_COUNT + 1))
            echo "Applying unseal key $UNSEAL_COUNT/3..."
            
            # Apply the unseal key
            UNSEAL_OUTPUT=$(vault operator unseal "$KEY" 2>&1)
            UNSEAL_EXIT=$?
            
            if [ $UNSEAL_EXIT -ne 0 ]; then
              echo "ERROR: Failed to apply unseal key $UNSEAL_COUNT"
              echo "$UNSEAL_OUTPUT"
              exit 1
            fi
            
            # Check if we're unsealed yet
            SEALED=$(echo "$UNSEAL_OUTPUT" | grep "Sealed" | awk '{print $2}')
            if [ "$SEALED" = "false" ]; then
              echo "Vault successfully unsealed!"
              break
            fi
          fi
        done
        
        # Final status check
        echo ""
        echo "Final Vault status:"
        vault status
        
        # Verify we're actually unsealed
        FINAL_STATUS=$(vault status -format=json)
        FINAL_SEALED=$(echo "$FINAL_STATUS" | jq -r '.sealed')
        
        if [ "$FINAL_SEALED" = "true" ]; then
          echo "ERROR: Vault is still sealed after applying keys"
          exit 1
        fi
        
        echo ""
        echo "✅ Vault unsealed successfully"
    - onlyif: vault status -format=json 2>/dev/null | jq -e '.sealed == true'
    - require:
      - cmd: vault_check_seal_status

# Create convenient unseal alias
vault_create_unseal_alias:
  file.managed:
    - name: /etc/profile.d/vault-unseal.sh
    - contents: |
        # Vault unseal convenience function
        vault-unseal() {
          export VAULT_ADDR="https://{{ hostname }}:{{ port }}"
          export VAULT_CACERT="/etc/vault.d/ca.crt"
          
          echo "Checking Vault status..."
          if vault status -format=json 2>/dev/null | jq -e '.sealed == false' > /dev/null; then
            echo "Vault is already unsealed"
            vault status
            return 0
          fi
          
          if [ -f "{{ init_file }}" ]; then
            echo "Using stored unseal keys..."
            /usr/local/bin/eos-vault-unseal
          else
            echo "No stored keys found. Please enter unseal keys manually."
            echo "You need to enter 3 out of 5 unseal keys."
            
            for i in 1 2 3; do
              echo -n "Enter unseal key $i/3: "
              read -s KEY
              echo
              vault operator unseal "$KEY"
            done
          fi
        }
    - mode: 644

# Log unseal event
vault_log_unseal_event:
  cmd.run:
    - name: |
        TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        echo "{\"event\": \"vault_unsealed\", \"timestamp\": \"$TIMESTAMP\", \"method\": \"salt_state\"}" >> /var/log/vault/unseal-events.jsonl
    - require:
      - cmd: vault_unseal_with_stored_keys

# Display unseal summary
vault_unseal_summary:
  cmd.run:
    - name: |
        echo ""
        echo "╔═══════════════════════════════════════════════════════════════════════╗"
        echo "║                      VAULT UNSEAL COMPLETED                          ║"
        echo "╚═══════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "🔓 Vault has been successfully unsealed using stored keys"
        echo ""
        echo "📊 Current Status:"
        vault status | grep -E "Version|Sealed|Cluster|Storage Type" || true
        echo ""
        echo "🔐 Security Notes:"
        echo "   • Unseal keys were read from: {{ init_file }}"
        echo "   • Only 3 out of 5 keys were needed (threshold)"
        echo "   • Consider using auto-unseal in production"
        echo ""
        echo "🛠️  Convenience Commands:"
        echo "   • Check status: vault status"
        echo "   • Reseal vault: vault operator seal"
        echo "   • Quick unseal: vault-unseal (after sourcing profile)"
        echo ""
    - require:
      - cmd: vault_log_unseal_event