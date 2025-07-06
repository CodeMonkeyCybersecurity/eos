# salt/orchestration/hashicorp/vault/deploy.sls
# HashiCorp Vault deployment orchestration

{% set vault_minions = salt['mine.get']('G@role:vault', 'network.ip_addrs', 'compound') %}
{% set cluster_size = pillar.get('vault', {}).get('cluster_size', 3) %}
{% set ha_enabled = pillar.get('vault', {}).get('ha', false) %}

# Stage 1: Install Vault on all target minions
vault_install_stage:
  salt.state:
    - tgt: 'G@role:vault'
    - tgt_type: compound
    - sls: hashicorp.vault.install
    - concurrent: true

# Stage 2: Configure Vault (sequential for HA clusters)
{% if ha_enabled %}
vault_config_stage:
  salt.state:
    - tgt: 'G@role:vault'
    - tgt_type: compound 
    - sls: hashicorp.vault.config
    - batch: 1
    - require:
      - salt: vault_install_stage
{% else %}
vault_config_stage:
  salt.state:
    - tgt: 'G@role:vault'
    - tgt_type: compound
    - sls: hashicorp.vault.config
    - concurrent: true
    - require:
      - salt: vault_install_stage
{% endif %}

# Stage 3: Start Vault services
vault_service_stage:
  salt.state:
    - tgt: 'G@role:vault'
    - tgt_type: compound
    - sls: hashicorp.vault.service
    - concurrent: true
    - require:
      - salt: vault_config_stage

# Stage 4: Initialize Vault cluster (HA mode only)
{% if ha_enabled and vault_minions %}
{% set primary_minion = vault_minions.keys() | list | first %}
vault_init_primary:
  salt.function:
    - tgt: '{{ primary_minion }}'
    - fun: cmd.run
    - arg:
      - |
        if ! vault status 2>/dev/null | grep -q "Initialized.*true"; then
          vault operator init -key-shares=5 -key-threshold=3 -format=json > /etc/vault.d/vault-init.json
          chmod 600 /etc/vault.d/vault-init.json
          echo "Vault initialized on primary node"
        else
          echo "Vault already initialized"
        fi
    - env:
      - VAULT_ADDR: "{{ pillar.get('vault', {}).get('api_addr', 'https://localhost:8200') }}"
    - require:
      - salt: vault_service_stage

# Wait for initialization to complete
vault_wait_init:
  salt.function:
    - tgt: '{{ primary_minion }}'
    - fun: cmd.run
    - arg:
      - sleep 5
    - require:
      - salt: vault_init_primary

# Stage 5: Unseal Vault on all nodes (if init keys are available)
vault_unseal_cluster:
  salt.function:
    - tgt: 'G@role:vault'
    - tgt_type: compound
    - fun: cmd.script
    - arg:
      - |
        #!/bin/bash
        VAULT_ADDR="{{ pillar.get('vault', {}).get('api_addr', 'https://localhost:8200') }}"
        export VAULT_ADDR
        
        # Check if we have init keys available
        if [ -f /etc/vault.d/vault-init.json ]; then
          # Extract unseal keys
          UNSEAL_KEYS=$(jq -r '.unseal_keys_b64[]' /etc/vault.d/vault-init.json | head -3)
          
          # Unseal Vault
          echo "$UNSEAL_KEYS" | while read key; do
            vault operator unseal "$key"
          done
          
          echo "Vault unsealed successfully"
        else
          echo "No init keys found - manual unsealing required"
        fi
    - require:
      - salt: vault_wait_init
{% endif %}

# Stage 6: Post-deployment health checks
vault_health_check:
  salt.function:
    - tgt: 'G@role:vault'
    - tgt_type: compound
    - fun: cmd.run
    - arg:
      - /usr/local/bin/vault-health-check.sh
    - require:
      - salt: vault_service_stage
      {% if ha_enabled %}
      - salt: vault_unseal_cluster
      {% endif %}

# Stage 7: Configure basic policies and auth methods (optional)
{% if pillar.get('vault', {}).get('configure_policies', true) %}
vault_configure_policies:
  salt.function:
    - tgt: 'G@role:vault and G@vault_primary:true'
    - tgt_type: compound
    - fun: cmd.script
    - arg:
      - |
        #!/bin/bash
        VAULT_ADDR="{{ pillar.get('vault', {}).get('api_addr', 'https://localhost:8200') }}"
        export VAULT_ADDR
        
        # Authenticate with root token (if available)
        if [ -f /etc/vault.d/vault-init.json ]; then
          ROOT_TOKEN=$(jq -r '.root_token' /etc/vault.d/vault-init.json)
          export VAULT_TOKEN="$ROOT_TOKEN"
          
          # Create admin policy
          vault policy write admin /etc/vault.d/policies/admin.hcl
          
          # Enable userpass auth
          vault auth enable userpass 2>/dev/null || true
          
          # Create admin user
          vault write auth/userpass/users/admin \
            password="{{ pillar.get('vault', {}).get('admin_password', 'changeme') }}" \
            policies=admin
          
          echo "Basic Vault configuration completed"
        else
          echo "No root token available - skipping policy configuration"
        fi
    - require:
      - salt: vault_health_check
{% endif %}

# Final notification
vault_deployment_complete:
  salt.function:
    - tgt: 'G@role:vault'
    - tgt_type: compound
    - fun: cmd.run
    - arg:
      - echo "Vault deployment completed successfully at $(date)"
    - require:
      - salt: vault_health_check
      {% if pillar.get('vault', {}).get('configure_policies', true) %}
      - salt: vault_configure_policies
      {% endif %}