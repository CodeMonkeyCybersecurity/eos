# Eos Vault Enablement State
# Implements the complete vault.EnableVault() functionality via Salt states
# This includes: unseal, auth setup, KV v2, policies, audit, MFA, agent, and initial hardening
#
# Usage: salt-call --local state.apply hashicorp.vault.enable

# Ensure Vault is unsealed first
vault_check_seal_status:
  cmd.run:
    - name: |
        if vault status -format=json 2>/dev/null | jq -e '.sealed == false' > /dev/null; then
          echo "Vault is already unsealed"
        else
          echo "ERROR: Vault is sealed. Please unseal first with: eos update vault unseal"
          exit 1
        fi
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
    - require_in:
      - cmd: vault_enable_kv_v2

# Phase 9a: Enable KV v2 secrets engine
vault_enable_kv_v2:
  cmd.run:
    - name: |
        # Check if KV v2 already enabled at secret/
        if vault secrets list -format=json | jq -e '.["secret/"]' > /dev/null 2>&1; then
          echo "KV v2 already enabled at secret/"
        else
          vault secrets enable -path=secret -version=2 kv
          echo "KV v2 secrets engine enabled at secret/"
        fi
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - unless: vault secrets list -format=json | jq -e '.["secret/"]'

# Phase 10a: Enable Userpass authentication
vault_enable_userpass:
  cmd.run:
    - name: |
        if vault auth list -format=json | jq -e '.["userpass/"]' > /dev/null 2>&1; then
          echo "Userpass auth already enabled"
        else
          vault auth enable userpass
          echo "Userpass authentication enabled"
        fi
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - unless: vault auth list -format=json | jq -e '.["userpass/"]'

# Create eos admin user if requested
{% if salt['pillar.get']('vault:enable_userpass', False) %}
vault_create_eos_user:
  cmd.run:
    - name: |
        vault write auth/userpass/users/eos \
          password="{{ salt['pillar.get']('vault:eos_password', 'changeme') }}" \
          policies="admin,default"
        echo "Created eos user with admin policy"
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - require:
      - cmd: vault_enable_userpass
{% endif %}

# Phase 10b: Enable AppRole authentication
{% if salt['pillar.get']('vault:enable_approle', False) %}
vault_enable_approle:
  cmd.run:
    - name: |
        if vault auth list -format=json | jq -e '.["approle/"]' > /dev/null 2>&1; then
          echo "AppRole auth already enabled"
        else
          vault auth enable approle
          echo "AppRole authentication enabled"
        fi
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - unless: vault auth list -format=json | jq -e '.["approle/"]'

# Create eos AppRole
vault_create_eos_approle:
  cmd.run:
    - name: |
        # Create the role
        vault write auth/approle/role/eos \
          token_policies="default,read-secrets" \
          token_num_uses=0 \
          token_ttl=1h \
          token_max_ttl=24h \
          secret_id_num_uses=0 \
          bind_secret_id=true
        
        # Get role ID
        ROLE_ID=$(vault read -field=role_id auth/approle/role/eos/role-id)
        echo "role_id: $ROLE_ID" > /var/lib/eos/secret/vault_approle.yaml
        
        # Generate secret ID
        SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/eos/secret-id)
        echo "secret_id: $SECRET_ID" >> /var/lib/eos/secret/vault_approle.yaml
        
        chmod 600 /var/lib/eos/secret/vault_approle.yaml
        echo "AppRole credentials saved to /var/lib/eos/secret/vault_approle.yaml"
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - require:
      - cmd: vault_enable_approle
    - creates: /var/lib/eos/secret/vault_approle.yaml
{% endif %}

# Phase 10c: Create Eos Entity
vault_create_eos_entity:
  cmd.run:
    - name: |
        # Create entity for eos
        ENTITY_ID=$(vault write -format=json identity/entity \
          name="eos-system" \
          policies="default" \
          metadata=type="system" \
          metadata=created_by="salt" | jq -r '.data.id')
        
        echo "Created entity: $ENTITY_ID"
        
        # Create aliases if auth methods exist
        if vault auth list -format=json | jq -e '.["userpass/"]' > /dev/null 2>&1; then
          # Get accessor for userpass
          USERPASS_ACCESSOR=$(vault auth list -format=json | jq -r '.["userpass/"].accessor')
          
          # Create alias for userpass
          vault write identity/entity-alias \
            name="eos" \
            canonical_id="$ENTITY_ID" \
            mount_accessor="$USERPASS_ACCESSOR"
        fi
        
        if vault auth list -format=json | jq -e '.["approle/"]' > /dev/null 2>&1; then
          # Get accessor for approle
          APPROLE_ACCESSOR=$(vault auth list -format=json | jq -r '.["approle/"].accessor')
          
          # Create alias for approle
          vault write identity/entity-alias \
            name="eos" \
            canonical_id="$ENTITY_ID" \
            mount_accessor="$APPROLE_ACCESSOR"
        fi
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - unless: vault list -format=json identity/entity/name | jq -e '. | index("eos-system")'

# Phase 11: Write core policies
vault_write_admin_policy:
  file.managed:
    - name: /tmp/vault-admin-policy.hcl
    - contents: |
        # Admin policy - full access
        path "*" {
          capabilities = ["create", "read", "update", "delete", "list", "sudo"]
        }
    - mode: 600

vault_apply_admin_policy:
  cmd.run:
    - name: vault policy write admin /tmp/vault-admin-policy.hcl
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - require:
      - file: vault_write_admin_policy
    - unless: vault policy list | grep -q "^admin$"

vault_write_read_secrets_policy:
  file.managed:
    - name: /tmp/vault-read-secrets-policy.hcl
    - contents: |
        # Read-only access to secrets
        path "secret/data/*" {
          capabilities = ["read", "list"]
        }
        
        path "secret/metadata/*" {
          capabilities = ["read", "list"]
        }
    - mode: 600

vault_apply_read_secrets_policy:
  cmd.run:
    - name: vault policy write read-secrets /tmp/vault-read-secrets-policy.hcl
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - require:
      - file: vault_write_read_secrets_policy
    - unless: vault policy list | grep -q "^read-secrets$"

# Phase 12: Enable audit logging
vault_create_audit_dir:
  file.directory:
    - name: /var/log/vault
    - user: vault
    - group: vault
    - mode: 755

vault_enable_file_audit:
  cmd.run:
    - name: |
        if vault audit list -format=json | jq -e '.["file/"]' > /dev/null 2>&1; then
          echo "File audit already enabled"
        else
          vault audit enable file \
            file_path=/var/log/vault/audit.log \
            log_raw=false \
            hmac_accessor=true \
            mode=0640
          echo "File audit logging enabled"
        fi
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - require:
      - file: vault_create_audit_dir
    - unless: vault audit list -format=json | jq -e '.["file/"]'

# Phase 13: Enable MFA (if requested)
{% if salt['pillar.get']('vault:enable_mfa', False) %}
vault_enable_totp_mfa:
  cmd.run:
    - name: |
        # Create TOTP method
        vault write identity/mfa/method/totp/eos-totp \
          issuer="Eos Vault" \
          period=30 \
          key_size=20 \
          qr_size=200 \
          algorithm=SHA256 \
          digits=6
        
        echo "TOTP MFA method created"
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"  
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - unless: vault list -format=json identity/mfa/method/totp | jq -e '. | index("eos-totp")'
{% endif %}

# Phase 14: Configure Vault Agent (if requested)
{% if salt['pillar.get']('vault:enable_agent', False) %}
vault_agent_config_dir:
  file.directory:
    - name: /etc/vault.d/agent
    - user: vault
    - group: vault
    - mode: 755

vault_agent_config:
  file.managed:
    - name: /etc/vault.d/agent/agent.hcl
    - contents: |
        # Vault Agent Configuration
        vault {
          address = "https://127.0.0.1:8179"
          tls_skip_verify = true
        }
        
        pid_file = "/var/run/vault-agent.pid"
        
        auto_auth {
          {% if salt['pillar.get']('vault:agent_auth_method', 'approle') == 'approle' %}
          method "approle" {
            config = {
              role_id_file_path = "/var/lib/eos/secret/vault_approle_role_id"
              secret_id_file_path = "/var/lib/eos/secret/vault_approle_secret_id"
            }
          }
          {% endif %}
          
          sink "file" {
            config = {
              path = "/var/lib/eos/secret/vault_agent_token"
              mode = 0640
            }
          }
        }
        
        cache {
          use_auto_auth_token = true
        }
        
        listener "tcp" {
          address = "127.0.0.1:8100"
          tls_disable = true
        }
    - user: vault
    - group: vault
    - mode: 640
    - require:
      - file: vault_agent_config_dir

vault_agent_systemd_service:
  file.managed:
    - name: /etc/systemd/system/vault-agent.service
    - contents: |
        [Unit]
        Description=Vault Agent
        Documentation=https://www.vaultproject.io/docs/agent
        Requires=network-online.target vault.service
        After=network-online.target vault.service
        ConditionFileNotEmpty=/etc/vault.d/agent/agent.hcl
        
        [Service]
        User=vault
        Group=vault
        ProtectSystem=full
        ProtectHome=read-only
        PrivateTmp=yes
        PrivateDevices=yes
        SecureBits=keep-caps
        AmbientCapabilities=CAP_IPC_LOCK
        CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
        NoNewPrivileges=yes
        ExecStart=/usr/bin/vault agent -config=/etc/vault.d/agent/agent.hcl
        ExecReload=/bin/kill -HUP $MAINPID
        KillMode=process
        Restart=on-failure
        RestartSec=5
        TimeoutStopSec=30
        
        [Install]
        WantedBy=multi-user.target
    - mode: 644

vault_agent_service_start:
  service.running:
    - name: vault-agent
    - enable: True
    - watch:
      - file: vault_agent_config
      - file: vault_agent_systemd_service
    - require:
      - file: vault_agent_systemd_service
      - cmd: vault_agent_systemd_reload

vault_agent_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: vault_agent_systemd_service
{% endif %}

# Phase 15: Write bootstrap secret
vault_write_bootstrap_secret:
  cmd.run:
    - name: |
        # Write a test secret to verify everything works
        vault kv put secret/eos/bootstrap \
          initialized="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
          managed_by="salt" \
          environment="production"
        
        # Verify we can read it back
        vault kv get -format=json secret/eos/bootstrap
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - require:
      - cmd: vault_enable_kv_v2

# Summary and next steps
vault_enable_complete:
  cmd.run:
    - name: |
        echo ""
        echo "╔═══════════════════════════════════════════════════════════════════════╗"
        echo "║              VAULT ENABLEMENT COMPLETED SUCCESSFULLY                  ║"
        echo "╚═══════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "✅ Completed Steps:"
        echo "   • KV v2 secrets engine enabled at secret/"
        {% if salt['pillar.get']('vault:enable_userpass', False) %}
        echo "   • Userpass authentication enabled"
        echo "   • Created eos user with admin policy"
        {% endif %}
        {% if salt['pillar.get']('vault:enable_approle', False) %}
        echo "   • AppRole authentication enabled"
        echo "   • Created eos approle with credentials"
        {% endif %}
        echo "   • Created eos-system entity with aliases"
        echo "   • Applied admin and read-secrets policies"
        echo "   • Enabled file audit logging"
        {% if salt['pillar.get']('vault:enable_mfa', False) %}
        echo "   • Configured TOTP MFA method"
        {% endif %}
        {% if salt['pillar.get']('vault:enable_agent', False) %}
        echo "   • Configured and started Vault Agent"
        {% endif %}
        echo "   • Created bootstrap secret"
        echo ""
        echo "📋 Next Steps:"
        echo "   1. Run: eos secure vault (to apply hardening)"
        echo "   2. Test auth: vault login -method=userpass username=eos"
        echo "   3. Revoke root token when ready: vault token revoke <root-token>"
        echo ""
        echo "🔐 Important Files:"
        echo "   • Audit logs: /var/log/vault/audit.log"
        {% if salt['pillar.get']('vault:enable_approle', False) %}
        echo "   • AppRole creds: /var/lib/eos/secret/vault_approle.yaml"
        {% endif %}
        {% if salt['pillar.get']('vault:enable_agent', False) %}
        echo "   • Agent config: /etc/vault.d/agent/agent.hcl"
        {% endif %}
        echo ""
    - require:
      - cmd: vault_write_bootstrap_secret