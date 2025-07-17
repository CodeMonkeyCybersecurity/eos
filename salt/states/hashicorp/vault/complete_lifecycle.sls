# Complete Vault Lifecycle Management via Salt
# This orchestrates the full Vault deployment: Create -> Enable -> Harden
# Replicates the complete functionality of pkg/vault lifecycle management
#
# Usage: 
#   Full deployment: salt-call --local state.apply hashicorp.vault.complete_lifecycle
#   With pillar:     salt-call --local state.apply hashicorp.vault.complete_lifecycle pillar='{"vault":{"enable_userpass":true,"enable_approle":true,"enable_mfa":true,"enable_agent":true}}'

# Phase 1: Complete Vault Creation (Install -> Environment -> TLS -> Config -> Service -> Initialize)
vault_complete_creation:
  salt.state:
    - tgt: '{{ grains.id }}'
    - sls: hashicorp.vault.eos_complete
    - require_in:
      - salt: vault_complete_enablement

# Wait for Vault to be ready after creation
vault_post_creation_wait:
  cmd.run:
    - name: |
        echo "Waiting for Vault to be fully initialized..."
        for i in {1..30}; do
          if [ -f "/var/lib/eos/secret/vault_init.json" ] && vault status -format=json 2>/dev/null | jq -e '.initialized == true' > /dev/null; then
            echo "Vault is initialized and ready"
            break
          fi
          echo "Waiting for Vault initialization... ($i/30)"
          sleep 2
        done
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
    - require:
      - salt: vault_complete_creation
    - require_in:
      - salt: vault_complete_enablement

# Phase 2: Complete Vault Enablement (Unseal -> Auth -> KV -> Policies -> Audit -> MFA -> Agent)
vault_complete_enablement:
  salt.state:
    - tgt: '{{ grains.id }}'
    - sls: hashicorp.vault.enable
    - pillar:
        vault:
          root_token: "{{ salt['cmd.run']('jq -r .root_token /var/lib/eos/secret/vault_init.json 2>/dev/null || echo ""') }}"
          enable_userpass: {{ salt['pillar.get']('vault:enable_userpass', True) }}
          enable_approle: {{ salt['pillar.get']('vault:enable_approle', True) }}
          enable_mfa: {{ salt['pillar.get']('vault:enable_mfa', True) }}
          enable_agent: {{ salt['pillar.get']('vault:enable_agent', True) }}
          eos_password: "{{ salt['pillar.get']('vault:eos_password', salt['random.get_str'](20)) }}"
    - require:
      - cmd: vault_post_creation_wait
    - unless: vault auth list | grep -q "userpass/"  # Skip if already enabled

# Phase 3: Complete Vault Hardening (System -> Vault-specific -> Security Policies -> Network)
vault_complete_hardening:
  salt.state:
    - tgt: '{{ grains.id }}'
    - sls: hashicorp.vault.harden
    - pillar:
        vault:
          root_token: "{{ salt['cmd.run']('jq -r .root_token /var/lib/eos/secret/vault_init.json 2>/dev/null || echo ""') }}"
          allowed_subnets: {{ salt['pillar.get']('vault:allowed_subnets', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) }}
    - require:
      - salt: vault_complete_enablement

# Create management scripts
vault_management_scripts:
  file.managed:
    - names:
      - /usr/local/bin/eos-vault:
          - contents: |
              #!/bin/bash
              # Eos Vault management wrapper
              export VAULT_ADDR="https://127.0.0.1:8179"
              export VAULT_CACERT="/etc/vault.d/ca.crt"
              vault "$@"
          - mode: 755
      - /usr/local/bin/eos-vault-status:
          - contents: |
              #!/bin/bash
              # Eos Vault status checker
              export VAULT_ADDR="https://127.0.0.1:8179"
              export VAULT_CACERT="/etc/vault.d/ca.crt"
              
              echo "=== Vault Service Status ==="
              systemctl status vault --no-pager | head -20
              
              echo -e "\n=== Vault API Status ==="
              vault status || echo "Vault API not responding"
              
              echo -e "\n=== Vault Agent Status ==="
              systemctl status vault-agent --no-pager 2>/dev/null | head -10 || echo "Vault Agent not configured"
              
              echo -e "\n=== Vault Audit Status ==="
              if [ -f "/var/lib/eos/secret/vault_init.json" ]; then
                ROOT_TOKEN=$(jq -r .root_token /var/lib/eos/secret/vault_init.json 2>/dev/null)
                if [ -n "$ROOT_TOKEN" ]; then
                  VAULT_TOKEN=$ROOT_TOKEN vault audit list 2>/dev/null || echo "Unable to list audit devices"
                fi
              fi
              
              echo -e "\n=== Network Listeners ==="
              ss -tlnp | grep 8179 || echo "No listeners on port 8179"
          - mode: 755
      - /usr/local/bin/eos-vault-backup:
          - contents: |
              #!/bin/bash
              # Eos Vault backup wrapper
              /usr/local/bin/vault-backup.sh
          - mode: 755
    - require:
      - salt: vault_complete_hardening

# Create comprehensive documentation
vault_lifecycle_documentation:
  file.managed:
    - name: /var/lib/eos/vault-lifecycle-complete.md
    - contents: |
        # Vault Complete Lifecycle Deployment
        
        *Last Updated: {{ salt['cmd.run']('date +%Y-%m-%d') }}*
        
        ## Deployment Summary
        
        This Salt-managed Vault deployment has completed all lifecycle phases:
        
        ### Phase 1: Creation
        - ✅ Vault binary installed via package manager
        - ✅ Environment prepared (user, directories, permissions)
        - ✅ TLS certificates generated (self-signed)
        - ✅ Configuration written and validated
        - ✅ Service started and health checked
        - ✅ Vault initialized (5 keys, 3 threshold)
        
        ### Phase 2: Enablement
        - ✅ KV v2 secrets engine enabled
        {% if salt['pillar.get']('vault:enable_userpass', True) %}
        - ✅ Userpass authentication enabled
        - ✅ Admin user 'eos' created
        {% endif %}
        {% if salt['pillar.get']('vault:enable_approle', True) %}
        - ✅ AppRole authentication enabled
        - ✅ AppRole 'eos' created
        {% endif %}
        - ✅ Entity and aliases created
        - ✅ Core policies applied
        - ✅ Audit logging enabled
        {% if salt['pillar.get']('vault:enable_mfa', True) %}
        - ✅ MFA configured
        {% endif %}
        {% if salt['pillar.get']('vault:enable_agent', True) %}
        - ✅ Vault Agent deployed
        {% endif %}
        
        ### Phase 3: Hardening
        - ✅ System hardening applied
        - ✅ Vault-specific security enhanced
        - ✅ Network access restricted
        - ✅ Backup automation configured
        - ✅ Monitoring and logging setup
        
        ## Important Files and Locations
        
        - **Vault Config**: `/etc/vault.d/vault.hcl`
        - **TLS Certificates**: `/opt/vault/tls/`
        - **Initialization Data**: `/var/lib/eos/secret/vault_init.json` (SENSITIVE!)
        - **Audit Logs**: `/var/log/vault/vault-audit.log`
        - **Backup Script**: `/usr/local/bin/vault-backup.sh`
        - **Management Scripts**: `/usr/local/bin/eos-vault*`
        
        ## Access Information
        
        - **API Endpoint**: `https://{{ grains.get('fqdn', 'localhost') }}:8179`
        - **Local CLI**: `eos-vault <command>`
        
        ## Authentication Methods
        
        {% if salt['pillar.get']('vault:enable_userpass', True) %}
        ### Userpass
        ```bash
        eos-vault login -method=userpass username=eos
        ```
        {% endif %}
        
        {% if salt['pillar.get']('vault:enable_approle', True) %}
        ### AppRole
        ```bash
        # Credentials stored in /var/lib/eos/secret/vault_approle.yaml
        ROLE_ID=$(grep role_id /var/lib/eos/secret/vault_approle.yaml | cut -d: -f2 | tr -d ' ')
        SECRET_ID=$(grep secret_id /var/lib/eos/secret/vault_approle.yaml | cut -d: -f2 | tr -d ' ')
        eos-vault write auth/approle/login role_id=$ROLE_ID secret_id=$SECRET_ID
        ```
        {% endif %}
        
        ## Maintenance Commands
        
        - **Check Status**: `eos-vault-status`
        - **Unseal Vault**: `/usr/local/bin/eos-vault-unseal`
        - **Backup Now**: `eos-vault-backup`
        - **View Audit Logs**: `sudo tail -f /var/log/vault/vault-audit.log`
        
        ## Security Considerations
        
        1. **Root Token**: Should be revoked after alternative auth is verified
        2. **Unseal Keys**: Should be distributed among multiple administrators
        3. **Backup**: Test restore procedures regularly
        4. **Monitoring**: Check audit logs for suspicious activity
        5. **Network**: Review firewall rules in production
        
        ## Next Steps
        
        1. Test authentication methods
        2. Store production secrets
        3. Configure additional auth backends as needed
        4. Set up monitoring and alerting
        5. Plan for high availability if required
        
        ---
        Managed by Eos Salt States | Generated: {{ salt['cmd.run']('date -u +%Y-%m-%dT%H:%M:%SZ') }}
    - user: root
    - group: root
    - mode: 644
    - require:
      - file: vault_management_scripts

# Final summary
vault_lifecycle_complete:
  cmd.run:
    - name: |
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║           VAULT COMPLETE LIFECYCLE DEPLOYMENT SUCCESSFUL                      ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "🎉 All Vault lifecycle phases completed via Salt:"
        echo ""
        echo "📦 PHASE 1 - CREATION: Vault installed, configured, and initialized"
        echo "🔓 PHASE 2 - ENABLEMENT: Auth methods, policies, and features enabled"
        echo "🛡️  PHASE 3 - HARDENING: Comprehensive security hardening applied"
        echo ""
        echo "📖 Full documentation: /var/lib/eos/vault-lifecycle-complete.md"
        echo ""
        echo "🚀 Quick Start Commands:"
        echo "   • Check status: eos-vault-status"
        echo "   • Use Vault: eos-vault <command>"
        echo "   • Login: eos-vault login -method=userpass username=eos"
        echo ""
        echo "⚠️  Important: Review the documentation for security considerations"
        echo ""
        echo "This deployment is fully managed by Salt. To modify configuration,"
        echo "update the pillar data and re-run this state."
        echo ""
    - require:
      - file: vault_lifecycle_documentation