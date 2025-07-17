# Vault Removal Salt State
# Comprehensive removal of HashiCorp Vault installation, configuration, and data
# Following the architectural principle: Salt = Physical infrastructure

{% set vault = pillar.get('vault', {}) %}
{% set vault_user = vault.get('user', 'vault') %}
{% set vault_group = vault.get('group', 'vault') %}

# Stop Vault services before removal
vault_service_stop:
  service.dead:
    - names:
      - vault
      - vault-agent-eos
      - vault-backup
      - vault-agent-health-check
    - enable: False

# Remove Vault package
vault_package_remove:
  pkg.removed:
    - name: vault
    - require:
      - service: vault_service_stop

# Remove Vault binary (in case it was manually installed)
vault_binary_remove:
  file.absent:
    - name: /usr/local/bin/vault

# Remove all Vault configuration files and directories
vault_config_cleanup:
  file.absent:
    - names:
      - /etc/vault.d
      - /etc/vault-agent-eos.hcl
      - /opt/vault
      - /var/lib/eos/secret/vault_init.json
      - /run/eos
      - /etc/tmpfiles.d/eos.conf
      - /home/vault/.config
    - require:
      - service: vault_service_stop

# Remove systemd service files
vault_systemd_cleanup:
  file.absent:
    - names:
      - /etc/systemd/system/vault.service
      - /etc/systemd/system/vault-agent-eos.service
      - /etc/systemd/system/vault-backup.service
      - /etc/systemd/system/vault-backup.timer
      - /etc/systemd/system/vault-agent-health-check.service
      - /etc/systemd/system/vault-agent-health-check.timer
      - /etc/systemd/system/vault.service.d
    - require:
      - service: vault_service_stop

# Remove management scripts
vault_scripts_cleanup:
  file.absent:
    - names:
      - /usr/local/bin/eos-vault-unseal
      - /usr/local/bin/eos-vault-status
      - /usr/local/bin/eos-vault-backup

# Remove TLS certificates from system trust store
vault_ca_trust_cleanup:
  file.absent:
    - names:
      - /usr/local/share/ca-certificates/vault-local-ca.crt
      - /etc/pki/ca-trust/source/anchors/vault-local-ca.crt

# Update CA certificates after removal
{% if grains['os_family'] == 'Debian' %}
vault_update_ca_certificates:
  cmd.run:
    - name: update-ca-certificates
    - require:
      - file: vault_ca_trust_cleanup
{% elif grains['os_family'] == 'RedHat' %}
vault_update_ca_trust:
  cmd.run:
    - name: update-ca-trust extract
    - require:
      - file: vault_ca_trust_cleanup
{% endif %}

# Remove Vault user and group (only if they exist and aren't system-critical)
vault_user_removal_check:
  cmd.run:
    - name: |
        # Only remove vault user if it exists and was created by our installation
        if id vault >/dev/null 2>&1; then
          # Check if vault user home directory suggests it was created by eos
          if [ -d "/opt/vault" ] || [ "$(getent passwd vault | cut -d: -f6)" = "/opt/vault" ]; then
            userdel --remove vault 2>/dev/null || userdel vault 2>/dev/null || true
            groupdel vault 2>/dev/null || true
            echo "Removed vault user and group"
          else
            echo "Vault user appears to be system-managed, not removing"
          fi
        else
          echo "Vault user does not exist"
        fi
    - require:
      - file: vault_config_cleanup

# Clean up HashiCorp repository (conditional - only if no other HashiCorp tools)
vault_repo_cleanup_check:
  cmd.run:
    - name: |
        # Check if other HashiCorp tools are installed
        HASHICORP_TOOLS="consul nomad terraform packer boundary"
        OTHER_TOOLS_FOUND=false
        
        for tool in $HASHICORP_TOOLS; do
          if command -v "$tool" >/dev/null 2>&1; then
            echo "Found other HashiCorp tool: $tool"
            OTHER_TOOLS_FOUND=true
            break
          fi
        done
        
        if [ "$OTHER_TOOLS_FOUND" = "false" ]; then
          echo "No other HashiCorp tools found, cleaning up repository"
          {% if grains['os_family'] == 'Debian' %}
          rm -f /usr/share/keyrings/hashicorp-archive-keyring.gpg
          rm -f /etc/apt/sources.list.d/hashicorp.list
          apt-get update
          {% elif grains['os_family'] == 'RedHat' %}
          rm -f /etc/yum.repos.d/hashicorp.repo
          {% endif %}
        else
          echo "Other HashiCorp tools present, keeping repository"
        fi

# Reload systemd after cleanup
vault_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - require:
      - file: vault_systemd_cleanup

# Final verification that Vault is completely removed
vault_removal_verification:
  cmd.run:
    - name: |
        echo ""
        echo "╔═══════════════════════════════════════════════════════════════════════╗"
        echo "║                   VAULT REMOVAL COMPLETED                            ║"
        echo "╚═══════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "🗑️  Vault package and binary removed"
        echo "🗂️  Configuration files and directories cleaned up"
        echo "⚙️  Systemd services removed and reloaded"
        echo "👤 Vault user/group handled appropriately"
        echo "🏛️  Repository cleanup performed if needed"
        echo ""
        
        # Check if anything remains
        REMAINING_ITEMS=""
        
        if command -v vault >/dev/null 2>&1; then
          REMAINING_ITEMS="$REMAINING_ITEMS vault-binary"
        fi
        
        if systemctl list-units --all | grep -q vault; then
          REMAINING_ITEMS="$REMAINING_ITEMS vault-services"
        fi
        
        if [ -d "/etc/vault.d" ] || [ -d "/opt/vault" ]; then
          REMAINING_ITEMS="$REMAINING_ITEMS vault-directories"
        fi
        
        if [ -n "$REMAINING_ITEMS" ]; then
          echo "⚠️  Some items may still remain: $REMAINING_ITEMS"
          echo "   This may be normal if manually installed or system-managed"
        else
          echo "✅ Complete removal verified - no Vault components detected"
        fi
        echo ""
    - require:
      - cmd: vault_systemd_reload
      - cmd: vault_user_removal_check