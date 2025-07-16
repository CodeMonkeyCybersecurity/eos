# Vault Configuration for Eos
# Replicates functionality from phase4_config.go
# Uses Eos-specific paths and port configuration (8179 instead of 8200)

{% set vault = pillar.get('vault', {}) %}
{% set vault_user = vault.get('user', 'vault') %}
{% set vault_group = vault.get('group', 'vault') %}
{% set hostname = grains.get('fqdn', grains.get('id', 'localhost')) %}
{% set tls_path = vault.get('tls_path', '/opt/vault/tls') %}
{% set data_path = vault.get('data_path', '/opt/vault/data') %}

# Ensure prerequisites
include:
  - hashicorp.vault.install
  - hashicorp.vault.tls

# Create main Vault configuration (replicating exact config from phase4_config.go)
vault_eos_config:
  file.managed:
    - name: /etc/vault.d/vault.hcl
    - contents: |
        # Vault configuration managed by Salt (Eos-compatible)
        # Replicates configuration from pkg/vault/phase4_config.go
        
        listener "tcp" {
          address         = "0.0.0.0:{{ vault.get('port', '8179') }}"
          tls_cert_file   = "{{ tls_path }}/tls.crt"
          tls_key_file    = "{{ tls_path }}/tls.key"
        }
        
        storage "file" {
          path = "{{ data_path }}"
        }
        
        disable_mlock = true
        api_addr = "https://{{ hostname }}:{{ vault.get('port', '8179') }}"
        ui = true
        log_level = "{{ vault.get('log_level', 'info') }}"
        log_format = "{{ vault.get('log_format', 'json') }}"
        
        # Security settings
        max_lease_ttl = "{{ vault.get('max_lease_ttl', '8760h') }}"
        default_lease_ttl = "{{ vault.get('default_lease_ttl', '768h') }}"
        
        # Performance tuning
        {% if vault.get('cache_size') %}
        cache_size = {{ vault.cache_size }}
        {% endif %}
        
        # Plugin directory
        plugin_directory = "{{ vault.get('plugin_directory', '/usr/local/lib/vault/plugins') }}"
        
    - user: root
    - group: {{ vault_group }}
    - mode: 644
    - require:
      - file: vault_tls_certificate
      - file: vault_directories

# Environment variables for Vault service (replicating VAULT_ADDR and VAULT_CACERT)
vault_environment:
  file.managed:
    - name: /etc/vault.d/vault.env
    - contents: |
        # Vault environment variables (managed by Salt)
        VAULT_ADDR=https://{{ hostname }}:{{ vault.get('port', '8179') }}
        VAULT_CACERT=/etc/vault.d/ca.crt
        VAULT_CONFIG_PATH=/etc/vault.d/vault.hcl
        VAULT_DATA_PATH={{ data_path }}
        VAULT_LOG_LEVEL={{ vault.get('log_level', 'info') }}
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 640
    - require:
      - file: vault_directories

# Validate configuration file (replicating validation logic from Go code)
vault_config_validation:
  cmd.run:
    - name: |
        # Check for required keywords in config
        if ! grep -q "listener" /etc/vault.d/vault.hcl; then
          echo "ERROR: Missing 'listener' in Vault config"
          exit 1
        fi
        if ! grep -q "storage" /etc/vault.d/vault.hcl; then
          echo "ERROR: Missing 'storage' in Vault config" 
          exit 1
        fi
        if ! grep -q "api_addr" /etc/vault.d/vault.hcl; then
          echo "ERROR: Missing 'api_addr' in Vault config"
          exit 1
        fi
        # Check file size > 0
        if [ ! -s /etc/vault.d/vault.hcl ]; then
          echo "ERROR: Vault config file is empty"
          exit 1
        fi
        echo "Vault configuration validation passed"
    - require:
      - file: vault_eos_config

# Create log rotation configuration
vault_logrotate:
  file.managed:
    - name: /etc/logrotate.d/vault
    - contents: |
        /opt/vault/logs/*.log {
          daily
          missingok
          rotate 7
          compress
          delaycompress
          notifempty
          copytruncate
          su vault vault
        }
    - user: root
    - group: root
    - mode: 644