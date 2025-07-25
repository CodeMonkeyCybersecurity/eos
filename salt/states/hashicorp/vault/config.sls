# salt/states/hashicorp/vault/config.sls
# HashiCorp Vault configuration state

{% set vault = pillar.get('vault', {}) %}
{% set vault_user = vault.get('user', 'vault') %}
{% set vault_group = vault.get('group', 'vault') %}
{% set config_path = vault.get('config_path', '/etc/vault.d') %}
{% set data_path = vault.get('data_path', '/opt/vault/data') %}
{% set tls_enabled = vault.get('tls_enabled', True) %}
{% set backend = vault.get('backend', 'file') %}
{% set cluster_addr = vault.get('cluster_addr', grains.get('ip4_interfaces', {}).get('eth0', ['127.0.0.1'])[0] + ':8201') %}
{% set api_addr = vault.get('api_addr', 'https://' + grains.get('fqdn', 'localhost') + ':8200') %}

include:
  - hashicorp.vault.install

# Generate TLS certificates if enabled
{% if tls_enabled %}
vault_tls_cert:
  cmd.run:
    - name: |
        openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
          -subj "/C=US/ST=State/L=City/O=Organization/CN={{ grains.get('fqdn', 'localhost') }}" \
          -keyout {{ config_path }}/vault-key.pem \
          -out {{ config_path }}/vault-cert.pem
        chown {{ vault_user }}:{{ vault_group }} {{ config_path }}/vault-*.pem
        chmod 600 {{ config_path }}/vault-key.pem
        chmod 644 {{ config_path }}/vault-cert.pem
    - unless: test -f {{ config_path }}/vault-cert.pem
    - require:
      - file: vault_directories
{% endif %}

# Main Vault configuration
vault_config:
  file.managed:
    - name: {{ config_path }}/vault.hcl
    - contents: |
        # Vault configuration file
        # Generated by Salt
        
        {% if backend == 'file' %}
        storage "file" {
          path = "{{ data_path }}"
        }
        {% elif backend == 'consul' %}
        storage "consul" {
          address = "{{ vault.get('consul_address', '127.0.0.1:8161') }}"
          path    = "{{ vault.get('consul_path', 'vault/') }}"
          {% if vault.get('consul_token') %}
          token   = "{{ vault.consul_token }}"
          {% endif %}
        }
        {% endif %}
        
        listener "tcp" {
          address = "{{ vault.get('listen_address', '0.0.0.0:8200') }}"
          {% if tls_enabled %}
          tls_cert_file = "{{ config_path }}/vault-cert.pem"
          tls_key_file  = "{{ config_path }}/vault-key.pem"
          {% else %}
          tls_disable = true
          {% endif %}
        }
        
        cluster_addr = "{{ cluster_addr }}"
        api_addr = "{{ api_addr }}"
        
        ui = {{ vault.get('ui_enabled', 'true') | lower }}
        
        {% if vault.get('log_level') %}
        log_level = "{{ vault.log_level }}"
        {% endif %}
        
        {% if vault.get('log_file') %}
        log_file = "{{ vault.log_file }}"
        {% endif %}
        
        # Security settings
        disable_mlock = {{ vault.get('disable_mlock', 'false') | lower }}
        disable_cache = {{ vault.get('disable_cache', 'false') | lower }}
        
        {% if vault.get('seal_type') == 'awskms' %}
        seal "awskms" {
          region     = "{{ vault.awskms.region }}"
          kms_key_id = "{{ vault.awskms.kms_key_id }}"
        }
        {% elif vault.get('seal_type') == 'gcpckms' %}
        seal "gcpckms" {
          project     = "{{ vault.gcpckms.project }}"
          region      = "{{ vault.gcpckms.region }}"
          key_ring    = "{{ vault.gcpckms.key_ring }}"
          crypto_key  = "{{ vault.gcpckms.crypto_key }}"
        }
        {% endif %}
        
        # Telemetry
        {% if vault.get('telemetry') %}
        telemetry {
          {% for key, value in vault.telemetry.items() %}
          {{ key }} = "{{ value }}"
          {% endfor %}
        }
        {% endif %}
        
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 640
    - require:
      - file: vault_directories
      {% if tls_enabled %}
      - cmd: vault_tls_cert
      {% endif %}

# Vault policy directory
vault_policies_dir:
  file.directory:
    - name: {{ config_path }}/policies
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 755
    - require:
      - file: vault_directories

# Default admin policy
vault_admin_policy:
  file.managed:
    - name: {{ config_path }}/policies/admin.hcl
    - contents: |
        # Admin policy for Vault
        path "*" {
          capabilities = ["create", "read", "update", "delete", "list", "sudo"]
        }
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 644
    - require:
      - file: vault_policies_dir

# Backup script
vault_backup_script:
  file.managed:
    - name: /usr/local/bin/vault-backup.sh
    - contents: |
        #!/bin/bash
        # Vault backup script
        BACKUP_DIR="{{ vault.get('backup_dir', '/opt/vault/backups') }}"
        DATE=$(date +%Y%m%d-%H%M%S)
        
        mkdir -p "$BACKUP_DIR"
        
        # Backup Vault data
        if [ -d "{{ data_path }}" ]; then
          tar -czf "$BACKUP_DIR/vault-data-$DATE.tar.gz" -C "{{ data_path }}" .
        fi
        
        # Backup configuration
        tar -czf "$BACKUP_DIR/vault-config-$DATE.tar.gz" -C "{{ config_path }}" .
        
        # Keep only last 7 days of backups
        find "$BACKUP_DIR" -name "vault-*.tar.gz" -mtime +7 -delete
        
        echo "Backup completed: $DATE"
    - mode: 755
    - require:
      - file: vault_config

# Backup cron job (if enabled)
{% if vault.get('backup_enabled', False) %}
vault_backup_cron:
  cron.present:
    - name: /usr/local/bin/vault-backup.sh
    - user: {{ vault_user }}
    - minute: "{{ vault.get('backup_minute', '0') }}"
    - hour: "{{ vault.get('backup_hour', '2') }}"
    - require:
      - file: vault_backup_script
{% endif %}