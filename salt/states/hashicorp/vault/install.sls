# salt/states/hashicorp/vault/install.sls
# HashiCorp Vault installation state

{% set vault = pillar.get('vault', {}) %}
{% set version = vault.get('version', 'latest') %}
{% set vault_user = vault.get('user', 'vault') %}
{% set vault_group = vault.get('group', 'vault') %}
{% set install_dir = vault.get('install_dir', '/opt/vault') %}
{% set bin_dir = vault.get('bin_dir', '/usr/local/bin') %}

# Create vault user and group
vault_group:
  group.present:
    - name: {{ vault_group }}
    - system: True

vault_user:
  user.present:
    - name: {{ vault_user }}
    - group: {{ vault_group }}
    - system: True
    - home: {{ install_dir }}
    - shell: /bin/false
    - createhome: False
    - require:
      - group: vault_group

# Create comprehensive directory structure (following phase2_env_setup.go)
vault_directories:
  file.directory:
    - names:
      - {{ install_dir }}
      - {{ vault.get('config_path', '/etc/vault.d') }}
      - {{ vault.get('data_path', '/opt/vault/data') }}
      - {{ vault.get('log_path', '/opt/vault/logs') }}
      - {{ vault.get('tls_path', '/opt/vault/tls') }}
      - /var/lib/eos
      - /var/lib/eos/secret
      - /run/eos
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 700  # More restrictive permissions for security
    - makedirs: True
    - require:
      - user: vault_user

# Set specific permissions for config directory (needs to be readable by service)
vault_config_directory:
  file.directory:
    - name: {{ vault.get('config_path', '/etc/vault.d') }}
    - user: root
    - group: {{ vault_group }}
    - mode: 755
    - require:
      - file: vault_directories

# Include shared HashiCorp repository setup
include:
  - hashicorp

# Update package cache after repository setup
update_package_cache:
  pkg.refresh_db:
    - require:
      - pkgrepo: hashicorp_repo

# Install Vault
{% if version == 'latest' %}
vault_package:
  pkg.installed:
    - name: vault
    - require:
      - pkg: update_package_cache
{% else %}
vault_package:
  pkg.installed:
    - name: vault
    - version: {{ version }}
    - require:
      - pkg: update_package_cache
{% endif %}

# Set capabilities for mlock
vault_mlock_capability:
  cmd.run:
    - name: setcap cap_ipc_lock=+ep {{ bin_dir }}/vault
    - unless: getcap {{ bin_dir }}/vault | grep cap_ipc_lock
    - require:
      - pkg: vault_package

# Create systemd environment file
vault_environment:
  file.managed:
    - name: /etc/vault.d/vault.env
    - contents: |
        VAULT_CONFIG_PATH={{ vault.get('config_path', '/etc/vault.d') }}
        VAULT_DATA_PATH={{ vault.get('data_path', '/opt/vault/data') }}
        VAULT_LOG_LEVEL={{ vault.get('log_level', 'INFO') }}
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 640
    - require:
      - file: vault_directories