# Vault secrets management for Helen deployments
# Handles both static and Ghost mode secrets

{% set mode = salt['pillar.get']('helen:mode', 'static') %}
{% set environment = salt['pillar.get']('helen:environment', 'production') %}
{% set domain = salt['pillar.get']('helen:domain') %}

# For static deployments, we just need basic metadata
{% if mode == 'static' %}

helen_vault_static_metadata:
  vault.write_secret:
    - path: kv/data/helen/{{ environment }}/metadata
    - data:
        deployment_mode: static
        domain: {{ domain }}
        deployed_at: {{ salt['cmd.run']('date -u +%Y-%m-%dT%H:%M:%SZ') }}
        deployed_by: {{ salt['environ.get']('USER', 'eos') }}
        git_commit: {{ salt['pillar.get']('helen:git_commit', 'N/A') }}

{% elif mode == 'ghost' %}

# Ghost deployments need comprehensive secrets

# Database credentials
helen_vault_ghost_database:
  vault.write_secret:
    - path: kv/data/helen/{{ environment }}/database
    - data:
        {% if salt['pillar.get']('helen:database', 'mysql') == 'mysql' %}
        client: mysql
        host: {{ salt['pillar.get']('helen:db_host', 'mysql.service.consul') }}
        port: {{ salt['pillar.get']('helen:db_port', 3306) }}
        user: helen_{{ environment }}
        password: {{ salt['cmd.run']('openssl rand -base64 32 | tr -d "=+/" | cut -c1-25') }}
        database: helen_{{ environment }}
        {% else %}
        client: sqlite3
        filename: /var/lib/ghost/content/data/ghost.db
        {% endif %}

# Email configuration
helen_vault_ghost_mail:
  vault.write_secret:
    - path: kv/data/helen/{{ environment }}/mail
    - data:
        transport: SMTP
        host: {{ salt['pillar.get']('helen:mail_host', 'smtp.gmail.com') }}
        port: {{ salt['pillar.get']('helen:mail_port', 587) }}
        secure: {{ salt['pillar.get']('helen:mail_secure', true) }}
        user: {{ salt['pillar.get']('helen:mail_user', '') }}
        password: {{ salt['pillar.get']('helen:mail_password', '') }}
        from: {{ salt['pillar.get']('helen:mail_from', 'noreply@' ~ domain) }}
    - require:
      - vault: helen_vault_ghost_database

# Admin credentials
helen_vault_ghost_admin:
  vault.write_secret:
    - path: kv/data/helen/{{ environment }}/admin
    - data:
        email: {{ salt['pillar.get']('helen:admin_email', 'admin@' ~ domain) }}
        password: {{ salt['cmd.run']('openssl rand -base64 32 | tr -d "=+/" | cut -c1-25') }}
        name: Administrator
    - require:
      - vault: helen_vault_ghost_mail

# S3 storage configuration (optional)
{% if salt['pillar.get']('helen:s3:enabled', false) %}
helen_vault_ghost_s3:
  vault.write_secret:
    - path: kv/data/helen/{{ environment }}/s3
    - data:
        access_key: {{ salt['pillar.get']('helen:s3:access_key') }}
        secret_key: {{ salt['pillar.get']('helen:s3:secret_key') }}
        bucket: {{ salt['pillar.get']('helen:s3:bucket') }}
        region: {{ salt['pillar.get']('helen:s3:region', 'us-east-1') }}
        asset_host: {{ salt['pillar.get']('helen:s3:asset_host', '') }}
{% endif %}

# Webhook configuration for CI/CD
{% if salt['pillar.get']('helen:enable_webhook', false) %}
helen_vault_ghost_webhook:
  vault.write_secret:
    - path: kv/data/helen/{{ environment }}/webhook
    - data:
        endpoint: /webhooks/helen/{{ environment }}
        secret: {{ salt['cmd.run']('openssl rand -base64 32') }}
        git_repo: {{ salt['pillar.get']('helen:git_repo') }}
        git_branch: {{ salt['pillar.get']('helen:git_branch', 'main') }}
        auto_deploy: true
{% endif %}

{% endif %}