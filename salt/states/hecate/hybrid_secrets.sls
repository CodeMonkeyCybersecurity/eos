# Hecate Hybrid Secret Management
# This state tries Vault first, falls back to Salt pillar secrets if Vault is unavailable
# Provides a consistent interface for secret management regardless of backend

{% set vault_addr = salt['environ.get']('VAULT_ADDR', 'https://127.0.0.1:8179') %}
{% set use_vault = salt['cmd.retcode']('vault status', env={'VAULT_ADDR': vault_addr}) == 0 %}

{% if use_vault %}
# Vault is available - use Vault-based secret management
hecate_secrets_vault_mode:
  cmd.run:
    - name: echo "Using Vault for secret management"
    
include:
  - hecate.vault_secrets

{% else %}
# Vault not available - use Salt pillar secret management
hecate_secrets_salt_mode:
  cmd.run:
    - name: echo "Using Salt pillar for secret management (Vault fallback)"

# Generate secrets directory for storing generated secrets
hecate_secrets_directory:
  file.directory:
    - name: /opt/hecate/secrets
    - mode: 700
    - makedirs: True

# Store PostgreSQL secrets
hecate_postgres_secrets:
  file.managed:
    - name: /opt/hecate/secrets/postgres.env
    - mode: 600
    - contents: |
        POSTGRES_ROOT_PASSWORD={{ pillar['hecate']['secrets']['postgres']['root_password'] }}
        POSTGRES_PASSWORD={{ pillar['hecate']['secrets']['postgres']['user_password'] }}
        POSTGRES_DB={{ pillar['hecate']['secrets']['postgres']['database'] }}
        POSTGRES_USER={{ pillar['hecate']['secrets']['postgres']['username'] }}
        POSTGRES_HOST={{ pillar['hecate']['secrets']['postgres']['host'] }}
        POSTGRES_PORT={{ pillar['hecate']['secrets']['postgres']['port'] }}
    - require:
      - file: hecate_secrets_directory

# Store Redis secrets
hecate_redis_secrets:
  file.managed:
    - name: /opt/hecate/secrets/redis.env
    - mode: 600
    - contents: |
        REDIS_PASSWORD={{ pillar['hecate']['secrets']['redis']['password'] }}
        REDIS_HOST={{ pillar['hecate']['secrets']['redis']['host'] }}
        REDIS_PORT={{ pillar['hecate']['secrets']['redis']['port'] }}
    - require:
      - file: hecate_secrets_directory

# Store Authentik secrets
hecate_authentik_secrets:
  file.managed:
    - name: /opt/hecate/secrets/authentik.env
    - mode: 600
    - contents: |
        AUTHENTIK_SECRET_KEY={{ pillar['hecate']['secrets']['authentik']['secret_key'] }}
        AUTHENTIK_REDIS_PASSWORD={{ pillar['hecate']['secrets']['authentik']['redis_password'] }}
        AUTHENTIK_ADMIN_USERNAME={{ pillar['hecate']['secrets']['authentik']['admin']['username'] }}
        AUTHENTIK_ADMIN_PASSWORD={{ pillar['hecate']['secrets']['authentik']['admin']['password'] }}
    - require:
      - file: hecate_secrets_directory

# Store Caddy configuration
hecate_caddy_config:
  file.managed:
    - name: /opt/hecate/secrets/caddy.env
    - mode: 600
    - contents: |
        CADDY_ADMIN_PORT={{ pillar['hecate']['secrets']['caddy']['admin_port'] }}
        CADDY_HTTP_PORT={{ pillar['hecate']['secrets']['caddy']['http_port'] }}
        CADDY_HTTPS_PORT={{ pillar['hecate']['secrets']['caddy']['https_port'] }}
    - require:
      - file: hecate_secrets_directory

# Create a secrets summary for debugging
hecate_secrets_summary:
  file.managed:
    - name: /opt/hecate/secrets/summary.yaml
    - mode: 600
    - contents: |
        # Hecate Secrets Summary
        # Generated: {{ pillar['hecate']['meta']['generated_at'] }}
        # Backend: Salt Pillar (Vault fallback)
        
        secret_backend: "salt-pillar"
        vault_available: false
        secrets_generated: true
        
        services:
          postgres:
            host: {{ pillar['hecate']['secrets']['postgres']['host'] }}
            port: {{ pillar['hecate']['secrets']['postgres']['port'] }}
            database: {{ pillar['hecate']['secrets']['postgres']['database'] }}
            username: {{ pillar['hecate']['secrets']['postgres']['username'] }}
            password_set: true
            
          redis:
            host: {{ pillar['hecate']['secrets']['redis']['host'] }}
            port: {{ pillar['hecate']['secrets']['redis']['port'] }}
            password_set: true
            
          authentik:
            admin_username: {{ pillar['hecate']['secrets']['authentik']['admin']['username'] }}
            secret_key_set: true
            admin_password_set: true
            
          caddy:
            admin_port: {{ pillar['hecate']['secrets']['caddy']['admin_port'] }}
            http_port: {{ pillar['hecate']['secrets']['caddy']['http_port'] }}
            https_port: {{ pillar['hecate']['secrets']['caddy']['https_port'] }}
    - require:
      - file: hecate_secrets_directory

{% endif %}

# Create a unified secrets interface script
hecate_secrets_interface:
  file.managed:
    - name: /opt/hecate/bin/get-secret.sh
    - mode: 755
    - makedirs: True
    - contents: |
        #!/bin/bash
        # Hecate Unified Secrets Interface
        # Usage: get-secret.sh <service> <key>
        # Examples: 
        #   get-secret.sh postgres password
        #   get-secret.sh authentik admin_password
        
        SERVICE="$1"
        KEY="$2"
        
        if [ -z "$SERVICE" ] || [ -z "$KEY" ]; then
            echo "Usage: $0 <service> <key>" >&2
            exit 1
        fi
        
        {% if use_vault %}
        # Vault mode
        case "$SERVICE" in
            postgres)
                case "$KEY" in
                    password) vault kv get -field=value secret/hecate/postgres/password ;;
                    root_password) vault kv get -field=value secret/hecate/postgres/root_password ;;
                    *) echo "Unknown postgres key: $KEY" >&2; exit 1 ;;
                esac
                ;;
            redis)
                case "$KEY" in
                    password) vault kv get -field=value secret/hecate/redis/password ;;
                    *) echo "Unknown redis key: $KEY" >&2; exit 1 ;;
                esac
                ;;
            authentik)
                case "$KEY" in
                    secret_key) vault kv get -field=value secret/hecate/authentik/secret_key ;;
                    admin_password) vault kv get -field=password secret/hecate/authentik/admin ;;
                    admin_username) vault kv get -field=username secret/hecate/authentik/admin ;;
                    *) echo "Unknown authentik key: $KEY" >&2; exit 1 ;;
                esac
                ;;
            *) echo "Unknown service: $SERVICE" >&2; exit 1 ;;
        esac
        {% else %}
        # Salt pillar mode
        case "$SERVICE" in
            postgres)
                case "$KEY" in
                    password) grep "^POSTGRES_PASSWORD=" /opt/hecate/secrets/postgres.env | cut -d'=' -f2 ;;
                    root_password) grep "^POSTGRES_ROOT_PASSWORD=" /opt/hecate/secrets/postgres.env | cut -d'=' -f2 ;;
                    *) echo "Unknown postgres key: $KEY" >&2; exit 1 ;;
                esac
                ;;
            redis)
                case "$KEY" in
                    password) grep "^REDIS_PASSWORD=" /opt/hecate/secrets/redis.env | cut -d'=' -f2 ;;
                    *) echo "Unknown redis key: $KEY" >&2; exit 1 ;;
                esac
                ;;
            authentik)
                case "$KEY" in
                    secret_key) grep "^AUTHENTIK_SECRET_KEY=" /opt/hecate/secrets/authentik.env | cut -d'=' -f2 ;;
                    admin_password) grep "^AUTHENTIK_ADMIN_PASSWORD=" /opt/hecate/secrets/authentik.env | cut -d'=' -f2 ;;
                    admin_username) grep "^AUTHENTIK_ADMIN_USERNAME=" /opt/hecate/secrets/authentik.env | cut -d'=' -f2 ;;
                    *) echo "Unknown authentik key: $KEY" >&2; exit 1 ;;
                esac
                ;;
            *) echo "Unknown service: $SERVICE" >&2; exit 1 ;;
        esac
        {% endif %}