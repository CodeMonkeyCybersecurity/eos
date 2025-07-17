# Create Vault secrets for Hecate components
# This state creates all necessary secrets in Vault before deploying services

{% set vault_addr = salt['environ.get']('VAULT_ADDR', 'http://127.0.0.1:8200') %}

# Generate random passwords for services
hecate_generate_passwords:
  cmd.run:
    - names:
      - |
        # Generate PostgreSQL passwords
        POSTGRES_ROOT_PASS=$(openssl rand -base64 32)
        POSTGRES_USER_PASS=$(openssl rand -base64 32)
        
        # Generate Redis password
        REDIS_PASS=$(openssl rand -base64 32)
        
        # Generate Authentik secret key
        AUTHENTIK_SECRET=$(openssl rand -hex 32)
        
        # Generate Authentik admin password
        AUTHENTIK_ADMIN_PASS=$(openssl rand -base64 16)
        
        # Store in Vault
        vault kv put secret/hecate/postgres/root_password value="$POSTGRES_ROOT_PASS"
        vault kv put secret/hecate/postgres/password value="$POSTGRES_USER_PASS"
        vault kv put secret/hecate/redis/password value="$REDIS_PASS"
        vault kv put secret/hecate/authentik/secret_key value="$AUTHENTIK_SECRET"
        vault kv put secret/hecate/authentik/admin username="akadmin" password="$AUTHENTIK_ADMIN_PASS"
    - env:
      - VAULT_ADDR: {{ vault_addr }}
    - unless: vault kv get secret/hecate/postgres/root_password

# Create additional configuration secrets
hecate_vault_config:
  cmd.run:
    - names:
      - |
        # Store database configuration
        vault kv put secret/hecate/postgres/config \
          host="hecate-postgres.service.consul" \
          port="5432" \
          database="authentik" \
          user="authentik"
        
        # Store Redis configuration
        vault kv put secret/hecate/redis/config \
          host="hecate-redis.service.consul" \
          port="6379"
        
        # Store Caddy configuration
        vault kv put secret/hecate/caddy/config \
          admin_port="2019" \
          http_port="80" \
          https_port="443"
    - env:
      - VAULT_ADDR: {{ vault_addr }}
    - require:
      - cmd: hecate_generate_passwords