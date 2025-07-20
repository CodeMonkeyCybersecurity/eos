# Hecate Secrets Pillar
# This pillar contains auto-generated secrets for Hecate services
# Used as fallback when Vault is not available

{#- Use our custom random module for secure generation -#}
{%- set redis_password = salt['eos_random.get_or_create']('hecate_redis_password', 32) -%}

hecate:
  secrets:
    # PostgreSQL secrets
    postgres:
      root_password: {{ salt['eos_random.get_or_create']('hecate_postgres_root', 32) }}
      user_password: {{ salt['eos_random.get_or_create']('hecate_postgres_user', 32) }}
      database: "authentik"
      username: "authentik"
      host: "hecate-postgres.service.consul"
      port: 5432
    
    # Redis secrets
    redis:
      password: {{ redis_password }}
      host: "hecate-redis.service.consul"
      port: 6379
    
    # Authentik secrets
    authentik:
      secret_key: {{ salt['eos_random.get_or_create']('hecate_authentik_secret', 64) }}
      admin:
        username: "akadmin"
        password: {{ salt['eos_random.get_or_create']('hecate_authentik_admin', 16) }}
      redis_password: {{ redis_password }}
    
    # Caddy configuration
    caddy:
      admin_port: 2019
      http_port: 80
      https_port: 443
    
    # TLS/Certificate configuration
    tls:
      country: "AU"
      state: "NSW" 
      city: "Sydney"
      organization: "Code Monkey Cybersecurity"
      organizational_unit: "IT Department"
      
  # Metadata about secret generation
  meta:
    generated_at: "pillar-render-time"
    generated_by: "salt-pillar"
    vault_fallback: true
    version: "1.0"