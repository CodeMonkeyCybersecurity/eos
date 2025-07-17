# Prerequisites for Hecate deployment
# Ensures all required system components are in place

# Create Hecate directories
hecate_directories:
  file.directory:
    - names:
      - /opt/hecate
      - /opt/hecate/caddy
      - /opt/hecate/caddy/data
      - /opt/hecate/caddy/config
      - /opt/hecate/caddy/routes
      - /opt/hecate/authentik
      - /opt/hecate/authentik/media
      - /opt/hecate/authentik/templates
      - /opt/hecate/authentik/certs
      - /opt/hecate/nomad
      - /opt/hecate/nomad/jobs
    - user: root
    - group: root
    - mode: 755
    - makedirs: True

# Ensure Docker network exists for Hecate
hecate_docker_network:
  cmd.run:
    - name: docker network create hecate-network --driver bridge --subnet 172.28.0.0/16 || true
    - unless: docker network inspect hecate-network

# Check for required services
check_nomad_service:
  service.running:
    - name: nomad
    - enable: True

check_consul_service:
  service.running:
    - name: consul
    - enable: True

check_vault_service:
  service.running:
    - name: vault
    - enable: True

# Create Vault policies for Hecate
hecate_vault_policy:
  cmd.run:
    - name: |
        vault policy write hecate-policy - <<EOF
        path "secret/data/hecate/*" {
          capabilities = ["create", "read", "update", "delete", "list"]
        }
        path "secret/metadata/hecate/*" {
          capabilities = ["list", "read", "delete"]
        }
        path "pki/issue/hecate" {
          capabilities = ["create", "update"]
        }
        EOF
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200
    - unless: vault policy read hecate-policy

# Create initial configuration file
hecate_initial_config:
  file.managed:
    - name: /opt/hecate/config.yaml
    - contents: |
        version: "1.0"
        deployment:
          type: "nomad"
          datacenter: "dc1"
        networking:
          caddy_http_port: 80
          caddy_https_port: 443
          caddy_admin_port: 2019
          authentik_http_port: 9000
          authentik_https_port: 9443
        database:
          host: "hecate-postgres.service.consul"
          port: 5432
          name: "authentik"
          user: "authentik"
        redis:
          host: "hecate-redis.service.consul"
          port: 6379
        authentik:
          secret_key: "{{ salt['random.get_str'](50) }}"
          error_reporting: false
          log_level: "info"
    - mode: 600
    - makedirs: True