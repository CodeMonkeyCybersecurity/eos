# Setup Redis for Authentik

# Generate Redis password and store in Vault
generate_redis_password:
  cmd.run:
    - name: |
        if ! vault kv get secret/hecate/redis/password >/dev/null 2>&1; then
          REDIS_PASS=$(openssl rand -hex 32)
          vault kv put secret/hecate/redis/password value="$REDIS_PASS"
        fi
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200

# Create host volume for Redis
create_redis_volume:
  cmd.run:
    - name: |
        # Create Nomad host volume configuration
        cat > /tmp/redis-volume.hcl << 'EOF'
        host_volume "hecate-redis" {
          path = "/opt/hecate/redis/data"
          read_only = false
        }
        EOF
        
        # Add to Nomad client config if not exists
        if ! grep -q "hecate-redis" /etc/nomad.d/client.hcl; then
          cat /tmp/redis-volume.hcl >> /etc/nomad.d/client.hcl
          systemctl reload nomad
        fi
    - unless: grep -q "hecate-redis" /etc/nomad.d/client.hcl

# Create Redis data directory
redis_data_directory:
  file.directory:
    - name: /opt/hecate/redis/data
    - user: 999  # Redis container user
    - group: 999
    - mode: 700
    - makedirs: True