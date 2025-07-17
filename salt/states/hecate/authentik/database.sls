# Setup PostgreSQL database for Authentik

# Generate database passwords and store in Vault
generate_postgres_passwords:
  cmd.run:
    - name: |
        # Generate passwords if they don't exist
        if ! vault kv get secret/hecate/postgres/root_password >/dev/null 2>&1; then
          ROOT_PASS=$(openssl rand -hex 32)
          vault kv put secret/hecate/postgres/root_password value="$ROOT_PASS"
        fi
        
        if ! vault kv get secret/hecate/postgres/password >/dev/null 2>&1; then
          AUTH_PASS=$(openssl rand -hex 32)
          vault kv put secret/hecate/postgres/password value="$AUTH_PASS"
        fi
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200

# Create host volume for PostgreSQL
create_postgres_volume:
  cmd.run:
    - name: |
        # Create Nomad host volume configuration
        cat > /tmp/postgres-volume.hcl << 'EOF'
        host_volume "hecate-postgres" {
          path = "/opt/hecate/postgres/data"
          read_only = false
        }
        EOF
        
        # Add to Nomad client config if not exists
        if ! grep -q "hecate-postgres" /etc/nomad.d/client.hcl; then
          cat /tmp/postgres-volume.hcl >> /etc/nomad.d/client.hcl
          systemctl reload nomad
        fi
    - unless: grep -q "hecate-postgres" /etc/nomad.d/client.hcl

# Create PostgreSQL data directory
postgres_data_directory:
  file.directory:
    - name: /opt/hecate/postgres/data
    - user: 999  # PostgreSQL container user
    - group: 999
    - mode: 700
    - makedirs: True