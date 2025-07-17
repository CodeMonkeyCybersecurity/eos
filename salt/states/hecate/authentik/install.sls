# Install and initialize Authentik

# Generate Authentik secret key
generate_authentik_secret:
  cmd.run:
    - name: |
        if ! vault kv get secret/hecate/authentik/secret_key >/dev/null 2>&1; then
          SECRET_KEY=$(openssl rand -hex 50)
          vault kv put secret/hecate/authentik/secret_key value="$SECRET_KEY"
        fi
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200

# Wait for database to be ready
wait_for_database:
  cmd.run:
    - name: |
        for i in {1..60}; do
          if nc -z hecate-postgres.service.consul 5432; then
            echo "Database is ready"
            exit 0
          fi
          echo "Waiting for database..."
          sleep 5
        done
        exit 1

# Initialize Authentik database
initialize_authentik_db:
  cmd.run:
    - name: |
        # Wait for Authentik to create tables
        sleep 30
        
        # Check if admin user exists
        ADMIN_EXISTS=$(nomad exec -job hecate-authentik-server ak list_users | grep -c akadmin || true)
        
        if [ "$ADMIN_EXISTS" -eq 0 ]; then
          # Create initial admin user
          ADMIN_PASS=$(openssl rand -hex 16)
          nomad exec -job hecate-authentik-server ak create_admin_user --username akadmin --password "$ADMIN_PASS"
          
          # Store admin password in Vault
          vault kv put secret/hecate/authentik/admin username="akadmin" password="$ADMIN_PASS"
          
          echo "Admin user created"
        else
          echo "Admin user already exists"
        fi
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200
    - require:
      - cmd: wait_for_database

# Create default Authentik provider for Caddy
create_caddy_provider:
  cmd.run:
    - name: |
        # Get admin credentials
        ADMIN_USER=$(vault kv get -field=username secret/hecate/authentik/admin)
        ADMIN_PASS=$(vault kv get -field=password secret/hecate/authentik/admin)
        
        # Get auth token
        TOKEN=$(curl -s -X POST http://localhost:9000/api/v3/core/tokens/ \
          -H "Content-Type: application/json" \
          -d "{\"identifier\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq -r .key)
        
        if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
          echo "Failed to get auth token"
          exit 1
        fi
        
        # Store API token
        vault kv put secret/hecate/authentik/api_token value="$TOKEN"
        
        # Create Caddy forward auth provider
        curl -s -X POST http://localhost:9000/api/v3/providers/proxy/ \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d '{
            "name": "caddy-forward-auth",
            "authorization_flow": "default-provider-authorization-implicit-consent",
            "mode": "forward_single",
            "external_host": "https://auth.{{ grains.domain | default("example.com") }}"
          }'
        
        echo "Caddy provider created"
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200
    - unless: vault kv get secret/hecate/authentik/api_token
    - require:
      - cmd: initialize_authentik_db