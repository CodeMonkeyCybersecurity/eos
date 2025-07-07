# salt/states/minio/vault_policy.sls
# MinIO Vault integration and policy management

{% set minio = pillar.get('minio', {}) %}
{% set vault = pillar.get('vault', {}) %}

# MinIO Vault policy content
minio_vault_policy_content:
  file.managed:
    - name: /opt/minio/minio-policy.hcl
    - contents: |
        # MinIO Vault Policy
        # Allows MinIO to read its credentials from Vault
        
        # Read MinIO root credentials
        path "kv/data/minio/root" {
          capabilities = ["read"]
        }
        
        # Read MinIO configuration secrets
        path "kv/data/minio/*" {
          capabilities = ["read"]
        }
        
        # Allow listing of MinIO secrets
        path "kv/metadata/minio/*" {
          capabilities = ["list", "read"]
        }
        
        # Token self-renewal
        path "auth/token/renew-self" {
          capabilities = ["update"]
        }
        
        # Token lookup (for validation)
        path "auth/token/lookup-self" {
          capabilities = ["read"]
        }
    - mode: 644
    - makedirs: True

# Install MinIO Vault policy (only if Vault is available)
minio_vault_policy_install:
  cmd.run:
    - name: |
        if command -v vault >/dev/null 2>&1; then
            # Check if Vault is reachable
            if vault status >/dev/null 2>&1; then
                echo "Installing MinIO Vault policy..."
                vault policy write minio-policy /opt/minio/minio-policy.hcl
                echo "MinIO Vault policy installed successfully"
            else
                echo "Warning: Vault is not accessible, skipping policy installation"
                exit 0
            fi
        else
            echo "Warning: Vault CLI not found, skipping policy installation"
            exit 0
        fi
    - require:
      - file: minio_vault_policy_content
    - unless: |
        # Skip if vault is not available or policy already exists
        if ! command -v vault >/dev/null 2>&1; then
            exit 0  # Skip if vault not available
        fi
        if ! vault status >/dev/null 2>&1; then
            exit 0  # Skip if vault not reachable
        fi
        vault policy read minio-policy >/dev/null 2>&1  # Skip if policy exists

# Generate initial MinIO credentials in Vault (if Vault is available)
minio_vault_credentials_setup:
  cmd.run:
    - name: |
        if command -v vault >/dev/null 2>&1; then
            if vault status >/dev/null 2>&1; then
                # Check if credentials already exist
                if ! vault kv get kv/minio/root >/dev/null 2>&1; then
                    echo "Setting up initial MinIO credentials in Vault..."
                    
                    # Generate secure password
                    MINIO_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
                    
                    # Store in Vault
                    vault kv put kv/minio/root \
                        MINIO_ROOT_USER="minioadmin" \
                        MINIO_ROOT_PASSWORD="$MINIO_PASSWORD"
                    
                    echo "MinIO credentials stored in Vault at kv/minio/root"
                    echo "To retrieve: vault kv get kv/minio/root"
                else
                    echo "MinIO credentials already exist in Vault"
                fi
            else
                echo "Warning: Vault is not accessible, skipping credential setup"
                exit 0
            fi
        else
            echo "Warning: Vault CLI not found, skipping credential setup"
            exit 0
        fi
    - require:
      - cmd: minio_vault_policy_install

# Create Vault token for MinIO service (if Vault is available)
minio_vault_service_token:
  cmd.run:
    - name: |
        if command -v vault >/dev/null 2>&1; then
            if vault status >/dev/null 2>&1; then
                # Create a renewable token for MinIO service
                echo "Creating service token for MinIO..."
                vault token create \
                    -policy=minio-policy \
                    -renewable=true \
                    -ttl=24h \
                    -display-name="minio-service" \
                    -format=json > /opt/minio/vault-token.json
                
                # Extract just the token for easy use
                vault write -format=json auth/token/create \
                    policies="minio-policy" \
                    renewable=true \
                    ttl="24h" \
                    display_name="minio-service" | \
                    jq -r '.auth.client_token' > /opt/minio/vault-token.txt
                
                # Secure the token files
                chown minio:minio /opt/minio/vault-token.*
                chmod 600 /opt/minio/vault-token.*
                
                echo "MinIO service token created and saved to /opt/minio/vault-token.txt"
            else
                echo "Warning: Vault is not accessible, skipping token creation"
                exit 0
            fi
        else
            echo "Warning: Vault CLI not found, skipping token creation"
            exit 0
        fi
    - require:
      - cmd: minio_vault_credentials_setup
    - unless: test -f /opt/minio/vault-token.txt

# Create helper script for Vault operations
minio_vault_helper_script:
  file.managed:
    - name: /opt/minio/vault-helper.sh
    - contents: |
        #!/bin/bash
        # MinIO Vault Helper Script
        
        VAULT_TOKEN_FILE="/opt/minio/vault-token.txt"
        
        # Function to check if Vault is available
        check_vault() {
            if ! command -v vault >/dev/null 2>&1; then
                echo "Error: Vault CLI not found"
                return 1
            fi
            
            if ! vault status >/dev/null 2>&1; then
                echo "Error: Vault is not accessible"
                return 1
            fi
            
            return 0
        }
        
        # Function to get MinIO credentials
        get_credentials() {
            if ! check_vault; then
                return 1
            fi
            
            if [[ -f "$VAULT_TOKEN_FILE" ]]; then
                export VAULT_TOKEN=$(cat "$VAULT_TOKEN_FILE")
            fi
            
            echo "MinIO Credentials from Vault:"
            vault kv get kv/minio/root
        }
        
        # Function to renew service token
        renew_token() {
            if ! check_vault; then
                return 1
            fi
            
            if [[ -f "$VAULT_TOKEN_FILE" ]]; then
                export VAULT_TOKEN=$(cat "$VAULT_TOKEN_FILE")
                vault token renew
                echo "Token renewed successfully"
            else
                echo "Error: Token file not found at $VAULT_TOKEN_FILE"
                return 1
            fi
        }
        
        # Function to rotate MinIO password
        rotate_password() {
            if ! check_vault; then
                return 1
            fi
            
            if [[ -f "$VAULT_TOKEN_FILE" ]]; then
                export VAULT_TOKEN=$(cat "$VAULT_TOKEN_FILE")
            fi
            
            echo "Rotating MinIO password..."
            NEW_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
            
            vault kv put kv/minio/root \
                MINIO_ROOT_USER="minioadmin" \
                MINIO_ROOT_PASSWORD="$NEW_PASSWORD"
            
            echo "Password rotated successfully"
            echo "You will need to restart MinIO to use the new password"
        }
        
        # Main command handling
        case "$1" in
            "get-credentials"|"creds")
                get_credentials
                ;;
            "renew-token"|"renew")
                renew_token
                ;;
            "rotate-password"|"rotate")
                rotate_password
                ;;
            *)
                echo "Usage: $0 {get-credentials|renew-token|rotate-password}"
                echo "  get-credentials : Display MinIO credentials from Vault"
                echo "  renew-token     : Renew the MinIO service token"
                echo "  rotate-password : Generate new MinIO password"
                exit 1
                ;;
        esac
    - mode: 755
    - user: minio
    - group: minio
    - require:
      - cmd: minio_vault_service_token