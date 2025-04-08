#!/bin/bash
set -e

VAULT_AGENT_DIR="/opt/pandora/vault-agent"

# Ensure the directory exists
mkdir -p "$VAULT_AGENT_DIR"

# Generate random Role ID and Secret ID (hex-encoded 32 bytes = 64 chars)
ROLE_ID=$(openssl rand -hex 32)
SECRET_ID=$(openssl rand -hex 32)

# Write them to files
echo "$ROLE_ID" > "$VAULT_AGENT_DIR/role_id"
echo "$SECRET_ID" > "$VAULT_AGENT_DIR/secret_id"

# Set secure permissions
chmod 600 "$VAULT_AGENT_DIR/role_id" "$VAULT_AGENT_DIR/secret_id"
chown 100:100 "$VAULT_AGENT_DIR/role_id" "$VAULT_AGENT_DIR/secret_id"

echo "✅ AppRole credentials generated:"
echo "🔐 Role ID:    $ROLE_ID"
echo "🔐 Secret ID:  $SECRET_ID"
