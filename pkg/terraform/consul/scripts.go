package consul

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ScriptData holds data for script generation
type ScriptData struct {
	VaultAddr        string
	SecretsMount     string
	ConsulDatacenter string
}

// GenerateVaultSecretsSetup generates the setup script for Vault and Consul secrets
// Migrated from cmd/create/consul_terraform.go generateConsulVaultSecretsSetup
func GenerateVaultSecretsSetup(rc *eos_io.RuntimeContext, outputDir string, data *ScriptData) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate input parameters
	log.Info("Assessing Vault secrets setup script generation requirements",
		zap.String("output_dir", outputDir),
		zap.String("vault_addr", data.VaultAddr))

	if err := os.MkdirAll(outputDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// INTERVENE - Generate setup script
	log.Info("Generating Vault and Consul secrets setup script")

	script := fmt.Sprintf(`#!/bin/bash
# Setup Vault and Consul secrets for Terraform deployment

set -e

VAULT_ADDR="%s"
SECRETS_MOUNT="%s"

echo "Setting up Vault and Consul secrets for Terraform..."

# Check if vault CLI is available
if ! command -v vault &> /dev/null; then
    echo "Error: vault CLI is not installed"
    echo "Please install vault CLI first: eos create hcl vault"
    exit 1
fi

# Check if consul CLI is available
if ! command -v consul &> /dev/null; then
    echo "Error: consul CLI is not installed"
    echo "Please install consul CLI first: eos create hcl consul"
    exit 1
fi

# Check if we're authenticated to Vault
if ! vault auth -method=token > /dev/null 2>&1; then
    echo "Error: Not authenticated to Vault"
    echo "Please authenticate first: vault auth -method=userpass username=<your-username>"
    exit 1
fi

# Create secrets engine if it doesn't exist
echo "Creating secrets engine: $SECRETS_MOUNT"
vault secrets enable -path="$SECRETS_MOUNT" kv-v2 || echo "Secrets engine already exists"

# Prompt for secrets
echo "Please provide the following secrets:"

read -p "Hetzner Cloud API Token: " -s HETZNER_TOKEN
echo
read -p "SSH Public Key (full key): " SSH_PUBLIC_KEY
read -p "SSH Private Key Path (optional): " SSH_PRIVATE_KEY_PATH

# Generate Consul encrypt key
CONSUL_ENCRYPT_KEY=$(consul keygen)

# Store Hetzner token
echo "Storing Hetzner token..."
vault kv put "$SECRETS_MOUNT/hetzner" token="$HETZNER_TOKEN"

# Store SSH keys
echo "Storing SSH keys..."
if [[ -n "$SSH_PRIVATE_KEY_PATH" && -f "$SSH_PRIVATE_KEY_PATH" ]]; then
    SSH_PRIVATE_KEY=$(cat "$SSH_PRIVATE_KEY_PATH")
    vault kv put "$SECRETS_MOUNT/ssh" \
        public_key="$SSH_PUBLIC_KEY" \
        private_key="$SSH_PRIVATE_KEY"
else
    vault kv put "$SECRETS_MOUNT/ssh" public_key="$SSH_PUBLIC_KEY"
fi

# Store Consul configuration
echo "Storing Consul configuration..."
vault kv put "$SECRETS_MOUNT/consul" \
    encrypt_key="$CONSUL_ENCRYPT_KEY" \
    datacenter="%s"

echo " Vault and Consul secrets setup completed!"
echo "Generated Consul encrypt key: $CONSUL_ENCRYPT_KEY"
echo "You can now run: eos create consul-vault . --services --consul-kv"
`, data.VaultAddr, data.SecretsMount, data.ConsulDatacenter)

	scriptPath := filepath.Join(outputDir, "setup-consul-vault-secrets.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("failed to write setup script: %w", err)
	}

	// EVALUATE - Verify script was created with correct permissions
	log.Info("Evaluating setup script generation")

	info, err := os.Stat(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to verify setup script: %w", err)
	}

	if info.Mode().Perm() != 0755 {
		log.Warn("Setup script permissions not as expected",
			zap.String("expected", "0755"),
			zap.String("actual", info.Mode().Perm().String()))
	}

	log.Info("Vault and Consul secrets setup script generated successfully",
		zap.String("path", scriptPath),
		zap.String("datacenter", data.ConsulDatacenter),
		zap.String("secrets_mount", data.SecretsMount))

	return nil
}
