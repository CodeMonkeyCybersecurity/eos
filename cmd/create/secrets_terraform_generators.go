// cmd/create/terraform_vault_generators.go

package create

import (
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var generateVaultK3sCmd = &cobra.Command{
	Use:   "vault-k3s [directory]",
	Short: "Generate Vault-integrated K3s Terraform configuration",
	Long: `Generate a complete K3s cluster deployment with Vault integration.
This creates Terraform configuration that:
- Retrieves Hetzner API token from Vault
- Uses Vault-stored SSH keys
- Stores cluster information back to Vault
- Includes proper firewall and networking`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputDir := "./terraform-vault-k3s"
		if len(args) > 0 {
			outputDir = args[0]
		}

		// Get flags
		clusterName, _ := cmd.Flags().GetString("cluster-name")
		nodeCount, _ := cmd.Flags().GetInt("node-count")
		serverType, _ := cmd.Flags().GetString("server-type")
		location, _ := cmd.Flags().GetString("location")
		sshKeyName, _ := cmd.Flags().GetString("ssh-key")
		vaultAddr, _ := cmd.Flags().GetString("vault-addr")
		secretsMount, _ := cmd.Flags().GetString("secrets-mount")

		if vaultAddr == "" {
			vaultAddr = os.Getenv("VAULT_ADDR")
			if vaultAddr == "" {
				vaultAddr = fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault)
			}
		}

		logger.Info("Generating Vault-integrated K3s configuration",
			zap.String("output_dir", outputDir),
			zap.String("cluster_name", clusterName))

		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		tfManager := terraform.NewManager(rc, outputDir)

		// Prepare template data
		templateData := terraform.VaultTemplateData{
			VaultAddr:    vaultAddr,
			SecretsMount: secretsMount,
			ClusterName:  clusterName,
			NodeCount:    nodeCount,
			ServerType:   serverType,
			Location:     location,
			SSHKeyName:   sshKeyName,
		}

		// Generate main K3s configuration
		if err := tfManager.GenerateFromString(terraform.K3sVaultTemplate, "main.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate main.tf: %w", err)
		}

		// Generate cloud-init for server
		serverCloudInit := terraform.VaultK3sServerCloudInit
		if err := tfManager.GenerateFromString(serverCloudInit, "k3s-server-init.yaml", templateData); err != nil {
			return fmt.Errorf("failed to generate server cloud-init: %w", err)
		}

		// Generate cloud-init for agents
		agentCloudInit := terraform.VaultK3sAgentCloudInit
		if err := tfManager.GenerateFromString(agentCloudInit, "k3s-agent-init.yaml", templateData); err != nil {
			return fmt.Errorf("failed to generate agent cloud-init: %w", err)
		}

		// Generate variables file
		if err := generateVaultK3sVariables(outputDir, templateData); err != nil {
			return fmt.Errorf("failed to generate variables: %w", err)
		}

		// Generate example secrets setup script
		if err := generateVaultSecretsSetup(outputDir, templateData); err != nil {
			return fmt.Errorf("failed to generate secrets setup script: %w", err)
		}

		logger.Info("Vault-integrated K3s configuration generated successfully",
			zap.String("directory", outputDir))

		fmt.Printf(" K3s configuration with Vault integration generated in: %s\n", outputDir)
		fmt.Printf(" Next steps:\n")
		fmt.Printf("   1. Review and customize the generated configuration\n")
		fmt.Printf("   2. Run: ./setup-vault-secrets.sh to configure Vault secrets\n")
		fmt.Printf("   3. Deploy with: eos create terraform-vault %s --vault-secrets\n", outputDir)

		return nil
	}),
}

var generateVaultHetznerCmd = &cobra.Command{
	Use:   "vault-hetzner [directory]",
	Short: "Generate Vault-integrated Hetzner server Terraform configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputDir := "./terraform-vault-hetzner"
		if len(args) > 0 {
			outputDir = args[0]
		}

		// Get flags
		serverName, _ := cmd.Flags().GetString("server-name")
		serverType, _ := cmd.Flags().GetString("server-type")
		location, _ := cmd.Flags().GetString("location")
		sshKeyName, _ := cmd.Flags().GetString("ssh-key")
		vaultAddr, _ := cmd.Flags().GetString("vault-addr")
		secretsMount, _ := cmd.Flags().GetString("secrets-mount")
		projectName, _ := cmd.Flags().GetString("project-name")

		if vaultAddr == "" {
			vaultAddr = os.Getenv("VAULT_ADDR")
			if vaultAddr == "" {
				vaultAddr = fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault)
			}
		}

		logger.Info("Generating Vault-integrated Hetzner configuration",
			zap.String("output_dir", outputDir),
			zap.String("server_name", serverName))

		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		tfManager := terraform.NewManager(rc, outputDir)

		// Prepare template data
		templateData := terraform.VaultTemplateData{
			VaultAddr:    vaultAddr,
			SecretsMount: secretsMount,
			ProjectName:  projectName,
			ServerName:   serverName,
			ServerType:   serverType,
			Location:     location,
			SSHKeyName:   sshKeyName,
		}

		// Generate main Hetzner configuration
		if err := tfManager.GenerateFromString(terraform.HetznerVaultTemplate, "main.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate main.tf: %w", err)
		}

		// Generate cloud-init
		if err := generateHetznerCloudInit(outputDir); err != nil {
			return fmt.Errorf("failed to generate cloud-init: %w", err)
		}

		// Generate variables file
		if err := generateVaultHetznerVariables(outputDir, templateData); err != nil {
			return fmt.Errorf("failed to generate variables: %w", err)
		}

		// Generate example secrets setup script
		if err := generateVaultSecretsSetup(outputDir, templateData); err != nil {
			return fmt.Errorf("failed to generate secrets setup script: %w", err)
		}

		logger.Info("Vault-integrated Hetzner configuration generated successfully",
			zap.String("directory", outputDir))

		fmt.Printf(" Hetzner configuration with Vault integration generated in: %s\n", outputDir)

		return nil
	}),
}

// TODO
// Helper functions
func generateVaultK3sVariables(outputDir string, data terraform.VaultTemplateData) error {
	variables := fmt.Sprintf(`
variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "%s"
}

variable "vault_token" {
  description = "Vault authentication token"
  type        = string
  sensitive   = true
}

variable "cluster_name" {
  description = "K3s cluster name"
  type        = string
  default     = "%s"
}

variable "node_count" {
  description = "Number of K3s nodes (including server)"
  type        = number
  default     = %d
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "%s"
}

variable "location" {
  description = "Hetzner location"
  type        = string
  default     = "%s"
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
  default     = "%s"
}
`, data.VaultAddr, data.ClusterName, data.NodeCount, data.ServerType, data.Location, data.SSHKeyName)

	return os.WriteFile(filepath.Join(outputDir, "variables.tf"), []byte(variables), 0644)
}

// TODO
func generateVaultHetznerVariables(outputDir string, data terraform.VaultTemplateData) error {
	variables := fmt.Sprintf(`
variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "%s"
}

variable "vault_token" {
  description = "Vault authentication token"
  type        = string
  sensitive   = true
}

variable "server_name" {
  description = "Server name"
  type        = string
  default     = "%s"
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "%s"
}

variable "location" {
  description = "Hetzner location"
  type        = string
  default     = "%s"
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
  default     = "%s"
}
`, data.VaultAddr, data.ServerName, data.ServerType, data.Location, data.SSHKeyName)

	return os.WriteFile(filepath.Join(outputDir, "variables.tf"), []byte(variables), 0644)
}

// TODO
func generateHetznerCloudInit(outputDir string) error {
	cloudInit := `#cloud-config
package_update: true
package_upgrade: true

packages:
  - curl
  - wget
  - git
  - htop
  - ufw

users:
  - name: admin
    groups: sudo
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - ${ssh_public_key}

runcmd:
  - ufw --force enable
  - ufw allow ssh
  - systemctl enable ufw
  - echo "Server setup completed" > /var/log/setup.log
`

	return os.WriteFile(filepath.Join(outputDir, "cloud-init.yaml"), []byte(cloudInit), 0644)
}

// TODO
func generateVaultSecretsSetup(outputDir string, data terraform.VaultTemplateData) error {
	script := fmt.Sprintf(`#!/bin/bash
# Setup Vault secrets for Terraform deployment

set -e

VAULT_ADDR="%s"
SECRETS_MOUNT="%s"

echo "Setting up Vault secrets for Terraform..."

# Check if vault CLI is available
if ! command -v vault &> /dev/null; then
    echo "Error: vault CLI is not installed"
    echo "Please install vault CLI first: eos create hcl vault"
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

# For K3s clusters, generate and store K3s token
if [[ "%s" == *"k3s"* ]]; then
    K3S_TOKEN=$(openssl rand -hex 32)
    echo "Storing K3s token..."
    vault kv put "$SECRETS_MOUNT/k3s" token="$K3S_TOKEN"
fi

echo " Vault secrets setup completed!"
echo "You can now run: eos create terraform-vault . --vault-secrets"
`, data.VaultAddr, data.SecretsMount, outputDir)

	scriptPath := filepath.Join(outputDir, "setup-vault-secrets.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return err
	}

	return nil
}

func init() {
	CreateCmd.AddCommand(generateVaultK3sCmd)
	CreateCmd.AddCommand(generateVaultHetznerCmd)

	// Vault K3s flags
	generateVaultK3sCmd.Flags().String("cluster-name", "k3s-cluster", "K3s cluster name")
	generateVaultK3sCmd.Flags().Int("node-count", 3, "Number of K3s nodes")
	generateVaultK3sCmd.Flags().String("server-type", "cx21", "Hetzner server type")
	generateVaultK3sCmd.Flags().String("location", "nbg1", "Hetzner location")
	generateVaultK3sCmd.Flags().String("ssh-key", "default", "SSH key name in Hetzner")
	generateVaultK3sCmd.Flags().String("vault-addr", "", "Vault server address")
	generateVaultK3sCmd.Flags().String("secrets-mount", "terraform", "Vault secrets mount path")

	// Vault Hetzner flags
	generateVaultHetznerCmd.Flags().String("server-name", "hetzner-server", "Server name")
	generateVaultHetznerCmd.Flags().String("server-type", "cx21", "Hetzner server type")
	generateVaultHetznerCmd.Flags().String("location", "nbg1", "Hetzner location")
	generateVaultHetznerCmd.Flags().String("ssh-key", "default", "SSH key name in Hetzner")
	generateVaultHetznerCmd.Flags().String("vault-addr", "", "Vault server address")
	generateVaultHetznerCmd.Flags().String("secrets-mount", "terraform", "Vault secrets mount path")
	generateVaultHetznerCmd.Flags().String("project-name", "hetzner-project", "Project name for labeling")
}
