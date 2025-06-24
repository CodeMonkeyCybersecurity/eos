// cmd/create/terraform_consul.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var terraformConsulVaultCmd = &cobra.Command{
	Use:   "consul-vault [directory]",
	Short: "Deploy infrastructure with integrated Consul, Vault, and Terraform",
	Long: `Deploy Terraform infrastructure with integrated Consul service discovery and Vault secrets management.
This command:
1. Validates Consul and Vault connectivity
2. Sets up Consul KV for configuration management
3. Configures service discovery for deployed services
4. Manages secrets through Vault with Consul coordination
5. Deploys infrastructure with full integration

Example:
  eos create consul-vault ./infrastructure --services --consul-kv`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		// Get flags
		useConsulServices, _ := cmd.Flags().GetBool("services")
		useConsulKV, _ := cmd.Flags().GetBool("consul-kv")
		useVaultSecrets, _ := cmd.Flags().GetBool("vault-secrets")
		consulAddr, _ := cmd.Flags().GetString("consul-addr")
		vaultAddr, _ := cmd.Flags().GetString("vault-addr")
		datacenter, _ := cmd.Flags().GetString("datacenter")
		servicePrefix, _ := cmd.Flags().GetString("service-prefix")
		kvPrefix, _ := cmd.Flags().GetString("kv-prefix")
		autoApprove, _ := cmd.Flags().GetBool("auto-approve")

		if consulAddr == "" {
			consulAddr = os.Getenv("CONSUL_HTTP_ADDR")
			if consulAddr == "" {
				consulAddr = "http://127.0.0.1:8500"
			}
		}

		if vaultAddr == "" {
			vaultAddr = os.Getenv("VAULT_ADDR")
			if vaultAddr == "" {
				vaultAddr = "https://127.0.0.1:8179"
			}
		}

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		// Validate directory
		if _, err := os.Stat(workingDir); os.IsNotExist(err) {
			return fmt.Errorf("directory %s does not exist", workingDir)
		}

		logger.Info("Starting Consul-Vault-Terraform integrated deployment",
			zap.String("directory", workingDir),
			zap.Bool("consul_services", useConsulServices),
			zap.Bool("consul_kv", useConsulKV),
			zap.Bool("vault_secrets", useVaultSecrets))

		// Initialize Terraform manager
		tfManager := terraform.NewManager(rc, workingDir)

		// Step 1: Configure Vault integration
		vaultConfig := terraform.VaultIntegration{
			VaultAddr:     vaultAddr,
			VaultToken:    os.Getenv("VAULT_TOKEN"),
			SecretsPath:   "terraform/secrets",
			BackendPath:   "terraform/state",
			EnableSecrets: useVaultSecrets,
			EnableState:   false, // We'll use Consul for coordination instead
		}

		if err := tfManager.ConfigureVaultIntegration(rc, vaultConfig); err != nil {
			return fmt.Errorf("vault integration setup failed: %w", err)
		}

		// Step 2: Configure Consul integration
		consulConfig := terraform.ConsulIntegration{
			ConsulAddr:      consulAddr,
			ConsulToken:     os.Getenv("CONSUL_HTTP_TOKEN"),
			Datacenter:      datacenter,
			EnableDiscovery: useConsulServices,
			EnableKV:        useConsulKV,
			EnableConnect:   true,
			ServicePrefix:   servicePrefix,
			KVPrefix:        kvPrefix,
		}

		if err := tfManager.ConfigureConsulIntegration(rc, consulConfig); err != nil {
			return fmt.Errorf("consul integration setup failed: %w", err)
		}

		// Step 3: Terraform workflow
		logger.Info("Starting Terraform deployment workflow")

		// Initialize
		logger.Info("Initializing Terraform")
		if err := tfManager.Init(rc); err != nil {
			return fmt.Errorf("terraform init failed: %w", err)
		}

		// Validate
		logger.Info("Validating configuration")
		if err := tfManager.Validate(rc); err != nil {
			return fmt.Errorf("terraform validation failed: %w", err)
		}

		// Plan
		logger.Info("Planning deployment")
		if err := tfManager.Plan(rc); err != nil {
			return fmt.Errorf("terraform plan failed: %w", err)
		}

		// Apply (with confirmation if not auto-approved)
		if !autoApprove {
			fmt.Print("\nDo you want to apply these changes? [y/N]: ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				logger.Warn("Failed to read user input, cancelling deployment", zap.Error(err))
				return nil
			}
			if response != "y" && response != "yes" && response != "Y" && response != "YES" {
				logger.Info("Deployment cancelled by user")
				return nil
			}
		}

		logger.Info("Applying configuration")
		if err := tfManager.Apply(rc, true); err != nil {
			return fmt.Errorf("terraform apply failed: %w", err)
		}

		// Step 4: Post-deployment integration
		if useConsulKV {
			// Store deployment info in Consul KV
			outputs := []string{"server_ip", "server_id", "service_url"}
			if err := tfManager.SyncTerraformOutputsToConsulKV(rc, kvPrefix+"/terraform", outputs); err != nil {
				logger.Warn("Failed to sync outputs to Consul KV", zap.Error(err))
			}
		}

		logger.Info("Consul-Vault-Terraform deployment completed successfully")
		fmt.Println("\n Infrastructure deployed successfully with Consul-Vault integration!")
		fmt.Printf(" Consul UI: %s\n", consulAddr+"/ui")
		fmt.Printf(" Vault UI: %s\n", vaultAddr+"/ui")

		return nil
	}),
}

var generateConsulClusterCmd = &cobra.Command{
	Use:   "consul-cluster [directory]",
	Short: "Generate Consul cluster with Vault integration",
	Long: `Generate a complete Consul cluster deployment with Vault integration.
This creates Terraform configuration that:
- Deploys Consul servers and clients on Hetzner Cloud
- Integrates with Vault for secrets management
- Configures service mesh capabilities
- Sets up proper networking and firewall rules`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputDir := "./terraform-consul-cluster"
		if len(args) > 0 {
			outputDir = args[0]
		}

		// Get flags
		clusterName, _ := cmd.Flags().GetString("cluster-name")
		serverCount, _ := cmd.Flags().GetInt("server-count")
		clientCount, _ := cmd.Flags().GetInt("client-count")
		datacenter, _ := cmd.Flags().GetString("datacenter")
		serverType, _ := cmd.Flags().GetString("server-type")
		location, _ := cmd.Flags().GetString("location")
		sshKeyName, _ := cmd.Flags().GetString("ssh-key")
		vaultAddr, _ := cmd.Flags().GetString("vault-addr")
		secretsMount, _ := cmd.Flags().GetString("secrets-mount")
		kvPrefix, _ := cmd.Flags().GetString("kv-prefix")

		if vaultAddr == "" {
			vaultAddr = os.Getenv("VAULT_ADDR")
			if vaultAddr == "" {
				vaultAddr = "https://127.0.0.1:8179"
			}
		}

		logger.Info("Generating Consul cluster configuration",
			zap.String("output_dir", outputDir),
			zap.String("cluster_name", clusterName))

		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		tfManager := terraform.NewManager(rc, outputDir)

		// Prepare template data
		templateData := terraform.ConsulTemplateData{
			VaultAddr:         vaultAddr,
			ConsulDatacenter:  datacenter,
			SecretsMount:      secretsMount,
			KVPrefix:          kvPrefix,
			ClusterName:       clusterName,
			ServerCount:       serverCount,
			ClientCount:       clientCount,
			ServerType:        serverType,
			Location:          location,
			SSHKeyName:        sshKeyName,
			ConsulServerCount: serverCount,
		}

		// Generate main Consul cluster configuration
		if err := tfManager.GenerateFromString(terraform.ConsulClusterTemplate, "main.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate main.tf: %w", err)
		}

		// Generate cloud-init for servers
		if err := tfManager.GenerateFromString(terraform.ConsulServerCloudInit, "consul-server-init.yaml", templateData); err != nil {
			return fmt.Errorf("failed to generate server cloud-init: %w", err)
		}

		// Generate cloud-init for clients
		if err := tfManager.GenerateFromString(terraform.ConsulClientCloudInit, "consul-client-init.yaml", templateData); err != nil {
			return fmt.Errorf("failed to generate client cloud-init: %w", err)
		}

		// Generate variables file
		if err := generateConsulClusterVariables(outputDir, templateData); err != nil {
			return fmt.Errorf("failed to generate variables: %w", err)
		}

		// Generate setup script for Consul and Vault secrets
		if err := generateConsulVaultSecretsSetup(outputDir, templateData); err != nil {
			return fmt.Errorf("failed to generate secrets setup script: %w", err)
		}

		logger.Info("Consul cluster configuration generated successfully",
			zap.String("directory", outputDir))

		fmt.Printf(" Consul cluster configuration generated in: %s\n", outputDir)
		fmt.Printf(" Next steps:\n")
		fmt.Printf("   1. Review and customize the generated configuration\n")
		fmt.Printf("   2. Run: ./setup-consul-vault-secrets.sh to configure secrets\n")
		fmt.Printf("   3. Deploy with: eos create consul-vault %s --services --consul-kv\n", outputDir)

		return nil
	}),
}

var consulServiceMeshCmd = &cobra.Command{
	Use:   "service-mesh [directory]",
	Short: "Generate Consul service mesh configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputDir := "./terraform-service-mesh"
		if len(args) > 0 {
			outputDir = args[0]
		}

		// Get flags
		consulAddr, _ := cmd.Flags().GetString("consul-addr")
		vaultAddr, _ := cmd.Flags().GetString("vault-addr")
		datacenter, _ := cmd.Flags().GetString("datacenter")
		kvPrefix, _ := cmd.Flags().GetString("kv-prefix")

		if consulAddr == "" {
			consulAddr = "http://127.0.0.1:8500"
		}
		if vaultAddr == "" {
			vaultAddr = "https://127.0.0.1:8179"
		}

		logger.Info("Generating service mesh configuration",
			zap.String("output_dir", outputDir))

		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		tfManager := terraform.NewManager(rc, outputDir)

		// Prepare template data with example services
		templateData := terraform.ConsulTemplateData{
			VaultAddr:        vaultAddr,
			ConsulAddr:       consulAddr,
			ConsulDatacenter: datacenter,
			KVPrefix:         kvPrefix,
			Services: []terraform.ConsulServiceTemplate{
				{
					Name: "web",
					Port: 8080,
					Tags: []string{"web", "frontend"},
					Check: &terraform.ConsulHealthCheck{
						HTTP:     "http://localhost:8080/health",
						Interval: "10s",
						Timeout:  "3s",
					},
					Connect: &terraform.ConsulConnect{
						Native: false,
						SidecarService: &terraform.ConsulSidecarService{
							Port: 21000,
							Proxy: &terraform.ConsulProxy{
								Upstreams: []terraform.ConsulUpstream{
									{
										DestinationName: "api",
										LocalBindPort:   8081,
									},
								},
							},
						},
					},
					Intentions: []terraform.ConsulIntention{
						{
							Source:      "web",
							Action:      "allow",
							Description: "Allow web to call itself",
						},
					},
				},
				{
					Name: "api",
					Port: 8082,
					Tags: []string{"api", "backend"},
					Check: &terraform.ConsulHealthCheck{
						HTTP:     "http://localhost:8082/health",
						Interval: "10s",
						Timeout:  "3s",
					},
					Connect: &terraform.ConsulConnect{
						Native: false,
						SidecarService: &terraform.ConsulSidecarService{
							Port: 21001,
							Proxy: &terraform.ConsulProxy{
								Upstreams: []terraform.ConsulUpstream{
									{
										DestinationName: "database",
										LocalBindPort:   5432,
									},
								},
							},
						},
					},
					Intentions: []terraform.ConsulIntention{
						{
							Source:      "web",
							Action:      "allow",
							Description: "Allow web to call API",
						},
					},
				},
			},
		}

		// Generate service mesh configuration
		if err := tfManager.GenerateFromString(terraform.ServiceMeshTemplate, "main.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate service mesh configuration: %w", err)
		}

		logger.Info("Service mesh configuration generated successfully",
			zap.String("directory", outputDir))

		fmt.Printf(" Service mesh configuration generated in: %s\n", outputDir)

		return nil
	}),
}

// Helper functions
func generateConsulClusterVariables(outputDir string, data terraform.ConsulTemplateData) error {
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

variable "consul_datacenter" {
  description = "Consul datacenter name"
  type        = string
  default     = "%s"
}

variable "cluster_name" {
  description = "Consul cluster name"
  type        = string
  default     = "%s"
}

variable "server_count" {
  description = "Number of Consul servers"
  type        = number
  default     = %d
}

variable "client_count" {
  description = "Number of Consul clients"
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
`, data.VaultAddr, data.ConsulDatacenter, data.ClusterName, data.ServerCount, data.ClientCount, data.ServerType, data.Location, data.SSHKeyName)

	return os.WriteFile(outputDir+"/variables.tf", []byte(variables), 0644)
}

func generateConsulVaultSecretsSetup(outputDir string, data terraform.ConsulTemplateData) error {
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

	scriptPath := outputDir + "/setup-consul-vault-secrets.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return err
	}

	return nil
}

func init() {
	CreateCmd.AddCommand(terraformConsulVaultCmd)
	CreateCmd.AddCommand(generateConsulClusterCmd)
	CreateCmd.AddCommand(consulServiceMeshCmd)

	// Consul-Vault flags
	terraformConsulVaultCmd.Flags().Bool("services", true, "Enable Consul service discovery")
	terraformConsulVaultCmd.Flags().Bool("consul-kv", true, "Enable Consul KV store")
	terraformConsulVaultCmd.Flags().Bool("vault-secrets", true, "Enable Vault secrets management")
	terraformConsulVaultCmd.Flags().String("consul-addr", "", "Consul server address")
	terraformConsulVaultCmd.Flags().String("vault-addr", "", "Vault server address")
	terraformConsulVaultCmd.Flags().String("datacenter", "dc1", "Consul datacenter")
	terraformConsulVaultCmd.Flags().String("service-prefix", "terraform", "Service name prefix")
	terraformConsulVaultCmd.Flags().String("kv-prefix", "terraform", "Consul KV prefix")
	terraformConsulVaultCmd.Flags().Bool("auto-approve", false, "Auto approve the deployment")

	// Consul cluster flags
	generateConsulClusterCmd.Flags().String("cluster-name", "consul-cluster", "Consul cluster name")
	generateConsulClusterCmd.Flags().Int("server-count", 3, "Number of Consul servers")
	generateConsulClusterCmd.Flags().Int("client-count", 2, "Number of Consul clients")
	generateConsulClusterCmd.Flags().String("datacenter", "dc1", "Consul datacenter")
	generateConsulClusterCmd.Flags().String("server-type", "cx21", "Hetzner server type")
	generateConsulClusterCmd.Flags().String("location", "nbg1", "Hetzner location")
	generateConsulClusterCmd.Flags().String("ssh-key", "default", "SSH key name in Hetzner")
	generateConsulClusterCmd.Flags().String("vault-addr", "", "Vault server address")
	generateConsulClusterCmd.Flags().String("secrets-mount", "terraform", "Vault secrets mount path")
	generateConsulClusterCmd.Flags().String("kv-prefix", "terraform", "Consul KV prefix")

	// Service mesh flags
	consulServiceMeshCmd.Flags().String("consul-addr", "", "Consul server address")
	consulServiceMeshCmd.Flags().String("vault-addr", "", "Vault server address")
	consulServiceMeshCmd.Flags().String("datacenter", "dc1", "Consul datacenter")
	consulServiceMeshCmd.Flags().String("kv-prefix", "terraform", "Consul KV prefix")
}
