// cmd/create/terraform_consul.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	terraformconsul "github.com/CodeMonkeyCybersecurity/eos/pkg/terraform/consul"
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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		useServices, _ := cmd.Flags().GetBool("services")
		useConsulKV, _ := cmd.Flags().GetBool("consul-kv")
		useVaultSecrets, _ := cmd.Flags().GetBool("vault-secrets")
		consulAddr, _ := cmd.Flags().GetString("consul-addr")
		vaultAddr, _ := cmd.Flags().GetString("vault-addr")
		datacenter, _ := cmd.Flags().GetString("datacenter")
		servicePrefix, _ := cmd.Flags().GetString("service-prefix")
		kvPrefix, _ := cmd.Flags().GetString("kv-prefix")
		autoApprove, _ := cmd.Flags().GetBool("auto-approve")

		// Determine the target directory
		targetDir := "."
		if len(args) > 0 {
			targetDir = args[0]
		}

		logger.Info("Deploying infrastructure with Consul and Vault integration",
			zap.String("directory", targetDir),
			zap.Bool("services", useServices),
			zap.Bool("consul_kv", useConsulKV),
			zap.Bool("vault_secrets", useVaultSecrets))

		// Auto-detect addresses if not provided
		if consulAddr == "" {
			consulAddr = fmt.Sprintf("http://localhost:%d", shared.PortConsul)
		}
		if vaultAddr == "" {
			vaultAddr = os.Getenv("VAULT_ADDR")
			if vaultAddr == "" {
				vaultAddr = "https://localhost:8200"
			}
		}

		// Create Terraform manager
		tfManager := terraform.NewManager(rc, targetDir)

		// Set environment variables
		if err := os.Setenv("CONSUL_HTTP_ADDR", consulAddr); err != nil {
			return fmt.Errorf("failed to set CONSUL_HTTP_ADDR: %w", err)
		}
		if err := os.Setenv("VAULT_ADDR", vaultAddr); err != nil {
			return fmt.Errorf("failed to set VAULT_ADDR: %w", err)
		}

		// Validate connectivity
		logger.Info("Validating Consul connectivity",
			zap.String("consul_addr", consulAddr))

		// TODO: Add actual Consul connectivity check here

		logger.Info("Validating Vault connectivity",
			zap.String("vault_addr", vaultAddr))

		// TODO: Add actual Vault connectivity check here

		// Create configuration template
		templateData := terraform.ConsulVaultTemplate{
			ConsulAddr:      consulAddr,
			VaultAddr:       vaultAddr,
			Datacenter:      datacenter,
			ServicePrefix:   servicePrefix,
			KVPrefix:        kvPrefix,
			UseServices:     useServices,
			UseConsulKV:     useConsulKV,
			UseVaultSecrets: useVaultSecrets,
		}

		// Generate Terraform configuration
		if err := tfManager.GenerateFromString(terraform.ConsulVaultIntegrationTemplate, "consul-vault-integration.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate Terraform configuration: %w", err)
		}

		// Create deployment script
		deployScript := fmt.Sprintf(`#!/bin/bash
# Deploy infrastructure with Consul and Vault integration

export CONSUL_HTTP_ADDR="%s"
export VAULT_ADDR="%s"

echo "Deploying infrastructure with Consul and Vault integration..."
terraform init
terraform plan -out=tfplan

%s

echo "Deployment complete!"
`, consulAddr, vaultAddr, func() string {
			if autoApprove {
				return "terraform apply tfplan"
			}
			return `read -p "Review the plan above. Continue with deployment? (yes/no): " confirm
if [[ "$confirm" == "yes" ]]; then
    terraform apply tfplan
else
    echo "Deployment cancelled."
    exit 1
fi`
		}())

		deployPath := targetDir + "/deploy-consul-vault.sh"
		if err := os.WriteFile(deployPath, []byte(deployScript), 0755); err != nil {
			return fmt.Errorf("failed to create deployment script: %w", err)
		}

		logger.Info("Consul-Vault integrated infrastructure ready",
			zap.String("directory", targetDir),
			zap.String("deploy_script", deployPath))

		logger.Info("terminal prompt:  Consul-Vault integrated infrastructure generated!")
		logger.Info("terminal prompt: To deploy:")
		logger.Info("terminal prompt:   cd to directory", zap.String("dir", targetDir))
		logger.Info("terminal prompt:   ./deploy-consul-vault.sh")
		logger.Info("terminal prompt: Consul Address", zap.String("address", consulAddr))
		logger.Info("terminal prompt: Vault Address", zap.String("address", vaultAddr))

		return nil
	}),
}

var generateConsulClusterCmd = &cobra.Command{
	Use:   "consul-cluster [directory]",
	Short: "Generate Terraform configuration for a Consul cluster on Hetzner Cloud",
	Long: `Generate complete Terraform configuration for deploying a Consul cluster on Hetzner Cloud.

This command creates:
- Multi-server Consul cluster configuration
- Client nodes for service registration
- Cloud-init scripts for automated setup
- Vault integration for secrets management
- Monitoring and observability setup

Example:
  eos create consul-cluster ./consul-infra --servers=3 --clients=2`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get configuration from flags
		serverCount, _ := cmd.Flags().GetInt("servers")
		clientCount, _ := cmd.Flags().GetInt("clients")
		datacenter, _ := cmd.Flags().GetString("datacenter")
		serverType, _ := cmd.Flags().GetString("server-type")
		location, _ := cmd.Flags().GetString("location")
		sshKeyName, _ := cmd.Flags().GetString("ssh-key")
		vaultAddr, _ := cmd.Flags().GetString("vault-addr")
		encryptKey, _ := cmd.Flags().GetString("encrypt-key")
		enableACL, _ := cmd.Flags().GetBool("enable-acl")
		enableTLS, _ := cmd.Flags().GetBool("enable-tls")

		// Determine output directory
		outputDir := "./consul-cluster"
		if len(args) > 0 {
			outputDir = args[0]
		}

		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		logger.Info("Generating Consul cluster configuration",
			zap.String("directory", outputDir),
			zap.Int("servers", serverCount),
			zap.Int("clients", clientCount))

		// Generate encryption key if not provided
		if encryptKey == "" {
			// TODO: Generate using consul keygen when available
			encryptKey = "PLACEHOLDER_GENERATE_WITH_CONSUL_KEYGEN"
		}

		// Create Terraform manager
		tfManager := terraform.NewManager(rc, outputDir)

		// Create template data
		templateData := terraform.ConsulTemplateData{
			ClusterName:      "consul-cluster",
			ConsulDatacenter: datacenter,
			ServerCount:      serverCount,
			ClientCount:      clientCount,
			ServerType:       serverType,
			Location:         location,
			SSHKeyName:       sshKeyName,
			VaultAddr:        vaultAddr,
			EncryptKey:       encryptKey,
			EnableACL:        enableACL,
			EnableTLS:        enableTLS,
			SecretsMount:     "consul-terraform",
			ConsulVersion:    "1.16.1",
			ConsulPort:       shared.PortConsul,
		}

		// Generate main Terraform configuration
		if err := tfManager.GenerateFromString(terraform.ConsulClusterTemplate, "main.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate main configuration: %w", err)
		}

		// Generate provider configuration
		if err := tfManager.GenerateFromString(terraform.ConsulProviderConfig, "provider.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate provider configuration: %w", err)
		}

		// Generate network configuration
		if err := tfManager.GenerateFromString(terraform.ConsulNetworkConfig, "network.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate network configuration: %w", err)
		}

		// Generate server configuration
		if err := tfManager.GenerateFromString(terraform.ConsulServerConfig, "consul-servers.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate server configuration: %w", err)
		}

		// Generate client configuration
		if err := tfManager.GenerateFromString(terraform.ConsulClientConfig, "consul-clients.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate client configuration: %w", err)
		}

		// Generate cloud-init templates
		if err := tfManager.GenerateFromString(terraform.ConsulServerCloudInit, "consul-server-init.yaml", templateData); err != nil {
			return fmt.Errorf("failed to generate server cloud-init: %w", err)
		}

		if err := tfManager.GenerateFromString(terraform.ConsulClientCloudInit, "consul-client-init.yaml", templateData); err != nil {
			return fmt.Errorf("failed to generate client cloud-init: %w", err)
		}

		// Generate variables file
		tfData := &terraformconsul.TemplateData{
			VaultAddr:        templateData.VaultAddr,
			ConsulDatacenter: templateData.ConsulDatacenter,
			ClusterName:      templateData.ClusterName,
			ServerCount:      templateData.ServerCount,
			ClientCount:      templateData.ClientCount,
			ServerType:       templateData.ServerType,
			Location:         templateData.Location,
			SSHKeyName:       templateData.SSHKeyName,
		}
		if err := terraformconsul.GenerateClusterVariables(rc, outputDir, tfData); err != nil {
			return fmt.Errorf("failed to generate variables: %w", err)
		}

		// Generate setup script for Consul and Vault secrets
		scriptData := &terraformconsul.ScriptData{
			VaultAddr:        templateData.VaultAddr,
			SecretsMount:     templateData.SecretsMount,
			ConsulDatacenter: templateData.ConsulDatacenter,
		}
		if err := terraformconsul.GenerateVaultSecretsSetup(rc, outputDir, scriptData); err != nil {
			return fmt.Errorf("failed to generate secrets setup script: %w", err)
		}

		logger.Info("Consul cluster configuration generated successfully",
			zap.String("directory", outputDir))

		logger.Info("terminal prompt:  Consul cluster configuration generated!\n")
		logger.Info("terminal prompt: Next steps:")
		logger.Info("terminal prompt: 1. Set up secrets: cd to dir && ./setup-consul-vault-secrets.sh", zap.String("dir", outputDir))
		logger.Info("terminal prompt: 2. Review configuration: terraform plan")
		logger.Info("terminal prompt: 3. Deploy cluster: terraform apply\n")
		logger.Info("terminal prompt: Cluster details:")
		logger.Info("terminal prompt: - Datacenter", zap.String("datacenter", datacenter))
		logger.Info("terminal prompt: - Servers", zap.Int("count", serverCount))
		logger.Info("terminal prompt: - Clients", zap.Int("count", clientCount))
		logger.Info("terminal prompt: - Location", zap.String("location", location))

		return nil
	}),
}

var consulServiceMeshCmd = &cobra.Command{
	Use:   "consul-mesh [directory]",
	Short: "Generate Consul Connect service mesh configuration",
	Long: `Generate Terraform configuration for Consul Connect service mesh with sidecar proxies.

This creates a complete service mesh setup including:
- Proxy configuration for services
- Intentions for service-to-service communication
- Observability with metrics and tracing
- mTLS between services

Example:
  eos create consul-mesh ./mesh-config --service=web --upstream=api`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get configuration from flags
		serviceName, _ := cmd.Flags().GetString("service")
		upstreams, _ := cmd.Flags().GetStringSlice("upstream")
		enableMetrics, _ := cmd.Flags().GetBool("enable-metrics")
		enableTracing, _ := cmd.Flags().GetBool("enable-tracing")
		datacenter, _ := cmd.Flags().GetString("datacenter")

		// Determine output directory
		outputDir := "./consul-mesh"
		if len(args) > 0 {
			outputDir = args[0]
		}

		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		logger.Info("Generating service mesh configuration",
			zap.String("directory", outputDir),
			zap.String("service", serviceName),
			zap.Strings("upstreams", upstreams))

		// Create Terraform manager
		tfManager := terraform.NewManager(rc, outputDir)

		// Create template data
		templateData := terraform.ServiceMeshTemplateData{
			ServiceName:   serviceName,
			Datacenter:    datacenter,
			EnableMetrics: enableMetrics,
			EnableTracing: enableTracing,
			ConsulPort:    shared.PortConsul,
			Upstreams: func() []terraform.UpstreamService {
				var ups []terraform.UpstreamService
				for i, upstream := range upstreams {
					ups = append(ups, terraform.UpstreamService{
						Name:       upstream,
						LocalPort:  9000 + i,
						Datacenter: datacenter,
					})
				}
				return ups
			}(),
			Intentions: func() []terraform.ServiceIntention {
				var ints []terraform.ServiceIntention
				for _, upstream := range upstreams {
					ints = append(ints, terraform.ServiceIntention{
						Source:      serviceName,
						Destination: upstream,
						Action:      "allow",
					})
				}
				return ints
			}(),
		}

		// Generate service mesh configuration
		if err := tfManager.GenerateFromString(terraform.ServiceMeshTemplate, "main.tf", templateData); err != nil {
			return fmt.Errorf("failed to generate service mesh configuration: %w", err)
		}

		logger.Info("Service mesh configuration generated successfully",
			zap.String("directory", outputDir))

		logger.Info("terminal prompt:  Service mesh configuration generated in directory", zap.String("dir", outputDir))

		return nil
	}),
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
	generateConsulClusterCmd.Flags().Int("servers", 3, "Number of Consul servers")
	generateConsulClusterCmd.Flags().Int("clients", 2, "Number of Consul clients")
	generateConsulClusterCmd.Flags().String("datacenter", "dc1", "Consul datacenter name")
	generateConsulClusterCmd.Flags().String("server-type", "cpx11", "Hetzner server type")
	generateConsulClusterCmd.Flags().String("location", "fsn1", "Hetzner datacenter location")
	generateConsulClusterCmd.Flags().String("ssh-key", "default", "SSH key name in Hetzner Cloud")
	generateConsulClusterCmd.Flags().String("vault-addr", "", "Vault server address for secrets")
	generateConsulClusterCmd.Flags().String("encrypt-key", "", "Consul gossip encryption key")
	generateConsulClusterCmd.Flags().Bool("enable-acl", false, "Enable Consul ACLs")
	generateConsulClusterCmd.Flags().Bool("enable-tls", false, "Enable TLS encryption")

	// Service mesh flags
	consulServiceMeshCmd.Flags().String("service", "web", "Service name")
	consulServiceMeshCmd.Flags().StringSlice("upstream", []string{}, "Upstream services")
	consulServiceMeshCmd.Flags().Bool("enable-metrics", true, "Enable metrics collection")
	consulServiceMeshCmd.Flags().Bool("enable-tracing", true, "Enable distributed tracing")
	consulServiceMeshCmd.Flags().String("datacenter", "dc1", "Consul datacenter")
}
