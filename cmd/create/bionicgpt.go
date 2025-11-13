// cmd/create/bionicgpt.go
package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt_nomad"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	// Deployment architecture
	bionicgptDeployment string // "docker" or "nomad"

	// Required flags (for Nomad deployment)
	bionicgptDomain    string
	bionicgptCloudNode string
	bionicgptAuthURL   string

	// Authentication configuration
	bionicgptSuperadminGroup string
	bionicgptDemoGroup       string
	bionicgptGroupPrefix     string

	// Azure OpenAI configuration
	bionicgptAzureEndpoint             string
	bionicgptAzureChatDeployment       string
	bionicgptAzureEmbeddingsDeployment string

	// Local embeddings configuration
	bionicgptUseLocalEmbeddings   bool
	bionicgptLocalEmbeddingsModel string

	// Infrastructure configuration
	bionicgptNomadAddress  string
	bionicgptConsulAddress string
	bionicgptNamespace     string

	// Deployment options
	bionicgptDryRun            bool
	bionicgptForce             bool
	bionicgptSkipHealthCheck   bool
	bionicgptRollbackOnFailure bool

	// Docker Compose specific options
	bionicgptPort int
)

func init() {
	bionicgptCmd := &cobra.Command{
		Use:   "bionicgpt",
		Short: "Deploy BionicGPT multi-tenant LLM platform",
		Long: `Deploy BionicGPT multi-tenant LLM platform with flexible deployment options.

Deployment Options:
  1. Docker Compose (--deployment=docker) [DEFAULT]
     - Single-node deployment
     - Simple Docker Compose orchestration
     - Suitable for: Development, single-server production
     - Prerequisites: Docker, Vault

  2. Nomad Enterprise (--deployment=nomad)
     - Multi-node distributed deployment
     - Hecate reverse proxy on cloud node (Caddy + Authentik SSO)
     - Consul service discovery (WAN joined)
     - Tailscale VPN between nodes
     - Suitable for: Enterprise production, distributed systems
     - Prerequisites: Nomad, Consul, Tailscale, Authentik, Vault

Common Features (Both Deployments):
  • Multi-tenant team isolation with PostgreSQL Row-Level Security
  • Vault-managed secrets
  • Retrieval-Augmented Generation (RAG) with document processing
  • Comprehensive audit logging and governance
  • Azure OpenAI or local embeddings (Ollama)

Examples:
  # Docker Compose deployment (simple, single-node) [DEFAULT]
  eos create bionicgpt

  # Docker Compose with Azure OpenAI
  eos create bionicgpt \
    --deployment=docker \
    --azure-endpoint https://my-resource.openai.azure.com \
    --azure-chat-deployment gpt-4-deployment

  # Nomad enterprise deployment (multi-node, SSO)
  eos create bionicgpt \
    --deployment=nomad \
    --domain chat.example.com \
    --cloud-node cloud-hecate \
    --auth-url https://auth.example.com

  # Enable rollback on failure
  eos create bionicgpt --rollback-on-failure

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
		PreRunE: eos.Wrap(validateBionicGPTConfig),
		RunE:    eos.Wrap(runCreateBionicGPT),
	}

	// Deployment architecture selection
	bionicgptCmd.Flags().StringVar(&bionicgptDeployment, "deployment", "docker",
		"Deployment type: 'docker' (Docker Compose, single-node) or 'nomad' (distributed, enterprise)")

	// Nomad deployment flags (required only for --deployment=nomad)
	bionicgptCmd.Flags().StringVar(&bionicgptDomain, "domain", "",
		"Public domain for BionicGPT (e.g., chat.example.com) [REQUIRED for Nomad]")

	bionicgptCmd.Flags().StringVar(&bionicgptCloudNode, "cloud-node", "",
		"Cloud node hostname for Hecate/Authentik (Tailscale name) [REQUIRED for Nomad]")

	bionicgptCmd.Flags().StringVar(&bionicgptAuthURL, "auth-url", "",
		"Authentik URL (e.g., https://auth.example.com) [REQUIRED for Nomad]")

	// Authentication configuration
	bionicgptCmd.Flags().StringVar(&bionicgptSuperadminGroup, "superadmin-group", "bionicgpt-superadmin",
		"Authentik group for superadmins")
	bionicgptCmd.Flags().StringVar(&bionicgptDemoGroup, "demo-group", "bionicgpt-demo-tenant",
		"Authentik group for demo tenant")
	bionicgptCmd.Flags().StringVar(&bionicgptGroupPrefix, "group-prefix", "bionicgpt-",
		"Prefix for BionicGPT groups in Authentik")

	// Azure OpenAI configuration (via LiteLLM proxy)
	bionicgptCmd.Flags().StringVar(&bionicgptAzureEndpoint, "azure-endpoint", "",
		"Azure OpenAI endpoint URL")
	bionicgptCmd.Flags().StringVar(&bionicgptAzureChatDeployment, "azure-chat-deployment", "",
		"Azure OpenAI chat deployment name (e.g., gpt-4-deployment)")
	bionicgptCmd.Flags().StringVar(&bionicgptAzureEmbeddingsDeployment, "azure-embeddings-deployment", "",
		"Azure OpenAI embeddings deployment name (optional if using local embeddings)")

	// Local embeddings configuration (Ollama)
	bionicgptCmd.Flags().BoolVar(&bionicgptUseLocalEmbeddings, "local-embeddings", true,
		"Use local embeddings via Ollama (default: true)")
	bionicgptCmd.Flags().StringVar(&bionicgptLocalEmbeddingsModel, "local-embeddings-model", "nomic-embed-text",
		"Local embeddings model to use")

	// Infrastructure configuration
	bionicgptCmd.Flags().StringVar(&bionicgptNomadAddress, "nomad-address", "http://localhost:4646",
		"Nomad API address")
	bionicgptCmd.Flags().StringVar(&bionicgptConsulAddress, "consul-address", "localhost:8500",
		"Consul API address")
	bionicgptCmd.Flags().StringVar(&bionicgptNamespace, "namespace", "default",
		"Nomad namespace")

	// Deployment options
	bionicgptCmd.Flags().BoolVar(&bionicgptDryRun, "dry-run", false,
		"Show what would be deployed without actually deploying")
	bionicgptCmd.Flags().BoolVar(&bionicgptForce, "force", false,
		"Force deployment even if already exists")
	bionicgptCmd.Flags().BoolVar(&bionicgptSkipHealthCheck, "skip-health-check", false,
		"Skip health check after deployment")
	bionicgptCmd.Flags().BoolVar(&bionicgptRollbackOnFailure, "rollback-on-failure", false,
		"Automatically rollback deployment if it fails")

	// Docker Compose specific options
	bionicgptCmd.Flags().IntVar(&bionicgptPort, "port", 8513,
		"Port for BionicGPT web interface [Docker deployment only]")

	CreateCmd.AddCommand(bionicgptCmd)
}

// validateBionicGPTConfig validates required configuration before deployment
// PreRunE: Validates deployment type and required flags for chosen deployment
func validateBionicGPTConfig(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate deployment type
	if bionicgptDeployment != "docker" && bionicgptDeployment != "nomad" {
		return fmt.Errorf("invalid deployment type: %s (must be 'docker' or 'nomad')", bionicgptDeployment)
	}

	// If Docker deployment, no additional validation needed (all flags are optional)
	if bionicgptDeployment == "docker" {
		logger.Info("Docker Compose deployment selected",
			zap.String("deployment", "docker"),
			zap.Int("port", bionicgptPort))
		return nil
	}

	// Nomad deployment - validate required flags
	logger.Info("Nomad enterprise deployment selected", zap.String("deployment", "nomad"))

	// Check if we're in interactive mode and can prompt for missing values
	if interaction.IsTTY() && (bionicgptDomain == "" || bionicgptCloudNode == "" || bionicgptAuthURL == "") {
		logger.Info("Missing required flags for Nomad deployment, entering interactive mode")

		// Build config with current values
		config := &bionicgpt_nomad.EnterpriseConfig{
			Domain:    bionicgptDomain,
			CloudNode: bionicgptCloudNode,
			AuthURL:   bionicgptAuthURL,
		}

		// Prompt for missing values (does NOT mutate global vars - returns updated config)
		updatedConfig, err := bionicgpt_nomad.PromptForMissingConfig(rc, config)
		if err != nil {
			logger.Info("Interactive mode cancelled or failed", zap.Error(err))
			return fmt.Errorf("Nomad deployment requires --domain, --cloud-node, and --auth-url flags\n\n"+
				"Interactive mode failed: %w\n\n"+
				"Use flags explicitly:\n"+
				"  eos create bionicgpt --deployment=nomad --domain=<domain> --cloud-node=<node> --auth-url=<url>", err)
		}

		// Store updated config back to flag vars (only after successful prompting)
		bionicgptDomain = updatedConfig.Domain
		bionicgptCloudNode = updatedConfig.CloudNode
		bionicgptAuthURL = updatedConfig.AuthURL

		logger.Info("Interactive configuration completed successfully",
			zap.String("domain", bionicgptDomain),
			zap.String("cloud_node", bionicgptCloudNode))

		return nil
	}

	// Non-interactive or all flags provided - validate required flags
	if bionicgptDomain == "" {
		return fmt.Errorf("Nomad deployment requires --domain flag\n" +
			"Example: eos create bionicgpt --deployment=nomad --domain=chat.example.com --cloud-node=cloud --auth-url=https://auth.example.com")
	}
	if bionicgptCloudNode == "" {
		return fmt.Errorf("Nomad deployment requires --cloud-node flag\n" +
			"Example: eos create bionicgpt --deployment=nomad --domain=chat.example.com --cloud-node=cloud --auth-url=https://auth.example.com")
	}
	if bionicgptAuthURL == "" {
		return fmt.Errorf("Nomad deployment requires --auth-url flag\n" +
			"Example: eos create bionicgpt --deployment=nomad --domain=chat.example.com --cloud-node=cloud --auth-url=https://auth.example.com")
	}

	logger.Info("Nomad deployment configuration validated",
		zap.String("domain", bionicgptDomain),
		zap.String("cloud_node", bionicgptCloudNode))

	return nil
}

func runCreateBionicGPT(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Route to appropriate installer based on deployment type
	switch bionicgptDeployment {
	case "docker":
		return runDockerComposeDeployment(rc, logger)
	case "nomad":
		return runNomadDeployment(rc, logger)
	default:
		return fmt.Errorf("invalid deployment type: %s", bionicgptDeployment)
	}
}

// runDockerComposeDeployment handles Docker Compose (single-node) deployment
func runDockerComposeDeployment(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) error {
	logger.Info("Starting BionicGPT deployment with Docker Compose")
	logger.Info("Deployment type: Single-node (Docker Compose)")

	// Build Docker Compose configuration from flags
	config := &bionicgpt.InstallConfig{
		Port:                      bionicgptPort,
		ForceReinstall:            bionicgptForce,
		SkipHealthCheck:           bionicgptSkipHealthCheck,
		UseLocalEmbeddings:        bionicgptUseLocalEmbeddings,
		LocalEmbeddingsModel:      bionicgptLocalEmbeddingsModel,
		AzureEndpoint:             bionicgptAzureEndpoint,
		AzureChatDeployment:       bionicgptAzureChatDeployment,
		AzureEmbeddingsDeployment: bionicgptAzureEmbeddingsDeployment,
		// Note: PostgresPassword, JWTSecret, LiteLLMMasterKey, AzureAPIKey
		// are retrieved from Vault by the installer
	}

	// Create Docker Compose installer
	installer := bionicgpt.NewBionicGPTInstaller(rc, config)

	// Run installation with optional rollback
	var err error
	if bionicgptRollbackOnFailure {
		err = runWithRollback(rc, installer, logger)
	} else {
		err = installer.Install()
	}

	if err != nil {
		logger.Error("BionicGPT deployment failed", zap.Error(err))
		return err
	}

	// Success message
	logger.Info("================================================================================")
	logger.Info("BionicGPT Deployment Completed Successfully")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Access BionicGPT",
		zap.String("url", fmt.Sprintf("http://localhost:%d", config.Port)))
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info("  1. Navigate to http://localhost:" + fmt.Sprintf("%d", config.Port))
	logger.Info("  2. Create your first team")
	logger.Info("  3. Upload documents for RAG functionality")
	logger.Info("  4. Start chatting with your LLM")
	logger.Info("")
	logger.Info("Useful commands:")
	logger.Info("  View logs:            docker compose -f /opt/bionicgpt/docker-compose.yml logs -f")
	logger.Info("  Check status:         docker compose -f /opt/bionicgpt/docker-compose.yml ps")
	logger.Info("  Restart services:     docker compose -f /opt/bionicgpt/docker-compose.yml restart")
	logger.Info("  Stop services:        docker compose -f /opt/bionicgpt/docker-compose.yml down")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}

// runNomadDeployment handles Nomad enterprise (multi-node) deployment
func runNomadDeployment(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) error {
	logger.Info("Starting BionicGPT deployment with Nomad orchestration")
	logger.Info("Deployment type: Multi-node enterprise (Nomad + Authentik + Hecate)")

	// Build Nomad configuration from flags
	config := &bionicgpt_nomad.EnterpriseConfig{
		// Core deployment
		Domain:    bionicgptDomain,
		CloudNode: bionicgptCloudNode,
		Namespace: bionicgptNamespace,

		// Authentication
		AuthURL:         bionicgptAuthURL,
		SuperadminGroup: bionicgptSuperadminGroup,
		DemoGroup:       bionicgptDemoGroup,
		GroupPrefix:     bionicgptGroupPrefix,

		// Azure OpenAI (via LiteLLM)
		AzureEndpoint:             bionicgptAzureEndpoint,
		AzureChatDeployment:       bionicgptAzureChatDeployment,
		AzureEmbeddingsDeployment: bionicgptAzureEmbeddingsDeployment,

		// Local embeddings (Ollama)
		UseLocalEmbeddings:   bionicgptUseLocalEmbeddings,
		LocalEmbeddingsModel: bionicgptLocalEmbeddingsModel,

		// Infrastructure
		NomadAddress:  bionicgptNomadAddress,
		ConsulAddress: bionicgptConsulAddress,

		// Deployment options
		DryRun:          bionicgptDryRun,
		Force:           bionicgptForce,
		SkipHealthCheck: bionicgptSkipHealthCheck,
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed", zap.Error(err))
		return err
	}

	// Create Nomad-based enterprise installer
	installer := bionicgpt_nomad.NewEnterpriseInstaller(rc, config)

	// Run 9-phase installation
	var err error
	if bionicgptRollbackOnFailure {
		logger.Warn("Rollback-on-failure is not yet implemented for Nomad deployments")
		logger.Warn("This feature will be added in a future release")
		err = installer.Install()
	} else {
		err = installer.Install()
	}

	if err != nil {
		logger.Error("BionicGPT deployment failed", zap.Error(err))
		return err
	}

	// Success message
	logger.Info("================================================================================")
	logger.Info("BionicGPT Deployment Completed Successfully")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Access BionicGPT",
		zap.String("url", fmt.Sprintf("https://%s", config.Domain)))
	logger.Info("Authentik SSO",
		zap.String("url", config.AuthURL))
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info("  1. Navigate to your domain and log in via Authentik")
	logger.Info(fmt.Sprintf("  2. Users in group '%s' will have superadmin access", config.SuperadminGroup))
	logger.Info(fmt.Sprintf("  3. Users in group '%s' will have demo tenant access", config.DemoGroup))
	logger.Info("  4. Upload documents for RAG functionality")
	logger.Info("  5. Start chatting with your LLM")
	logger.Info("")
	logger.Info("Useful commands:")
	logger.Info("  Check Nomad jobs:     nomad job status bionicgpt")
	logger.Info("  Check Consul:         consul catalog services | grep bionicgpt")
	logger.Info("  View logs:            nomad alloc logs <ALLOC_ID>")
	logger.Info("  Check health:         nomad job deployments bionicgpt")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}

// runWithRollback runs installation with automatic rollback on failure
func runWithRollback(rc *eos_io.RuntimeContext, installer *bionicgpt.BionicGPTInstaller, logger otelzap.LoggerWithCtx) error {
	logger.Info("Rollback-on-failure enabled - deployment will rollback if it fails")

	// TODO: Implement snapshot/rollback mechanism
	// For now, just run normal installation
	logger.Warn("Rollback mechanism not yet fully implemented")
	logger.Warn("Manual cleanup may be required if installation fails")

	err := installer.Install()

	if err != nil {
		logger.Error("Installation failed - rollback would be triggered here")
		logger.Info("Manual cleanup: docker compose -f /opt/bionicgpt/docker-compose.yml down -v")
		return err
	}

	return nil
}
