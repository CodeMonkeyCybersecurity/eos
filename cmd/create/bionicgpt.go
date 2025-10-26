// cmd/create/bionicgpt.go
package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt_nomad"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	// Required flags
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
	bionicgptDryRun          bool
	bionicgptForce           bool
	bionicgptSkipHealthCheck bool
)

func init() {
	bionicgptCmd := &cobra.Command{
		Use:   "bionicgpt",
		Short: "Deploy BionicGPT with Nomad orchestration, Hecate reverse proxy, and Authentik SSO",
		Long: `Deploy BionicGPT enterprise multi-tenant LLM platform using Nomad orchestration.

Architecture:
  - Nomad orchestration on local node
  - Hecate reverse proxy on cloud node (Caddy + Authentik)
  - Consul service discovery (WAN joined)
  - Tailscale VPN between nodes
  - PostgreSQL with pgVector for RAG
  - LiteLLM proxy for Azure OpenAI
  - Ollama for local embeddings (optional)
  - oauth2-proxy for SSO authentication

Enterprise Features:
  • Multi-tenant team isolation with PostgreSQL Row-Level Security
  • Authentik SSO with OAuth2/OIDC
  • Hecate reverse proxy with automatic routing
  • Consul service discovery and health checks
  • Vault-managed secrets
  • Retrieval-Augmented Generation (RAG) with document processing
  • Comprehensive audit logging and governance

Examples:
  # Basic deployment (minimal required flags)
  eos create bionicgpt \
    --domain chat.example.com \
    --cloud-node cloud-hecate \
    --auth-url https://auth.example.com

  # Full deployment with Azure OpenAI and local embeddings
  eos create bionicgpt \
    --domain chat.example.com \
    --cloud-node cloud-hecate \
    --auth-url https://auth.example.com \
    --azure-endpoint https://my-resource.openai.azure.com \
    --azure-chat-deployment gpt-4-deployment \
    --local-embeddings

  # Dry run to check configuration
  eos create bionicgpt \
    --domain chat.example.com \
    --cloud-node cloud-hecate \
    --auth-url https://auth.example.com \
    --dry-run

Prerequisites:
  1. Tailscale installed and connected on both nodes
  2. Authentik API token stored in Vault
  3. Consul accessible on cloud node
  4. Caddy Admin API accessible on cloud node

  Run 'eos create bionicgpt --help' for more details.

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
		PreRunE: eos.Wrap(validateBionicGPTConfig),
		RunE:    eos.Wrap(runCreateBionicGPT),
	}

	// Required flags
	bionicgptCmd.Flags().StringVar(&bionicgptDomain, "domain", "",
		"Public domain for BionicGPT (e.g., chat.example.com) [REQUIRED]")
	_ = bionicgptCmd.MarkFlagRequired("domain")

	bionicgptCmd.Flags().StringVar(&bionicgptCloudNode, "cloud-node", "",
		"Cloud node hostname for Hecate/Authentik (Tailscale name) [REQUIRED]")
	_ = bionicgptCmd.MarkFlagRequired("cloud-node")

	bionicgptCmd.Flags().StringVar(&bionicgptAuthURL, "auth-url", "",
		"Authentik URL (e.g., https://auth.example.com) [REQUIRED]")
	_ = bionicgptCmd.MarkFlagRequired("auth-url")

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

	CreateCmd.AddCommand(bionicgptCmd)
}

// validateBionicGPTConfig validates required configuration before deployment
// PreRunE: Fails fast with helpful error message if required flags are missing
func validateBionicGPTConfig(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Build minimal config to check required fields
	config := &bionicgpt_nomad.EnterpriseConfig{
		Domain:    bionicgptDomain,
		CloudNode: bionicgptCloudNode,
		AuthURL:   bionicgptAuthURL,
	}

	// Validate required flags - returns user-friendly error with context
	return bionicgpt_nomad.ValidateRequiredFlags(config)
}

func runCreateBionicGPT(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting BionicGPT deployment with Nomad orchestration")

	// Build configuration from flags
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
	if err := installer.Install(); err != nil {
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
