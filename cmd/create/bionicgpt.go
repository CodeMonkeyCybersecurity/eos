// cmd/create/bionicgpt.go
package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO: refactor
var (
	bionicgptPort                      int
	bionicgptPostgresPassword          string
	bionicgptJWTSecret                 string
	bionicgptAppName                   string
	bionicgptAzureEndpoint             string
	bionicgptAzureChatDeployment       string
	bionicgptAzureEmbeddingsDeployment string
	bionicgptAzureAPIKey               string
	bionicgptUseLocalEmbeddings        bool
	bionicgptLocalEmbeddingsModel      string
	bionicgptForce                     bool
	bionicgptSkipHealthCheck           bool
)

func init() {
	bionicgptCmd := &cobra.Command{
		Use:   "bionicgpt",
		Short: "Deploy BionicGPT multi-tenant LLM platform with Azure OpenAI",
		Long: `Deploy BionicGPT configured for multi-tenant LLM deployment with Azure OpenAI via LiteLLM proxy.

BionicGPT provides an enterprise-grade ChatGPT replacement with:
• Multi-tenant team isolation with PostgreSQL Row-Level Security
• Azure OpenAI integration via LiteLLM translation proxy
• Retrieval-Augmented Generation (RAG) with document processing
• Comprehensive audit logging and governance
• Team-based access control
• Document chunking and embeddings pipeline
• Vault-managed secrets for PostgreSQL, JWT, and Azure API keys

The deployment includes:
- Docker Compose setup in /opt/bionicgpt
- PostgreSQL with pgVector for embeddings
- LiteLLM proxy for Azure OpenAI compatibility (translates OpenAI format ↔ Azure format)
- Azure OpenAI integration (no local LLM required)
- Document parsing and chunking engine
- RAG pipeline for document retrieval
- Web interface on port 8513 (next available prime)
- LiteLLM proxy on port 4000 (internal)
- Comprehensive multi-tenancy validation
- Health checks and verification
- Persistent data storage
- HashiCorp Vault secret management

Architecture:
  BionicGPT (OpenAI format) → LiteLLM Proxy (translator) → Azure OpenAI → Your Credits

Examples:
  # Interactive installation (will prompt for Azure configuration)
  eos create bionicgpt

  # Specify Azure OpenAI configuration with deployment names
  eos create bionicgpt \
    --azure-endpoint https://my-resource.openai.azure.com \
    --azure-chat-deployment gpt-4-deployment \
    --azure-embeddings-deployment text-embedding-ada-002 \
    --azure-api-key $AZURE_KEY

  # Custom port
  eos create bionicgpt --port 8080

  # Force reinstall
  eos create bionicgpt --force

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
		RunE: eos.Wrap(runCreateBionicGPT),
	}

	// Configuration flags
	bionicgptCmd.Flags().IntVar(&bionicgptPort, "port", 0,
		"External port to expose (default: 8513)")
	bionicgptCmd.Flags().StringVar(&bionicgptPostgresPassword, "postgres-password", "",
		"PostgreSQL password (retrieved from Vault if not provided)")
	bionicgptCmd.Flags().StringVar(&bionicgptJWTSecret, "jwt-secret", "",
		"JWT secret for authentication (retrieved from Vault if not provided)")
	bionicgptCmd.Flags().StringVar(&bionicgptAppName, "app-name", "BionicGPT",
		"Display name for the application")

	// Azure OpenAI configuration (via LiteLLM proxy)
	bionicgptCmd.Flags().StringVar(&bionicgptAzureEndpoint, "azure-endpoint", "",
		"Azure OpenAI endpoint URL (will prompt if not provided)")
	bionicgptCmd.Flags().StringVar(&bionicgptAzureChatDeployment, "azure-chat-deployment", "",
		"Azure OpenAI chat deployment name, e.g., gpt-4-deployment (will prompt if not provided)")
	bionicgptCmd.Flags().StringVar(&bionicgptAzureEmbeddingsDeployment, "azure-embeddings-deployment", "",
		"Azure OpenAI embeddings deployment name, e.g., text-embedding-ada-002 (will prompt if not provided)")
	bionicgptCmd.Flags().StringVar(&bionicgptAzureAPIKey, "azure-api-key", "",
		"Azure OpenAI API key (retrieved from Vault if not provided)")

	// Local embeddings configuration (Ollama)
	bionicgptCmd.Flags().BoolVar(&bionicgptUseLocalEmbeddings, "use-local-embeddings", false,
		"Use local embeddings via Ollama instead of Azure (FREE, requires Ollama)")
	bionicgptCmd.Flags().StringVar(&bionicgptLocalEmbeddingsModel, "local-embeddings-model", "nomic-embed-text",
		"Local embeddings model to use with Ollama")

	// Installation behavior flags
	bionicgptCmd.Flags().BoolVar(&bionicgptForce, "force", false,
		"Force reinstall even if already installed")
	bionicgptCmd.Flags().BoolVar(&bionicgptSkipHealthCheck, "skip-health-check", false,
		"Skip health check after installation")

	CreateCmd.AddCommand(bionicgptCmd)
}

// TODO: refactor
func runCreateBionicGPT(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting BionicGPT deployment")

	// Create installation config from flags
	config := &bionicgpt.InstallConfig{
		Port:                      bionicgptPort,
		PostgresPassword:          bionicgptPostgresPassword,
		JWTSecret:                 bionicgptJWTSecret,
		AppName:                   bionicgptAppName,
		AzureEndpoint:             bionicgptAzureEndpoint,
		AzureChatDeployment:       bionicgptAzureChatDeployment,
		AzureEmbeddingsDeployment: bionicgptAzureEmbeddingsDeployment,
		AzureAPIKey:               bionicgptAzureAPIKey,
		UseLocalEmbeddings:        bionicgptUseLocalEmbeddings,
		LocalEmbeddingsModel:      bionicgptLocalEmbeddingsModel,
		ForceReinstall:            bionicgptForce,
		SkipHealthCheck:           bionicgptSkipHealthCheck,
	}

	// Create installer
	installer := bionicgpt.NewBionicGPTInstaller(rc, config)

	// Run installation
	if err := installer.Install(); err != nil {
		logger.Error("BionicGPT deployment failed", zap.Error(err))
		return err
	}

	// Display success message with instructions
	logger.Info("================================================================================")
	logger.Info("BionicGPT deployment completed successfully")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Access BionicGPT",
		zap.String("url", fmt.Sprintf("http://localhost:%d", config.Port)),
		zap.Int("port", config.Port))
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info(fmt.Sprintf("  1. Open your browser and go to http://localhost:%d", config.Port))
	logger.Info("  2. Create your first team")
	logger.Info("  3. Upload documents for RAG functionality")
	logger.Info("  4. Start chatting with Azure OpenAI")
	logger.Info("")
	logger.Info("Features enabled:")
	logger.Info("  Multi-tenant isolation with PostgreSQL RLS")
	logger.Info("  Azure OpenAI integration")
	logger.Info("  Document RAG pipeline with embeddings")
	logger.Info("  Comprehensive audit logging")
	logger.Info("  Vault-managed secrets")
	logger.Info("")
	logger.Info("Useful commands:")
	logger.Info("  View logs:        docker compose -f /opt/bionicgpt/docker-compose.yml logs -f")
	logger.Info("  Stop service:     docker compose -f /opt/bionicgpt/docker-compose.yml down")
	logger.Info("  Restart service:  docker compose -f /opt/bionicgpt/docker-compose.yml restart")
	logger.Info("  Check status:     docker compose -f /opt/bionicgpt/docker-compose.yml ps")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}
