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

var (
	bionicgptPort             int
	bionicgptPostgresPassword string
	bionicgptJWTSecret        string
	bionicgptAppName          string
	bionicgptAzureEndpoint    string
	bionicgptAzureDeployment  string
	bionicgptAzureAPIKey      string
	bionicgptForce            bool
	bionicgptSkipHealthCheck  bool
)

func init() {
	bionicgptCmd := &cobra.Command{
		Use:   "bionicgpt",
		Short: "Deploy BionicGPT multi-tenant LLM platform with Azure OpenAI",
		Long: `Deploy BionicGPT configured for multi-tenant LLM deployment with Azure OpenAI.

BionicGPT provides an enterprise-grade ChatGPT replacement with:
• Multi-tenant team isolation with PostgreSQL Row-Level Security
• Azure OpenAI integration for enterprise LLM hosting
• Retrieval-Augmented Generation (RAG) with document processing
• Comprehensive audit logging and governance
• Team-based access control
• Document chunking and embeddings pipeline
• Vault-managed secrets for PostgreSQL, JWT, and Azure API keys

The deployment includes:
- Docker Compose setup in /opt/bionicgpt
- PostgreSQL with pgVector for embeddings
- Azure OpenAI integration (no local LLM required)
- Document parsing and chunking engine
- RAG pipeline for document retrieval
- Web interface on port 8513 (next available prime)
- Health checks and verification
- Persistent data storage
- HashiCorp Vault secret management

Examples:
  # Interactive installation (will prompt for Azure configuration)
  eos create bionicgpt

  # Specify Azure OpenAI configuration
  eos create bionicgpt --azure-endpoint https://my-resource.openai.azure.com \
    --azure-deployment gpt-4 --azure-api-key $AZURE_KEY

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

	// Azure OpenAI configuration
	bionicgptCmd.Flags().StringVar(&bionicgptAzureEndpoint, "azure-endpoint", "",
		"Azure OpenAI endpoint URL (will prompt if not provided)")
	bionicgptCmd.Flags().StringVar(&bionicgptAzureDeployment, "azure-deployment", "",
		"Azure OpenAI deployment name (will prompt if not provided)")
	bionicgptCmd.Flags().StringVar(&bionicgptAzureAPIKey, "azure-api-key", "",
		"Azure OpenAI API key (retrieved from Vault if not provided)")

	// Installation behavior flags
	bionicgptCmd.Flags().BoolVar(&bionicgptForce, "force", false,
		"Force reinstall even if already installed")
	bionicgptCmd.Flags().BoolVar(&bionicgptSkipHealthCheck, "skip-health-check", false,
		"Skip health check after installation")

	CreateCmd.AddCommand(bionicgptCmd)
}

func runCreateBionicGPT(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting BionicGPT deployment")

	// Create installation config from flags
	config := &bionicgpt.InstallConfig{
		Port:             bionicgptPort,
		PostgresPassword: bionicgptPostgresPassword,
		JWTSecret:        bionicgptJWTSecret,
		AppName:          bionicgptAppName,
		AzureEndpoint:    bionicgptAzureEndpoint,
		AzureDeployment:  bionicgptAzureDeployment,
		AzureAPIKey:      bionicgptAzureAPIKey,
		ForceReinstall:   bionicgptForce,
		SkipHealthCheck:  bionicgptSkipHealthCheck,
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
