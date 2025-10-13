// cmd/create/openwebui.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/openwebui"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	openwebuiAzureEndpoint   string
	openwebuiAzureDeployment string
	openwebuiAzureAPIKey     string
	openwebuiAzureAPIVersion string
	openwebuiPort            int
	openwebuiName            string
	openwebuiForce           bool
	openwebuiSkipHealthCheck bool
	openwebuiDirectMode      bool
	openwebuiLiteLLMPort     int
)

func init() {
	openwebuiCmd := &cobra.Command{
		Use:   "openwebui",
		Short: "Deploy Open WebUI with Azure OpenAI backend",
		Long: `Deploy Open WebUI configured to use Azure OpenAI as the backend.

Open WebUI provides a user-friendly chat interface for interacting with Azure OpenAI models.
This command sets up Open WebUI in a Docker container with proper configuration and security.

Deployment Options:
1. LiteLLM Proxy (DEFAULT) - Production-ready with cost tracking, load balancing
2. Direct Azure OpenAI (--direct-mode) - Simple setup, basic features only

The deployment includes:
- Docker Compose setup in /opt/openwebui
- Secure environment variable configuration
- Azure OpenAI integration (direct or via LiteLLM)
- PostgreSQL database (when using LiteLLM)
- Health checks and verification
- Persistent data storage
- Cost tracking and usage monitoring (LiteLLM only)

Examples:
  # Interactive installation (will prompt for Azure credentials)
  eos create openwebui

  # Production setup with LiteLLM proxy (DEFAULT - recommended)
  eos create openwebui \
    --azure-endpoint https://myopenai.openai.azure.com \
    --azure-deployment gpt-4 \
    --azure-api-key YOUR_API_KEY

  # Direct Azure OpenAI connection (simple, no cost tracking)
  eos create openwebui \
    --direct-mode \
    --azure-endpoint https://myopenai.openai.azure.com \
    --azure-deployment gpt-4 \
    --azure-api-key YOUR_API_KEY

  # Custom ports (LiteLLM mode)
  eos create openwebui \
    --port 3000 \
    --litellm-port 4000

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
		RunE: eos.Wrap(runCreateOpenWebUI),
	}

	// Azure OpenAI configuration flags
	openwebuiCmd.Flags().StringVar(&openwebuiAzureEndpoint, "azure-endpoint", "",
		"Azure OpenAI endpoint URL (e.g., https://myopenai.openai.azure.com)")
	openwebuiCmd.Flags().StringVar(&openwebuiAzureDeployment, "azure-deployment", "",
		"Azure OpenAI deployment name (e.g., gpt-4)")
	openwebuiCmd.Flags().StringVar(&openwebuiAzureAPIKey, "azure-api-key", "",
		"Azure OpenAI API key")
	openwebuiCmd.Flags().StringVar(&openwebuiAzureAPIVersion, "azure-api-version", "2024-02-15-preview",
		"Azure OpenAI API version")

	// Open WebUI configuration flags
	openwebuiCmd.Flags().IntVar(&openwebuiPort, "port", 0,
		"External port to expose (default: 8501)")
	openwebuiCmd.Flags().StringVar(&openwebuiName, "name", "Code Monkey AI Chat",
		"Display name for the web UI")

	// LiteLLM proxy flags (ENABLED BY DEFAULT)
	openwebuiCmd.Flags().BoolVar(&openwebuiDirectMode, "direct-mode", false,
		"Use direct Azure OpenAI connection (disables LiteLLM production features)")
	openwebuiCmd.Flags().IntVar(&openwebuiLiteLLMPort, "litellm-port", 4000,
		"Port for LiteLLM proxy (default: 4000)")

	// Installation behavior flags
	openwebuiCmd.Flags().BoolVar(&openwebuiForce, "force", false,
		"Force reinstall even if already installed")
	openwebuiCmd.Flags().BoolVar(&openwebuiSkipHealthCheck, "skip-health-check", false,
		"Skip health check after installation")

	CreateCmd.AddCommand(openwebuiCmd)
}

func runCreateOpenWebUI(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Open WebUI deployment")

	// Create installation config from flags
	config := &openwebui.InstallConfig{
		AzureEndpoint:    openwebuiAzureEndpoint,
		AzureDeployment:  openwebuiAzureDeployment,
		AzureAPIKey:      openwebuiAzureAPIKey,
		AzureAPIVersion:  openwebuiAzureAPIVersion,
		Port:             openwebuiPort,
		WebUIName:        openwebuiName,
		ForceReinstall:   openwebuiForce,
		SkipHealthCheck:  openwebuiSkipHealthCheck,
		DirectMode:       openwebuiDirectMode,
		LiteLLMPort:      openwebuiLiteLLMPort,
	}

	// Create installer
	installer := openwebui.NewOpenWebUIInstaller(rc, config)

	// Run installation
	if err := installer.Install(); err != nil {
		logger.Error("Open WebUI deployment failed", zap.Error(err))
		return err
	}

	// Display success message with instructions
	logger.Info("================================================================================")
	logger.Info("Open WebUI deployment completed successfully")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Access Open WebUI",
		zap.String("url", fmt.Sprintf("http://localhost:%d", config.Port)),
		zap.Int("port", config.Port))
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info(fmt.Sprintf("  1. Open your browser and go to http://localhost:%d", config.Port))
	logger.Info("  2. Create your first user account (will be admin)")
	logger.Info("  3. Start chatting with Azure OpenAI")
	logger.Info("")
	if !config.DirectMode {
		logger.Info("🚀 LiteLLM Proxy (Production Mode):")
		logger.Info(fmt.Sprintf("  UI:   http://localhost:%d/ui", config.LiteLLMPort))
		logger.Info(fmt.Sprintf("  Docs: http://localhost:%d/docs", config.LiteLLMPort))
		logger.Info("")
		logger.Info("Production Features Enabled:")
		logger.Info("  ✓ Cost tracking and usage monitoring")
		logger.Info("  ✓ Load balancing across multiple models")
		logger.Info("  ✓ Request logging and analytics")
		logger.Info("  ✓ Rate limiting and quotas")
		logger.Info("")
	} else {
		logger.Info("⚠️  Direct Mode (Development Only):")
		logger.Info("  No cost tracking or production features")
		logger.Info("  For production, remove --direct-mode flag")
		logger.Info("")
	}
	logger.Info("Useful commands:")
	logger.Info("  View logs:        docker compose -f /opt/openwebui/docker-compose.yml logs -f")
	logger.Info("  Stop service:     docker compose -f /opt/openwebui/docker-compose.yml down")
	logger.Info("  Restart service:  docker compose -f /opt/openwebui/docker-compose.yml restart")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}
