// cmd/create/iris.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/iris"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	interactiveConfig bool
	skipConfig        bool
	azureEndpoint     string
	azureAPIKey       string
	azureDeployment   string
	smtpHost          string
	smtpPort          int
	smtpUsername      string
	smtpPassword      string
	emailFrom         string
	emailTo           string
)

var createIrisCmd = &cobra.Command{
	Use:   "iris",
	Short: "Install Iris security alert processing system",
	Long: `Install Iris (Wazuh Notify) for automated processing of Wazuh security alerts.

Iris uses:
- Temporal workflows for durable execution
- Azure OpenAI for alert analysis
- Email notifications via SMTP
- Webhook receiver for Wazuh integration

Installation creates:
- /opt/iris project directory
- Worker and webhook Go programs
- Configuration files
- Systemd services
- Test scripts

Prerequisites:
- Go 1.21+
- Temporal server (will be installed if missing)
- Azure OpenAI account
- SMTP server for email

Examples:
  eos create iris                                    # Interactive (default)
  eos create iris --skip-config                      # Use placeholders
  eos create iris --azure-endpoint=https://...       # Non-interactive`,
	RunE: eos.Wrap(runCreateIris),
}

func init() {
	CreateCmd.AddCommand(createIrisCmd)

	createIrisCmd.Flags().BoolVar(&interactiveConfig, "interactive", true, "Interactive configuration (default)")
	createIrisCmd.Flags().BoolVar(&skipConfig, "skip-config", false, "Skip configuration, use placeholders")

	// Azure OpenAI flags
	createIrisCmd.Flags().StringVar(&azureEndpoint, "azure-endpoint", "", "Azure OpenAI endpoint")
	createIrisCmd.Flags().StringVar(&azureAPIKey, "azure-key", "", "Azure OpenAI API key")
	createIrisCmd.Flags().StringVar(&azureDeployment, "azure-deployment", "gpt-4o", "Azure deployment name")

	// SMTP flags
	createIrisCmd.Flags().StringVar(&smtpHost, "smtp-host", "", "SMTP server host")
	createIrisCmd.Flags().IntVar(&smtpPort, "smtp-port", 587, "SMTP server port")
	createIrisCmd.Flags().StringVar(&smtpUsername, "smtp-user", "", "SMTP username")
	createIrisCmd.Flags().StringVar(&smtpPassword, "smtp-pass", "", "SMTP password")
	createIrisCmd.Flags().StringVar(&emailFrom, "email-from", "", "From email address")
	createIrisCmd.Flags().StringVar(&emailTo, "email-to", "", "To email address")
}

func runCreateIris(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Iris installation")

	projectDir := "/opt/iris"

	// Step 1: Check prerequisites
	logger.Info("Step 1/8: Checking prerequisites")
	if err := iris.CheckPrerequisites(rc); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}

	// Step 2: Install Temporal if needed
	logger.Info("Step 2/8: Ensuring Temporal is installed")
	if err := iris.InstallTemporal(rc); err != nil {
		return fmt.Errorf("temporal installation failed: %w", err)
	}

	// Step 3: Create project structure
	logger.Info("Step 3/8: Creating project structure")
	if err := iris.CreateProjectStructure(rc, projectDir); err != nil {
		return fmt.Errorf("failed to create project structure: %w", err)
	}

	// Step 4: Gather configuration (interactive or from flags)
	logger.Info("Step 4/8: Configuration setup")
	irisConfig := iris.IrisConfiguration{
		Temporal: struct {
			HostPort  string
			Namespace string
			TaskQueue string
		}{
			HostPort:  "localhost:7233",
			Namespace: "default",
			TaskQueue: "wazuh-alerts",
		},
		Webhook: struct {
			Port int
		}{
			Port: 8080,
		},
		Azure: struct {
			Endpoint       string
			APIKey         string
			DeploymentName string
			APIVersion     string
		}{
			APIVersion: "2024-08-01-preview",
		},
	}

	if skipConfig {
		logger.Info("Skipping configuration - using placeholders")
		irisConfig = iris.GetPlaceholderConfig()
	} else if iris.HasConfigFlags(azureEndpoint, azureAPIKey, smtpHost, smtpUsername) {
		logger.Info("Using configuration from flags")
		irisConfig = iris.GetConfigFromFlags(azureEndpoint, azureAPIKey, azureDeployment,
			smtpHost, smtpPort, smtpUsername, smtpPassword, emailFrom, emailTo)
		if err := iris.ValidateConfiguration(irisConfig); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
	} else if interactiveConfig {
		logger.Info("Starting interactive configuration")
		if err := iris.GatherInteractiveConfig(rc, &irisConfig); err != nil {
			return fmt.Errorf("configuration failed: %w", err)
		}
	}

	// Create configuration file with gathered config
	if err := iris.CreateConfigFile(rc, projectDir, irisConfig); err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	// Step 5: Generate worker and webhook source
	logger.Info("Step 5/8: Generating worker and webhook source code")
	if err := iris.GenerateSourceFiles(rc, projectDir); err != nil {
		return fmt.Errorf("failed to generate source: %w", err)
	}

	// Step 6: Initialize Go module and dependencies
	logger.Info("Step 6/8: Installing Go dependencies")
	if err := iris.InstallDependencies(rc, projectDir); err != nil {
		return fmt.Errorf("failed to install dependencies: %w", err)
	}

	// Step 7: Create systemd service files
	logger.Info("Step 7/8: Creating systemd service files")
	if err := iris.CreateSystemdServices(rc, projectDir); err != nil {
		return fmt.Errorf("failed to create systemd services: %w", err)
	}

	// Step 8: Create test script and README
	logger.Info("Step 8/8: Creating test script and documentation")
	if err := iris.CreateTestScriptAndDocs(rc, projectDir); err != nil {
		return fmt.Errorf("failed to create test script: %w", err)
	}

	logger.Info("Iris installation completed successfully",
		zap.String("project_dir", projectDir))
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt:   1. Edit config: nano /opt/iris/config.yaml")
	logger.Info("terminal prompt:   2. Start Temporal: temporal server start-dev")
	logger.Info("terminal prompt:   3. Test install: eos debug iris")
	logger.Info("terminal prompt:   4. Start services: sudo systemctl start iris-worker iris-webhook")
	logger.Info("terminal prompt:   5. View Temporal UI: http://localhost:8233")

	return nil
}
