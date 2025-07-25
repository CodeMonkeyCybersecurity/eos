package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var saltstackEnhancedCmd = &cobra.Command{
	Use:     "saltstack-enhanced",
	Aliases: []string{"salt-enhanced", "salt-api"},
	Short:   "Install SaltStack with enhanced API-first configuration",
	Long: `Install and configure SaltStack with a focus on API-first operation.

This enhanced version ensures:
- Proper file_roots configuration for Eos states
- REST API is configured and running
- API credentials are generated and saved
- All services are properly started
- Ready for Consul and other deployments

Key differences from standard install:
- Automatic API configuration
- Secure credential generation
- File_roots pre-configured for /opt/eos/salt/states
- Comprehensive verification`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Check root permissions
		if os.Geteuid() != 0 {
			return eos_err.NewUserError("this command requires root privileges")
		}

		logger.Info("Starting enhanced SaltStack installation with API-first approach")

		// Get configuration from flags
		masterMode, _ := cmd.Flags().GetBool("master-mode")
		skipTest, _ := cmd.Flags().GetBool("skip-test")
		logLevel, _ := cmd.Flags().GetString("log-level")
		forceReinstall, _ := cmd.Flags().GetBool("force")

		// Create configuration
		config := &saltstack.Config{
			MasterMode: masterMode,
			SkipTest:   skipTest,
			LogLevel:   logLevel,
		}

		// Check if already installed
		if !forceReinstall {
			if apiConfigured, err := checkAPIConfiguration(rc); err == nil && apiConfigured {
				logger.Info("Salt API is already configured and running")
				logger.Info("terminal prompt: Salt API is already configured.")
				logger.Info("terminal prompt: Use --force to reconfigure.")
				
				// Show current configuration
				if err := showCurrentConfig(rc); err != nil {
					logger.Warn("Failed to show current config", zap.Error(err))
				}
				
				return nil
			}
		}

		// Use the enhanced installation
		logger.Info("Installing Salt with enhanced API configuration")
		if err := saltstack.Install(rc, config); err != nil {
			logger.Error("Salt installation failed", zap.Error(err))
			return err
		}

		// Verify API is working
		logger.Info("Verifying Salt API functionality")
		if err := verifySaltAPI(rc); err != nil {
			logger.Error("Salt API verification failed", zap.Error(err))
			return err
		}

		// Display success information
		displaySuccessInfo(rc, logger)

		return nil
	}),
}

func checkAPIConfiguration(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if credentials exist
	if creds, err := saltstack.LoadAPICredentials(); err == nil && creds != nil {
		logger.Debug("Found API credentials", 
			zap.String("url", creds.URL),
			zap.String("user", creds.Username))
		
		// Try to create API client
		factory := salt.NewClientFactory(rc)
		if client, err := factory.CreateClient(); err == nil {
			// Test API connectivity
			if err := client.CheckStatus(rc.Ctx); err == nil {
				return true, nil
			}
		}
	}

	return false, nil
}

func verifySaltAPI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Load credentials
	creds, err := saltstack.LoadAPICredentials()
	if err != nil {
		return fmt.Errorf("failed to load API credentials: %w", err)
	}

	// Set environment variables
	os.Setenv("SALT_API_URL", creds.URL)
	os.Setenv("SALT_API_USER", creds.Username)
	os.Setenv("SALT_API_PASSWORD", creds.Password)

	// Create API client
	factory := salt.NewClientFactory(rc)
	client, err := factory.CreateClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Test basic functionality
	if err := client.CheckStatus(rc.Ctx); err != nil {
		return fmt.Errorf("API status check failed: %w", err)
	}

	logger.Info("Salt API verified successfully")
	return nil
}

func showCurrentConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Load and display current credentials
	if creds, err := saltstack.LoadAPICredentials(); err == nil {
		logger.Info("terminal prompt: Current Salt API Configuration:")
		logger.Info(fmt.Sprintf("terminal prompt:   URL: %s", creds.URL))
		logger.Info(fmt.Sprintf("terminal prompt:   User: %s", creds.Username))
		logger.Info("terminal prompt:   Credentials: /etc/eos/salt/api.env")
	}

	// Check file_roots status
	if status, err := saltstack.GetFileRootsStatus(rc); err == nil {
		if dirStatus, ok := status["directories"].(map[string]bool); ok {
			logger.Info("terminal prompt: File roots status:")
			for dir, exists := range dirStatus {
				status := "✗"
				if exists {
					status = "✓"
				}
				logger.Info(fmt.Sprintf("terminal prompt:   %s %s", status, dir))
			}
		}
	}

	return nil
}

func displaySuccessInfo(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) {
	logger.Info("terminal prompt: ===== Salt API Installation Complete =====")
	
	// Load and display credentials info
	if creds, err := saltstack.LoadAPICredentials(); err == nil {
		logger.Info("terminal prompt: ")
		logger.Info(fmt.Sprintf("terminal prompt: API URL: %s", creds.URL))
		logger.Info(fmt.Sprintf("terminal prompt: API User: %s", creds.Username))
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: To use the Salt API:")
		logger.Info("terminal prompt:   source /etc/eos/salt/api.env")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Test commands:")
		logger.Info("terminal prompt:   # Test local Salt")
		logger.Info("terminal prompt:   salt-call --local test.ping")
		logger.Info("terminal prompt:   ")
		logger.Info("terminal prompt:   # Test API")
		logger.Info("terminal prompt:   curl -k https://localhost:8000")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Now ready to deploy services like Consul:")
		logger.Info("terminal prompt:   eos create consul")
	}
}

func init() {
	// Add command flags
	saltstackEnhancedCmd.Flags().Bool("master-mode", false, "Install as master-minion instead of masterless")
	saltstackEnhancedCmd.Flags().Bool("skip-test", false, "Skip the verification test")
	saltstackEnhancedCmd.Flags().String("log-level", "warning", "Set Salt log level (debug, info, warning, error)")
	saltstackEnhancedCmd.Flags().Bool("force", false, "Force reinstallation even if already configured")

	// Register with parent command
	CreateCmd.AddCommand(saltstackEnhancedCmd)
}