package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var saltstackCmd = &cobra.Command{
	Use:   "saltstack",
	Short: "Install and configure SaltStack for configuration management",
	Long: `Install and configure SaltStack in masterless mode for use by other Eos commands.

This command uses multiple robust installation methods with automatic fallbacks:
1. Official Salt bootstrap script (with GitHub mirrors)
2. Local package manager (Ubuntu repositories)
3. Version-aware external repositories
4. Manual installation guidance

Features:
- Network connectivity testing and smart source selection
- Content validation to prevent HTML/JSON corruption
- Retry logic with exponential backoff for transient failures
- Automatic masterless configuration
- State tree structure creation
- Comprehensive verification testing

After installation, other Eos commands can use Salt for configuration management
by placing state files in /srv/salt/eos/ and applying them with salt-call.`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		logger.Info("Starting SaltStack installation")

		// Get configuration from flags
		masterMode, _ := cmd.Flags().GetBool("master-mode")
		skipTest, _ := cmd.Flags().GetBool("skip-test")
		logLevel, _ := cmd.Flags().GetString("log-level")
		version, _ := cmd.Flags().GetString("version")
		forceVersion, _ := cmd.Flags().GetBool("force-version")
		bootstrapURL, _ := cmd.Flags().GetString("bootstrap-url")
		skipChecksum, _ := cmd.Flags().GetBool("skip-checksum")
		configureMasterless, _ := cmd.Flags().GetBool("configure-masterless")

		// Create configuration
		config := &saltstack.Config{
			MasterMode:   masterMode,
			SkipTest:     skipTest,
			LogLevel:     logLevel,
			Version:      version,
			ForceVersion: forceVersion,
		}

		// Store bootstrap configuration in context for bootstrap installer
		rc.Attributes["bootstrap_url"] = bootstrapURL
		if skipChecksum {
			rc.Attributes["skip_checksum"] = "true"
		}
		if !configureMasterless {
			rc.Attributes["configure_masterless"] = "false"
		}

		// Create installation manager with fallback strategies
		installManager := saltstack.NewInstallationManager(rc)

		// Check for forced installation method
		installMethod, _ := cmd.Flags().GetString("install-method")
		
		if installMethod != "auto" {
			logger.Info("Using forced installation method", zap.String("method", installMethod))
			if err := installManager.InstallWithStrategy(rc, installMethod, config); err != nil {
				logger.Error("Forced installation method failed", zap.Error(err))
				return err
			}
		} else {
			// Use automatic installation with fallbacks
			logger.Info("Installing SaltStack with automatic method selection and fallbacks")
			if err := installManager.Install(rc, config); err != nil {
				logger.Error("All installation methods failed", zap.Error(err))
				return err
			}
		}

		// Display success message with next steps
		saltstack.PrintSuccessMessage(rc, config)

		return nil
	}),
}

func init() {
	// Add command flags
	saltstackCmd.Flags().Bool("master-mode", false, "Install as master-minion instead of masterless")
	saltstackCmd.Flags().Bool("skip-test", false, "Skip the verification test")
	saltstackCmd.Flags().String("log-level", "warning", "Set Salt log level (debug, info, warning, error)")
	saltstackCmd.Flags().String("version", "latest", "Salt version to install ('latest' for automatic detection)")
	saltstackCmd.Flags().Bool("force-version", false, "Force installation of specified version even if newer exists")
	
	// Bootstrap-specific flags
	saltstackCmd.Flags().String("bootstrap-url", "https://bootstrap.saltstack.com", "Custom bootstrap script URL")
	saltstackCmd.Flags().Bool("skip-checksum", false, "Skip bootstrap script checksum verification (not recommended)")
	saltstackCmd.Flags().String("install-method", "auto", "Force specific installation method: auto, Bootstrap Script, Local Package Manager, Version-Aware Repository, Direct Package Download, Manual Installation Guide")
	saltstackCmd.Flags().Bool("configure-masterless", true, "Automatically configure Salt for masterless operation")

	// Register with parent command
	CreateCmd.AddCommand(saltstackCmd)
}