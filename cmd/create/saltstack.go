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

This command uses the official Salt bootstrap script method - the most reliable installation approach:
- Downloads from the correct bootstrap URL (https://bootstrap.saltproject.io)
- Validates script content to prevent HTML/JSON corruption
- Supports both masterless and master-minion configurations
- Includes checksum verification for security
- Automatic configuration and verification

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
		bootstrapURL, _ := cmd.Flags().GetString("bootstrap-url")
		skipChecksum, _ := cmd.Flags().GetBool("skip-checksum")

		// Create configuration
		config := &saltstack.Config{
			MasterMode: masterMode,
			SkipTest:   skipTest,
			LogLevel:   logLevel,
			Version:    version,
		}

		// Store bootstrap configuration in context for installer
		rc.Attributes["bootstrap_url"] = bootstrapURL
		if skipChecksum {
			rc.Attributes["skip_checksum"] = "true"
		}

		// Use single, reliable installation method
		logger.Info("Installing Salt using official bootstrap script method")
		if err := saltstack.Install(rc, config); err != nil {
			logger.Error("Salt installation failed", zap.Error(err))
			return err
		}

		return nil
	}),
}

func init() {
	// Add command flags for simplified bootstrap installation
	saltstackCmd.Flags().Bool("master-mode", false, "Install as master-minion instead of masterless")
	saltstackCmd.Flags().Bool("skip-test", false, "Skip the verification test")
	saltstackCmd.Flags().String("log-level", "warning", "Set Salt log level (debug, info, warning, error)")
	saltstackCmd.Flags().String("version", "latest", "Salt version to install ('latest' for automatic detection)")
	
	// Bootstrap-specific flags (using correct URL)
	saltstackCmd.Flags().String("bootstrap-url", "https://bootstrap.saltproject.io", "Bootstrap script URL (updated to correct endpoint)")
	saltstackCmd.Flags().Bool("skip-checksum", false, "Skip bootstrap script checksum verification (not recommended)")

	// Register with parent command
	CreateCmd.AddCommand(saltstackCmd)
}