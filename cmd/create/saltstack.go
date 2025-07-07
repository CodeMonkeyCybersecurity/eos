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

This command will:
- Add the official SaltStack repository for Ubuntu
- Install salt-minion package
- Configure Salt for masterless operation
- Create necessary directory structure
- Verify the installation with a test state

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

		// Create configuration
		config := &saltstack.Config{
			MasterMode:   masterMode,
			SkipTest:     skipTest,
			LogLevel:     logLevel,
			Version:      version,
			ForceVersion: forceVersion,
		}

		// Create version-aware installer
		installer := saltstack.NewVersionAwareInstaller(rc)

		// Perform version-aware installation
		logger.Info("Installing SaltStack with version detection")
		if err := installer.InstallWithVersionDetection(rc, config); err != nil {
			logger.Error("Failed to install Salt", zap.Error(err))
			return err
		}

		// Display success message
		logger.Info("SaltStack installation completed successfully",
			zap.String("mode", config.GetMode()),
			zap.String("config_path", "/etc/salt/minion"),
			zap.String("states_path", "/srv/salt/eos"),
		)

		logger.Info("Other Eos commands can now use Salt for configuration management")
		logger.Info("Example: salt-call --local state.apply eos.mystate")

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

	// Register with parent command
	CreateCmd.AddCommand(saltstackCmd)
}