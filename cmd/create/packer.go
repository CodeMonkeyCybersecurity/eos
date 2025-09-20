// cmd/create/packer.go
package create

import (
	"fmt"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/packer"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var CreatePackerCmd = &cobra.Command{
	Use:   "packer",
	Short: "Install HashiCorp Packer using native installer",
	Long: `Install HashiCorp Packer for image building.

This installer provides:
- Direct binary or repository installation
- Plugin directory setup
- Cache configuration
- Environment variables

Examples:
  eos create packer                             # Latest version
  eos create packer --version=1.10.0            # Specific version`,
	RunE: eos_cli.Wrap(runCreatePackerNative),
}

func init() {
	CreateCmd.AddCommand(CreatePackerCmd)
	
	// Packer flags
	CreatePackerCmd.Flags().String("version", "latest", "Packer version to install")
	CreatePackerCmd.Flags().String("plugin-dir", "/var/lib/packer/plugins", "Plugin directory")
	CreatePackerCmd.Flags().String("cache-dir", "/var/cache/packer", "Cache directory")
	CreatePackerCmd.Flags().Bool("clean", false, "Clean install")
	CreatePackerCmd.Flags().Bool("force", false, "Force reinstall")
	CreatePackerCmd.Flags().Bool("use-repository", false, "Install via APT repository")
}

func runCreatePackerNative(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Packer using native installer")

	// Parse flags
	config := &packer.InstallConfig{
		Version:         cmd.Flag("version").Value.String(),
		UseRepository:   cmd.Flag("use-repository").Value.String() == "true",
		PluginDirectory: cmd.Flag("plugin-dir").Value.String(),
		CacheDirectory:  cmd.Flag("cache-dir").Value.String(),
		CleanInstall:    cmd.Flag("clean").Value.String() == "true",
		ForceReinstall:  cmd.Flag("force").Value.String() == "true",
	}

	// Create and run installer
	installer := packer.NewPackerInstaller(rc, config)
	if err := installer.Install(); err != nil {
		return fmt.Errorf("packer installation failed: %w", err)
	}

	logger.Info("Packer installation completed successfully")
	logger.Info("terminal prompt: Packer is installed. Check version with: packer version")
	return nil
}
