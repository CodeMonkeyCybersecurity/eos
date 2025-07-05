package container

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewInstallCmd creates the Docker installation command
func NewInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install Docker and configure it for non-root usage",
		Long: `Install Docker CE, set up repository and user permissions, and verify with hello-world.

This command performs a complete Docker installation:
- Removes conflicting packages and snap Docker
- Updates package repositories  
- Installs prerequisites and GPG keys
- Adds Docker repository
- Installs Docker CE and related components
- Configures non-root user access
- Verifies installation with hello-world container

Examples:
  eos container install                    # Install Docker with default settings
  eos container install --skip-verify     # Skip hello-world verification
  eos container install --no-user-setup   # Skip non-root user configuration`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
			skipVerify, _ := cmd.Flags().GetBool("skip-verify")
			noUserSetup, _ := cmd.Flags().GetBool("no-user-setup")

			logger.Info("Starting Docker installation process",
				zap.Bool("skip_verify", skipVerify),
				zap.Bool("no_user_setup", noUserSetup))

			// Check for root privileges
			privilegeManager := privilege_check.NewPrivilegeManager(nil)
			if err := privilegeManager.CheckSudoOnly(rc); err != nil {
				logger.Error("Root privileges required for Docker installation", zap.Error(err))
				return err
			}

			// Update package repositories first
			logger.Info("Updating package repositories")
			if err := platform.PackageUpdate(rc, false); err != nil {
				logger.Warn("Package update failed", zap.Error(err))
				// Continue anyway as this might not be critical
			}

			// Use the comprehensive Docker installation from container package
			if err := container.InstallDocker(rc); err != nil {
				logger.Error("Docker installation failed", zap.Error(err))
				return err
			}

			logger.Info("Docker installation and configuration completed successfully")
			return nil
		}),
	}

	cmd.Flags().Bool("skip-verify", false, "Skip hello-world verification")
	cmd.Flags().Bool("no-user-setup", false, "Skip non-root user configuration")

	return cmd
}