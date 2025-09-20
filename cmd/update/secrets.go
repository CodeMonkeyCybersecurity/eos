// cmd/update/secrets.go

package update

import (
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var VaultUpdateCmd = &cobra.Command{
	Use:   "vault",
	Short: "Updates Vault using  (recommended) or system package manager",
	Long: `Updates HashiCorp Vault using  for managed deployments or system package manager as fallback.

This command prioritizes -based updates for better configuration management:
- If  is available: Uses  state to update Vault with proper configuration management
- Fallback: Uses system package manager (dnf/apt) for direct updates

The command requires root privileges to perform system updates.

Examples:
  sudo eos update vault             # Update Vault ( preferred)
  eos update vault                  # Will prompt for root if not running as root

Recommended: Use 'eos create vault-' for new installations.`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		logger := otelzap.Ctx(rc.Ctx)

		if os.Geteuid() != 0 {
			logger.Fatal("This command must be run with sudo or as root.")
		}

		// Show deprecation warning for direct package updates
		logger.Warn("DEPRECATION WARNING: Direct package updates are deprecated. Consider using 'eos create vault-' for managed deployments.")

		// Fallback to direct package manager update
		distro := platform.DetectLinuxDistro(rc)
		var updateCmd *exec.Cmd

		switch distro {
		case "rhel":
			logger.Info("Updating Vault via dnf", zap.String("distro", distro))
			updateCmd = exec.Command("dnf", "upgrade", "-y", "vault")
		case "debian":
			logger.Info("Updating Vault via apt", zap.String("distro", distro))
			updateCmd = exec.Command("apt", "update")
			if err := updateCmd.Run(); err != nil {
				logger.Fatal("Failed to run apt update", zap.Error(err))
			}
			updateCmd = exec.Command("apt", "install", "-y", "vault")
		default:
			logger.Fatal("Unsupported or unknown distro", zap.String("distro", distro))
		}

		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr

		if err := updateCmd.Run(); err != nil {
			logger.Fatal("Failed to update Vault", zap.Error(err))
		}
		logger.Info("Vault updated successfully via package manager")
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(VaultUpdateCmd)
}
