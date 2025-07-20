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
	Short: "Updates Vault using SaltStack (recommended) or system package manager",
	Long: `Updates HashiCorp Vault using SaltStack for managed deployments or system package manager as fallback.

This command prioritizes SaltStack-based updates for better configuration management:
- If SaltStack is available: Uses Salt state to update Vault with proper configuration management
- Fallback: Uses system package manager (dnf/apt) for direct updates

The command requires root privileges to perform system updates.

Examples:
  sudo eos update vault             # Update Vault (Salt preferred)
  eos update vault                  # Will prompt for root if not running as root

Recommended: Use 'eos create vault-salt' for new installations.`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		logger := otelzap.Ctx(rc.Ctx)

		if os.Geteuid() != 0 {
			logger.Fatal("This command must be run with sudo or as root.")
		}

		// Try SaltStack-based update first (preferred method)
		if _, err := exec.LookPath("salt-call"); err == nil {
			logger.Info("SaltStack detected, using Salt-based Vault update")
			
			// Execute Salt state for Vault update
			saltCmd := exec.Command("salt-call", "--local", "state.apply", "hashicorp.vault.install", "--output=json")
			saltCmd.Stdout = os.Stdout
			saltCmd.Stderr = os.Stderr
			
			if err := saltCmd.Run(); err != nil {
				logger.Warn("Salt-based update failed, falling back to package manager", zap.Error(err))
			} else {
				logger.Info("Vault updated successfully via SaltStack")
				return nil
			}
		} else {
			logger.Warn("SaltStack not available, using direct package manager update")
			logger.Warn("DEPRECATION WARNING: Direct package updates are deprecated. Consider using 'eos create vault-salt' for managed deployments.")
		}

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
