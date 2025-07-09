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
	Short: "Updates Vault using the system's package manager",
	Long: `Updates HashiCorp Vault using the system's package manager.

This command automatically detects the Linux distribution and uses the appropriate package manager:
- RHEL/CentOS/Fedora: Uses dnf to upgrade vault
- Debian/Ubuntu: Uses apt to install/update vault

The command requires root privileges to perform system package updates.

Examples:
  sudo eos update vault             # Update Vault on current system
  eos update vault                  # Will prompt for root if not running as root`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		logger := otelzap.Ctx(rc.Ctx)

		if os.Geteuid() != 0 {
			logger.Fatal("This command must be run with sudo or as root.")
		}

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
		logger.Info("Vault updated successfully")
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(VaultUpdateCmd)
}
