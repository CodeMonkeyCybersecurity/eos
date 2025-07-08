// cmd/update/vault.go

package update

import (
	"fmt"
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
	Long:  `Updates Vault using dnf or apt depending on the host's Linux distribution.`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		if os.Geteuid() != 0 {
			otelzap.Ctx(rc.Ctx).Fatal("This command must be run with sudo or as root.")
		}

		distro := platform.DetectLinuxDistro(rc)
		var updateCmd *exec.Cmd

		switch distro {
		case "rhel":
			fmt.Println(" Updating Vault via dnf...")
			updateCmd = exec.Command("dnf", "upgrade", "-y", "vault")
		case "debian":
			fmt.Println(" Updating Vault via apt...")
			updateCmd = exec.Command("apt", "update")
			if err := updateCmd.Run(); err != nil {
				otelzap.Ctx(rc.Ctx).Fatal("Failed to run apt update", zap.Error(err))
			}
			updateCmd = exec.Command("apt", "install", "-y", "vault")
		default:
			otelzap.Ctx(rc.Ctx).Fatal("Unsupported or unknown distro", zap.String("distro", distro))
		}

		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr

		if err := updateCmd.Run(); err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to update Vault", zap.Error(err))
		}
		fmt.Println(" Vault updated successfully.")
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(VaultUpdateCmd)
}
