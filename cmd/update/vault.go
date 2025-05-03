// cmd/update/vault.go

package update

import (
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var VaultUpdateCmd = &cobra.Command{
	Use:   "vault",
	Short: "Updates Vault using the system's package manager",
	Long:  `Updates Vault using dnf or apt depending on the host's Linux distribution.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			log.Fatal("This command must be run with sudo or as root.")
		}

		distro := platform.DetectLinuxDistro(log)
		var updateCmd *exec.Cmd

		switch distro {
		case "rhel":
			fmt.Println("🔄 Updating Vault via dnf...")
			updateCmd = exec.Command("sudo", "dnf", "upgrade", "-y", "vault")
		case "debian":
			fmt.Println("🔄 Updating Vault via apt...")
			updateCmd = exec.Command("sudo", "apt", "update")
			if err := updateCmd.Run(); err != nil {
				log.Fatal("Failed to run apt update", zap.Error(err))
			}
			updateCmd = exec.Command("sudo", "apt", "install", "-y", "vault")
		default:
			log.Fatal("Unsupported or unknown distro", zap.String("distro", distro))
		}

		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr

		if err := updateCmd.Run(); err != nil {
			log.Fatal("Failed to update Vault", zap.Error(err))
		}
		fmt.Println("✅ Vault updated successfully.")
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(VaultUpdateCmd)
}
