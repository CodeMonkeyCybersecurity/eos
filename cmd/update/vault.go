// cmd/update/vault.go

package update

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var VaultUpdateCmd = &cobra.Command{
	Use:   "vault",
	Short: "Updates Vault using the system's package manager",
	Long:  `Updates Vault using dnf or apt depending on the host's Linux distribution.`,
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			log.Fatal("This command must be run with sudo or as root.")
		}

		distro := platform.DetectLinuxDistro()
		var updateCmd *exec.Cmd

		switch distro {
		case "rhel":
			fmt.Println("🔄 Updating Vault via dnf...")
			updateCmd = exec.Command("dnf", "upgrade", "-y", "vault")
		case "debian":
			fmt.Println("🔄 Updating Vault via apt...")
			updateCmd = exec.Command("apt", "update")
			if err := updateCmd.Run(); err != nil {
				log.Fatal("Failed to run apt update", zap.Error(err))
			}
			updateCmd = exec.Command("apt", "install", "-y", "vault")
		default:
			log.Fatal("Unsupported or unknown distro", zap.String("distro", distro))
		}

		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr

		if err := updateCmd.Run(); err != nil {
			log.Fatal("Failed to update Vault", zap.Error(err))
		}
		fmt.Println("✅ Vault updated successfully.")
	},
}

func init() {
	UpdateCmd.AddCommand(VaultUpdateCmd)
}
