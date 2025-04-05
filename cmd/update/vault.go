package update

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// vaultUpdateCmd represents the "update vault" command.
var VaultUpdateCmd = &cobra.Command{
	Use:   "vault",
	Short: "Updates the Vault installation via snap",
	Long:  `Runs a snap refresh for Vault, updating it to the latest available version.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check for root privileges.
		if os.Geteuid() != 0 {
			log.Fatal("This command must be run with sudo or as root.")
		}

		fmt.Println("Updating Vault via snap...")
		updateCmd := exec.Command("snap", "refresh", "vault")
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr

		if err := updateCmd.Run(); err != nil {
			log.Fatal("Failed to update Vault: %v", zap.Error(err))
		}

		fmt.Println("Vault updated successfully.")
	},
}

func init() {
	// Assuming you have a parent "update" command.
	UpdateCmd.AddCommand(VaultUpdateCmd)
}
