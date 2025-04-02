// cmd/delete/vault.go
package delete

import (
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// vaultDeleteCmd represents the "delete vault" command.
var DeleteVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Deletes the Vault installation",
	Long:  `Removes the Vault snap package and optionally cleans up its configuration, data, and logs.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Ensure the command is run as root.
		if os.Geteuid() != 0 {
			log.Fatal("This command must be run with sudo or as root.")
		}

		log.Info("Deleting Vault installation...")

		// Kill any running Vault process.
		killCmd := exec.Command("pkill", "-f", "vault server")
		killCmd.Stdout = os.Stdout
		killCmd.Stderr = os.Stderr
		if err := killCmd.Run(); err != nil {
			log.Warn("Could not kill Vault process (it might not be running)", zap.Error(err))
		} else {
			log.Info("Stopped Vault process.")
		}

		// Remove the Vault snap.
		removeCmd := exec.Command("snap", "remove", "vault")
		removeCmd.Stdout = os.Stdout
		removeCmd.Stderr = os.Stderr
		if err := removeCmd.Run(); err != nil {
			log.Fatal("Failed to remove Vault snap", zap.Error(err))
		}
		log.Info("Vault snap removed successfully.")

		// Optionally remove Vault configuration and data.
		configDir := "/var/snap/vault"
		if err := os.RemoveAll(configDir); err != nil {
			log.Warn("Failed to remove configuration directory", zap.String("directory", configDir), zap.Error(err))
		} else {
			log.Info("Removed configuration directory", zap.String("directory", configDir))
		}

		log.Info("Vault deletion complete.")
	},
}


func init() {

	DeleteCmd.AddCommand(DeleteVaultCmd)
}
