package delete

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// vaultDeleteCmd represents the "delete vault" command.
var vaultDeleteCmd = &cobra.Command{
	Use:   "vault",
	Short: "Deletes the Vault installation",
	Long:  `Removes the Vault snap package and optionally cleans up its configuration, data, and logs.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Ensure the command is run as root.
		if os.Geteuid() != 0 {
			log.Fatal("This command must be run with sudo or as root.")
		}

		fmt.Println("Deleting Vault installation...")

		// Kill any running Vault process.
		killCmd := exec.Command("pkill", "-f", "vault server")
		killCmd.Stdout = os.Stdout
		killCmd.Stderr = os.Stderr
		if err := killCmd.Run(); err != nil {
			log.Printf("Warning: could not kill Vault process (it might not be running): %v", err)
		} else {
			fmt.Println("Stopped Vault process.")
		}

		// Remove the Vault snap.
		removeCmd := exec.Command("snap", "remove", "vault")
		removeCmd.Stdout = os.Stdout
		removeCmd.Stderr = os.Stderr
		if err := removeCmd.Run(); err != nil {
			log.Fatalf("Failed to remove Vault snap: %v", err)
		}
		fmt.Println("Vault snap removed successfully.")

		// Optionally remove Vault configuration and data.
		configDir := "/var/snap/vault"
		if err := os.RemoveAll(configDir); err != nil {
			log.Printf("Warning: failed to remove configuration directory %s: %v", configDir, err)
		} else {
			fmt.Printf("Removed configuration directory %s\n", configDir)
		}

		fmt.Println("Vault deletion complete.")
	},
}

func init() {
	// Add the vaultDeleteCmd to your parent DeleteCmd.
	// Make sure DeleteCmd is defined in your cmd/delete package.
	DeleteCmd.AddCommand(vaultDeleteCmd)
}
