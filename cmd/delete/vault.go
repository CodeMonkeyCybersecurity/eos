// cmd/delete/vault.go
package delete

import (
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var purge bool // <-- global flag for --purge

// vaultDeleteCmd represents the "delete vault" command.
var DeleteVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Deletes the Vault installation",
	Long:  `Removes the Vault package (via snap, apt, or dnf) and optionally purges all configuration, data, and logs.`,

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

		osPlatform := platform.GetOSPlatform()
		distro := platform.DetectLinuxDistro()

		switch {
		case osPlatform != "linux":
			log.Fatal("Vault uninstallation only supported on Linux")
		case distro == "debian":
			log.Info("Removing Vault via apt...")
			removeCmd := exec.Command("apt-get", "remove", "-y", "vault")
			removeCmd.Stdout = os.Stdout
			removeCmd.Stderr = os.Stderr
			if err := removeCmd.Run(); err != nil {
				log.Fatal("Failed to remove Vault via apt", zap.Error(err))
			}
		case distro == "rhel":
			log.Info("Removing Vault via dnf...")
			removeCmd := exec.Command("dnf", "remove", "-y", "vault")
			removeCmd.Stdout = os.Stdout
			removeCmd.Stderr = os.Stderr
			if err := removeCmd.Run(); err != nil {
				log.Fatal("Failed to remove Vault via dnf", zap.Error(err))
			}
		default:
			log.Info("Attempting to remove Vault via snap...")
			removeCmd := exec.Command("snap", "remove", "vault")
			removeCmd.Stdout = os.Stdout
			removeCmd.Stderr = os.Stderr
			if err := removeCmd.Run(); err != nil {
				log.Warn("Failed to remove Vault via snap", zap.Error(err))
			}
		}

		if purge {
			log.Info("Purging Vault configuration, data, and logs...")
			configDirs := []string{
				"/etc/vault.d",
				"/opt/vault",
				"/var/lib/vault",
				"/var/log/vault.log",
				"/var/snap/vault",
			}
			for _, dir := range configDirs {
				if err := os.RemoveAll(dir); err != nil {
					log.Warn("Failed to remove", zap.String("path", dir), zap.Error(err))
				} else {
					log.Info("Removed", zap.String("path", dir))
				}
			}
		} else {
			log.Info("Purge flag not set; skipping configuration and data cleanup.")
		}

		log.Info("Vault deletion complete.")
	},
}

func init() {
	DeleteVaultCmd.Flags().BoolVar(&purge, "purge", false, "Also remove Vault config, secrets, and logs")
	DeleteCmd.AddCommand(DeleteVaultCmd)
}