// cmd/delete/vault.go
package delete

import (
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var purge bool // <-- global flag for --purge

// vaultDeleteCmd represents the "delete vault" command.
var DeleteVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Deletes the Vault installation",
	Long:  `Removes the Vault package (via snap, apt, or dnf) and optionally purges all configuration, data, and logs.`,

	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
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

		osPlatform := platform.GetOSPlatform(log)
		distro := platform.DetectLinuxDistro(log)

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
			log.Info("🧨 Purging Vault config, data, and runtime paths...")
			for _, path := range vault.GetVaultPurgePaths() {
				if err := os.RemoveAll(path); err != nil {
					log.Warn("Failed to remove path during purge", zap.String("path", path), zap.Error(err))
				} else {
					log.Info("🧹 Removed path", zap.String("path", path))
				}
			}

			log.Info("🧼 Cleaning up Vault repo and keyring files...")
			vault.Purge(distro, log)
		} else {
			log.Info("Skipping purge because --no-purge was specified.")
		}

		// Attempt a best-effort Vault client setup
		client, err := vault.NewClient(log)
		if err != nil {
			log.Warn("Skipping Vault health check — client unavailable", zap.Error(err))
		} else {
			report, _ := vault.Check(client, log, nil, "") // no storedHashes or root token
			if report == nil || !report.Installed {
				log.Warn("Vault not detected after deletion")
			} else {
				log.Info("Post-delete Vault check complete", zap.Any("report", report))
			}
		}

		log.Info("Vault deletion complete.")
		return nil
	}),
}

func init() {
	DeleteVaultCmd.Flags().BoolVar(&purge, "purge", true, "Remove Vault config, secrets, and logs (default: true)")
	DeleteVaultCmd.Flags().Lookup("purge").NoOptDefVal = "true" // support --no-purge
	DeleteCmd.AddCommand(DeleteVaultCmd)
}
