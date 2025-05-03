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

var purge bool

var DeleteVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Deletes the Vault installation",
	Long:  `Removes the Vault package (via snap, apt, or dnf) and optionally purges all configuration, data, and logs.`,

	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {

		log.Info("🧨 Deleting Vault...")

		distro := platform.DetectLinuxDistro(log)
		osPlatform := platform.GetOSPlatform(log)
		if osPlatform != "linux" {
			log.Fatal("Vault uninstallation only supported on Linux")
		}

		// Kill Vault processes if any
		run("sudo", "pkill", "-f", "vault server")

		// Remove Vault depending on platform
		switch distro {
		case "debian":
			run("sudo", "apt-get", "remove", "-y", "vault")
		case "rhel":
			run("sudo", "dnf", "remove", "-y", "vault")
		}

		if purge {
			log.Info("🧹 Purging Vault files and directories...")

			for _, path := range vault.GetVaultPurgePaths() {
				if err := os.RemoveAll(path); err != nil {
					log.Warn("Failed to remove path", zap.String("path", path), zap.Error(err))
				} else {
					log.Info("Removed path", zap.String("path", path))
				}
			}

			for _, wildcard := range vault.GetVaultWildcardPurgePaths() {
				run("sh", "-c", "rm -rf "+wildcard)
			}

			log.Info("Cleaning up Vault repo and keyring...")
			vault.Purge(distro, log)
		} else {
			log.Info("Skipping purge (--no-purge provided)")
		}

		log.Info("✅ Vault deletion complete.")
		return nil
	}),
}

func init() {
	DeleteVaultCmd.Flags().BoolVar(&purge, "purge", true, "Remove Vault config, secrets, and logs (default: true)")
	DeleteVaultCmd.Flags().Lookup("purge").NoOptDefVal = "true"
	DeleteCmd.AddCommand(DeleteVaultCmd)
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Warn("Command failed", zap.String("cmd", name+" "+args[0]), zap.Error(err))
	} else {
		log.Info("Ran", zap.String("cmd", name+" "+args[0]))
	}
}
