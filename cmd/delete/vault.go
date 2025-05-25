// cmd/delete/vault.go

package delete

import (
	"os"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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

	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("🧨 Deleting Vault...")

		distro := platform.DetectLinuxDistro()
		osPlatform := platform.GetOSPlatform()
		if osPlatform != "linux" {
			zap.L().Fatal("Vault uninstallation only supported on Linux")
		}

		// Kill Vault processes if any
		run("pkill", "-f", "vault server")

		// Remove Vault depending on platform
		switch distro {
		case "debian":
			run("apt-get", "remove", "-y", "vault")
		case "rhel":
			run("dnf", "remove", "-y", "vault")
		}

		if purge {
			zap.L().Info("🧹 Purging Vault files and directories...")

			for _, path := range vault.GetVaultPurgePaths() {
				if err := os.RemoveAll(path); err != nil {
					zap.L().Warn("Failed to remove path", zap.String("path", path), zap.Error(err))
				} else {
					zap.L().Info("Removed path", zap.String("path", path))
				}
			}

			for _, wildcard := range vault.GetVaultWildcardPurgePaths() {
				run("sh", "-c", "rm -rf "+wildcard)
			}

			zap.L().Info("Cleaning up Vault repo and keyring...")
			vault.Purge(distro)
		} else {
			zap.L().Info("Skipping purge (--no-purge provided)")
		}

		zap.L().Info("✅ Vault deletion complete.")
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
		zap.L().Warn("❌ Command failed", zap.String("cmd", name+" "+strings.Join(args, " ")), zap.Error(err))
	} else {
		zap.L().Info("✅ Ran", zap.String("cmd", name+" "+strings.Join(args, " ")))
	}
}
