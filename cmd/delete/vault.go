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
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var purge bool

var DeleteVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Deletes the Vault installation",
	Long:  `Removes the Vault package (via snap, apt, or dnf) and optionally purges all configuration, data, and logs.`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("🧨 Deleting Vault...")

		distro := platform.DetectLinuxDistro(rc)
		osPlatform := platform.GetOSPlatform()
		if osPlatform != "linux" {
			otelzap.Ctx(rc.Ctx).Fatal("Vault uninstallation only supported on Linux")
		}

		// Kill Vault processes if any
		run(rc, "pkill", "-f", "vault server")

		// Remove Vault depending on platform
		switch distro {
		case "debian":
			run(rc, "apt-get", "remove", "-y", "vault")
		case "rhel":
			run(rc, "dnf", "remove", "-y", "vault")
		}

		if purge {
			otelzap.Ctx(rc.Ctx).Info("🧹 Purging Vault files and directories...")

			for _, path := range vault.GetVaultPurgePaths() {
				if err := os.RemoveAll(path); err != nil {
					otelzap.Ctx(rc.Ctx).Warn("Failed to remove path", zap.String("path", path), zap.Error(err))
				} else {
					otelzap.Ctx(rc.Ctx).Info("Removed path", zap.String("path", path))
				}
			}

			for _, wildcard := range vault.GetVaultWildcardPurgePaths() {
				run(rc, "sh", "-c", "rm -rf "+wildcard)
			}

			otelzap.Ctx(rc.Ctx).Info("Cleaning up Vault repo and keyring...")
			vault.Purge(rc, distro)
		} else {
			otelzap.Ctx(rc.Ctx).Info("Skipping purge (--no-purge provided)")
		}

		otelzap.Ctx(rc.Ctx).Info("✅ Vault deletion complete.")
		return nil
	}),
}

func init() {
	DeleteVaultCmd.Flags().BoolVar(&purge, "purge", true, "Remove Vault config, secrets, and logs (default: true)")
	DeleteVaultCmd.Flags().Lookup("purge").NoOptDefVal = "true"
	DeleteCmd.AddCommand(DeleteVaultCmd)
}

func run(rc *eos_io.RuntimeContext, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ Command failed", zap.String("cmd", name+" "+strings.Join(args, " ")), zap.Error(err))
	} else {
		otelzap.Ctx(rc.Ctx).Info("✅ Ran", zap.String("cmd", name+" "+strings.Join(args, " ")))
	}
}
