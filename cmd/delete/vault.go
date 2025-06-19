// cmd/delete/vault.go

package delete

import (
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
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

		// Stop services before removal
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Stopping Vault services")
		if err := execute.RunSimple(rc.Ctx, "systemctl", "stop", "vault.service"); err != nil {
			logger.Warn("Failed to stop vault service", zap.Error(err))
		}
		if err := execute.RunSimple(rc.Ctx, "systemctl", "stop", "vault-agent-eos.service"); err != nil {
			logger.Warn("Failed to stop vault agent service", zap.Error(err))
		}

		// Kill any remaining Vault processes
		if err := execute.RunSimple(rc.Ctx, "pkill", "-f", "vault server"); err != nil {
			logger.Info("No vault server processes found")
		}

		// Remove Vault depending on platform
		switch distro {
		case "debian":
			if err := execute.RunSimple(rc.Ctx, "apt-get", "remove", "-y", "vault"); err != nil {
				logger.Error("Failed to remove vault package", zap.Error(err))
				return err
			}
		case "rhel":
			if err := execute.RunSimple(rc.Ctx, "dnf", "remove", "-y", "vault"); err != nil {
				logger.Error("Failed to remove vault package", zap.Error(err))
				return err
			}
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
				if err := execute.RunSimple(rc.Ctx, "rm", "-rf", wildcard); err != nil {
					otelzap.Ctx(rc.Ctx).Warn("Failed to remove wildcard path", zap.String("path", wildcard), zap.Error(err))
				} else {
					otelzap.Ctx(rc.Ctx).Info("Removed wildcard path", zap.String("path", wildcard))
				}
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

// run function removed - replaced with secure execute.RunSimple calls
