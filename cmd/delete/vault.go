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

		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting Vault deletion process",
			zap.String("operation", "vault_deletion"),
			zap.Bool("purge_enabled", purge))

		distro := platform.DetectLinuxDistro(rc)
		osPlatform := platform.GetOSPlatform()
		logger.Info("Detected platform information",
			zap.String("distro", distro),
			zap.String("os_platform", osPlatform))

		if osPlatform != "linux" {
			logger.Fatal("Vault uninstallation only supported on Linux",
				zap.String("detected_platform", osPlatform))
		}

		// Stop services before removal
		logger.Info("Stopping Vault services before removal")

		logger.Debug("Attempting to stop vault.service")
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", "vault.service"},
			Logger:  logger.ZapLogger(),
		}); err != nil {
			logger.Warn("Failed to stop vault service",
				zap.Error(err),
				zap.String("service", "vault.service"))
		} else {
			logger.Info("Successfully stopped vault service")
		}

		logger.Debug("Attempting to stop vault-agent-eos.service")
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", "vault-agent-eos.service"},
			Logger:  logger.ZapLogger(),
		}); err != nil {
			logger.Warn("Failed to stop vault agent service",
				zap.Error(err),
				zap.String("service", "vault-agent-eos.service"))
		} else {
			logger.Info("Successfully stopped vault agent service")
		}

		// Kill any remaining Vault processes
		logger.Debug("Checking for remaining Vault server processes")
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "pkill",
			Args:    []string{"-f", "vault server"},
			Logger:  logger.ZapLogger(),
		}); err != nil {
			logger.Debug("No vault server processes found to kill", zap.Error(err))
		} else {
			logger.Info("Killed remaining vault server processes")
		}

		// Remove Vault depending on platform
		logger.Info("Removing Vault package", zap.String("distro", distro))
		switch distro {
		case "debian":
			logger.Debug("Using apt-get to remove vault package")
			if _, err := execute.Run(rc.Ctx, execute.Options{
				Command: "apt-get",
				Args:    []string{"remove", "-y", "vault"},
				Logger:  logger.ZapLogger(),
			}); err != nil {
				logger.Error("Failed to remove vault package via apt-get",
					zap.Error(err),
					zap.String("package_manager", "apt-get"))
				return err
			}
			logger.Info("Successfully removed vault package via apt-get")
		case "rhel":
			logger.Debug("Using dnf to remove vault package")
			if _, err := execute.Run(rc.Ctx, execute.Options{
				Command: "dnf",
				Args:    []string{"remove", "-y", "vault"},
				Logger:  logger.ZapLogger(),
			}); err != nil {
				logger.Error("Failed to remove vault package via dnf",
					zap.Error(err),
					zap.String("package_manager", "dnf"))
				return err
			}
			logger.Info("Successfully removed vault package via dnf")
		default:
			logger.Warn("Unknown distribution for package removal",
				zap.String("distro", distro))
		}

		if purge {
			logger.Info("Starting Vault purge process",
				zap.String("operation", "purge_vault_data"))

			purgePaths := vault.GetVaultPurgePaths()
			logger.Debug("Removing Vault directories",
				zap.Int("path_count", len(purgePaths)),
				zap.Strings("paths", purgePaths))

			for _, path := range purgePaths {
				logger.Debug("Attempting to remove path", zap.String("path", path))
				if err := os.RemoveAll(path); err != nil {
					logger.Warn("Failed to remove path",
						zap.String("path", path),
						zap.Error(err))
				} else {
					logger.Info("Successfully removed path", zap.String("path", path))
				}
			}

			wildcardPaths := vault.GetVaultWildcardPurgePaths()
			logger.Debug("Removing Vault wildcard paths",
				zap.Int("wildcard_count", len(wildcardPaths)),
				zap.Strings("wildcards", wildcardPaths))

			for _, wildcard := range wildcardPaths {
				logger.Debug("Attempting to remove wildcard path", zap.String("path", wildcard))
				if _, err := execute.Run(rc.Ctx, execute.Options{
					Command: "rm",
					Args:    []string{"-rf", wildcard},
					Logger:  logger.ZapLogger(),
				}); err != nil {
					logger.Warn("Failed to remove wildcard path",
						zap.String("path", wildcard),
						zap.Error(err))
				} else {
					logger.Info("Successfully removed wildcard path", zap.String("path", wildcard))
				}
			}

			logger.Info("Cleaning up Vault repository and keyring",
				zap.String("distro", distro))
			vault.Purge(rc, distro)
			logger.Info("Vault purge process completed")
		} else {
			logger.Info("Skipping purge operation",
				zap.Bool("purge_flag", purge),
				zap.String("reason", "purge disabled via flag"))
		}

		logger.Info("Vault deletion process completed successfully",
			zap.String("operation", "vault_deletion"),
			zap.String("status", "success"))
		return nil
	}),
}

func init() {
	DeleteVaultCmd.Flags().BoolVar(&purge, "purge", true, "Remove Vault config, secrets, and logs (default: true)")
	DeleteVaultCmd.Flags().Lookup("purge").NoOptDefVal = "true"
	DeleteCmd.AddCommand(DeleteVaultCmd)
}

// run function removed - replaced with secure execute.RunSimple calls
