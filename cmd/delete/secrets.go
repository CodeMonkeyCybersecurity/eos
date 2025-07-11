// cmd/delete/secrets.go
package delete

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault/cleanup"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var purgeSecure bool
var removeUser bool
var force bool
var purge bool

var DeleteVaultSecureCmd = &cobra.Command{
	Use:   "vault-secure",
	Short: "Securely deletes Vault installation with comprehensive cleanup",
	Long: `Securely removes Vault with comprehensive cleanup including:
- Stops and disables all Vault services
- Removes packages via package manager  
- Cleans up all configuration files and data
- Removes system hardening artifacts
- Optionally removes eos user and related files
- Verifies complete cleanup before finishing`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("🧨 Starting secure Vault deletion")

		// Check if running as root
		if os.Geteuid() != 0 {
			return fmt.Errorf("this command must be run as root")
		}

		distro := platform.DetectLinuxDistro(rc)
		osPlatform := platform.GetOSPlatform()
		if osPlatform != "linux" {
			return fmt.Errorf("vault uninstallation only supported on Linux")
		}

		// Phase 1: Stop and disable services
		if err := cleanup.StopVaultServices(rc); err != nil {
			logger.Error("Failed to stop Vault services", zap.Error(err))
			if !force {
				return fmt.Errorf("stop services: %w", err)
			}
		}

		// Phase 2: Remove packages
		if err := cleanup.RemoveVaultPackages(rc, distro); err != nil {
			logger.Error("Failed to remove Vault packages", zap.Error(err))
			if !force {
				return fmt.Errorf("remove packages: %w", err)
			}
		}

		// Phase 3: Clean up files and directories
		if purgeSecure {
			if err := cleanup.PurgeVaultFiles(rc); err != nil {
				logger.Error("Failed to purge Vault files", zap.Error(err))
				if !force {
					return fmt.Errorf("purge files: %w", err)
				}
			}

			// Phase 4: Clean up system hardening
			if err := cleanup.CleanupSystemHardening(rc); err != nil {
				logger.Error("Failed to cleanup system hardening", zap.Error(err))
				if !force {
					return fmt.Errorf("cleanup hardening: %w", err)
				}
			}

			// Phase 5: Clean up eos user (optional)
			if removeUser {
				if err := cleanup.CleanupEosUser(rc); err != nil {
					logger.Error("Failed to cleanup eos user", zap.Error(err))
					if !force {
						return fmt.Errorf("cleanup eos user: %w", err)
					}
				}
			}

			// Phase 6: Clean up package repositories
			if err := cleanup.CleanupPackageRepos(rc, distro); err != nil {
				logger.Error("Failed to cleanup package repositories", zap.Error(err))
				if !force {
					return fmt.Errorf("cleanup repos: %w", err)
				}
			}
		}

		// Phase 7: Verify cleanup
		if err := cleanup.VerifyCleanup(rc); err != nil {
			logger.Error("Cleanup verification failed", zap.Error(err))
			if !force {
				return fmt.Errorf("cleanup verification: %w", err)
			}
		}

		logger.Info(" Secure Vault deletion completed successfully")
		return nil
	}),
}

func init() {
	DeleteVaultSecureCmd.Flags().BoolVar(&purgeSecure, "purge", true, "Remove all Vault config, secrets, and logs (default: true)")
	DeleteVaultSecureCmd.Flags().BoolVar(&removeUser, "remove-user", false, "Remove the eos user and related files (default: false)")
	DeleteVaultSecureCmd.Flags().BoolVar(&force, "force", false, "Continue even if some cleanup steps fail (default: false)")
}

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

// DeleteTestDataCmd attempts to delete test-data from Vault,
// falling back to removing local disk copy if Vault is unavailable.
var DeleteTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Delete test-data from Vault (fallback to disk)",
	Long:  `Deletes the test-data from Vault. Falls back to deleting local test-data.json if Vault is unavailable.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		client, err := vault.GetVaultClient(rc)
		if err != nil {
			log.Warn("Vault client unavailable", zap.Error(err))
			client = nil // Will trigger fallback to disk
		} else {
			vault.ValidateAndCache(rc, client)
		}

		vault.SetVaultClient(rc, client)
		vault.ValidateAndCache(rc, client)

		log.Info(" Attempting to delete test-data from Vault...")
		err = vault.Delete(rc, client, shared.TestDataVaultPath)
		if err != nil {
			log.Warn("Vault delete failed, falling back to disk", zap.Error(err))
			return vault.DeleteTestDataFromDisk(rc)
		}

		fmt.Println()
		fmt.Println("  Test Data Deletion Summary")
		fmt.Println("   Vault: SUCCESS")
		fmt.Printf("     Path: secret/data/%s\n\n", shared.TestDataVaultPath)
		log.Info(" Test-data deleted successfully (Vault)")
		return nil
	}),
}

func init() {
	DeleteVaultCmd.Flags().BoolVar(&purge, "purge", true, "Remove Vault config, secrets, and logs (default: true)")
	DeleteVaultCmd.Flags().Lookup("purge").NoOptDefVal = "true"
}