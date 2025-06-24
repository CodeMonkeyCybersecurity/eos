package delete

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var purgeSecure bool
var removeUser bool
var force bool

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
		if err := stopVaultServices(rc); err != nil {
			logger.Error("Failed to stop Vault services", zap.Error(err))
			if !force {
				return fmt.Errorf("stop services: %w", err)
			}
		}

		// Phase 2: Remove packages
		if err := removeVaultPackages(rc, distro); err != nil {
			logger.Error("Failed to remove Vault packages", zap.Error(err))
			if !force {
				return fmt.Errorf("remove packages: %w", err)
			}
		}

		// Phase 3: Clean up files and directories
		if purgeSecure {
			if err := purgeVaultFiles(rc); err != nil {
				logger.Error("Failed to purge Vault files", zap.Error(err))
				if !force {
					return fmt.Errorf("purge files: %w", err)
				}
			}

			// Phase 4: Clean up system hardening
			if err := cleanupSystemHardening(rc); err != nil {
				logger.Error("Failed to cleanup system hardening", zap.Error(err))
				if !force {
					return fmt.Errorf("cleanup hardening: %w", err)
				}
			}

			// Phase 5: Clean up eos user (optional)
			if removeUser {
				if err := cleanupEosUser(rc); err != nil {
					logger.Error("Failed to cleanup eos user", zap.Error(err))
					if !force {
						return fmt.Errorf("cleanup eos user: %w", err)
					}
				}
			}

			// Phase 6: Clean up package repositories
			if err := cleanupPackageRepos(rc, distro); err != nil {
				logger.Error("Failed to cleanup package repositories", zap.Error(err))
				if !force {
					return fmt.Errorf("cleanup repos: %w", err)
				}
			}
		}

		// Phase 7: Verify cleanup
		if err := verifyCleanup(rc); err != nil {
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
	DeleteCmd.AddCommand(DeleteVaultSecureCmd)
}

func stopVaultServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🛑 Stopping and disabling Vault services")

	services := []string{
		"vault-agent-eos.service",
		"vault.service",
		"vault-backup.timer",
		"vault-backup.service",
	}

	for _, service := range services {
		// Stop service
		logger.Info("Stopping service", zap.String("service", service))
		if err := execute.RunSimple(rc.Ctx, "systemctl", "stop", service); err != nil {
			logger.Warn("Failed to stop service (may not exist)", zap.String("service", service), zap.Error(err))
		}

		// Disable service
		logger.Info("Disabling service", zap.String("service", service))
		if err := execute.RunSimple(rc.Ctx, "systemctl", "disable", service); err != nil {
			logger.Warn("Failed to disable service (may not exist)", zap.String("service", service), zap.Error(err))
		}
	}

	// Kill any remaining Vault processes
	logger.Info("Killing any remaining Vault processes")
	if err := execute.RunSimple(rc.Ctx, "pkill", "-f", "vault server"); err != nil {
		logger.Info("No vault server processes found")
	}
	if err := execute.RunSimple(rc.Ctx, "pkill", "-f", "vault agent"); err != nil {
		logger.Info("No vault agent processes found")
	}

	// Wait a moment for processes to terminate
	time.Sleep(2 * time.Second)

	return nil
}

func removeVaultPackages(rc *eos_io.RuntimeContext, distro string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Removing Vault packages", zap.String("distro", distro))

	switch distro {
	case "debian":
		if err := execute.RunSimple(rc.Ctx, "apt-get", "remove", "-y", "vault"); err != nil {
			return fmt.Errorf("remove vault package (debian): %w", err)
		}
		if err := execute.RunSimple(rc.Ctx, "apt-get", "autoremove", "-y"); err != nil {
			logger.Warn("Failed to autoremove packages", zap.Error(err))
		}
	case "rhel":
		if err := execute.RunSimple(rc.Ctx, "dnf", "remove", "-y", "vault"); err != nil {
			return fmt.Errorf("remove vault package (rhel): %w", err)
		}
	default:
		logger.Warn("Unknown distro, skipping package removal", zap.String("distro", distro))
	}

	return nil
}

func purgeVaultFiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🧹 Purging Vault files and directories")

	// Get all purge paths from vault package
	allPaths := append(vault.GetVaultPurgePaths(), vault.GetVaultWildcardPurgePaths()...)

	// Add additional paths that might be missed
	additionalPaths := []string{
		"/etc/profile.d/eos_vault.sh",
		"/home/eos/.vault-token",
		"/home/eos/.config/vault/",
		"/home/eos/.config/hcp/", // Vault binary creates this despite VAULT_SKIP_HCP=true
		"/tmp/vault*",
	}
	allPaths = append(allPaths, additionalPaths...)

	removedCount := 0
	for _, path := range allPaths {
		if strings.Contains(path, "*") {
			// Handle wildcard paths
			matches, err := filepath.Glob(path)
			if err != nil {
				logger.Warn("Failed to glob path", zap.String("path", path), zap.Error(err))
				continue
			}
			for _, match := range matches {
				if err := removePathSecurely(rc, match); err != nil {
					logger.Warn("Failed to remove path", zap.String("path", match), zap.Error(err))
				} else {
					removedCount++
				}
			}
		} else {
			// Handle direct paths
			if err := removePathSecurely(rc, path); err != nil {
				logger.Warn("Failed to remove path", zap.String("path", path), zap.Error(err))
			} else {
				removedCount++
			}
		}
	}

	logger.Info("File purge completed", zap.Int("removed_count", removedCount))
	return nil
}

func removePathSecurely(rc *eos_io.RuntimeContext, path string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // Path doesn't exist, nothing to do
	}

	// Use execute package instead of direct command execution
	if err := execute.RunSimple(rc.Ctx, "rm", "-rf", path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}

	logger.Info("Removed path", zap.String("path", path))
	return nil
}

func cleanupSystemHardening(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Cleaning up system hardening configurations")

	hardeningPaths := []string{
		"/etc/systemd/system/vault.service.d/",
		"/etc/security/limits.d/vault-hardening.conf",
		"/etc/security/limits.d/vault-ulimits.conf",
		"/etc/logrotate.d/vault",
		"/usr/local/bin/vault-backup.sh",
		"/etc/systemd/system/vault-backup.timer",
		"/etc/systemd/system/vault-backup.service",
		"/etc/tmpfiles.d/eos.conf",
	}

	for _, path := range hardeningPaths {
		if err := removePathSecurely(rc, path); err != nil {
			logger.Warn("Failed to remove hardening path", zap.String("path", path), zap.Error(err))
		}
	}

	// TODO: Restore original configurations that were modified
	// This would require storing backups of original files during hardening
	logger.Warn("Manual review required for modified system configs (SSH, firewall, etc.)")

	return nil
}

func cleanupEosUser(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("👤 Cleaning up eos user and related files")

	// Remove eos user home directory
	if err := removePathSecurely(rc, "/home/eos"); err != nil {
		logger.Warn("Failed to remove eos home directory", zap.Error(err))
	}

	// Remove eos user
	if err := execute.RunSimple(rc.Ctx, "userdel", "eos"); err != nil {
		logger.Warn("Failed to remove eos user", zap.Error(err))
	}

	// Remove eos group
	if err := execute.RunSimple(rc.Ctx, "groupdel", "eos"); err != nil {
		logger.Warn("Failed to remove eos group", zap.Error(err))
	}

	// Remove sudoers file
	if err := removePathSecurely(rc, "/etc/sudoers.d/eos"); err != nil {
		logger.Warn("Failed to remove eos sudoers file", zap.Error(err))
	}

	// Remove eos password file
	if err := removePathSecurely(rc, shared.SecretsDir+"/eos-passwd.json"); err != nil {
		logger.Warn("Failed to remove eos password file", zap.Error(err))
	}

	return nil
}

func cleanupPackageRepos(rc *eos_io.RuntimeContext, distro string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Cleaning up package repositories", zap.String("distro", distro))

	switch distro {
	case "debian":
		repoPaths := []string{
			"/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			"/etc/apt/sources.list.d/hashicorp.list",
		}
		for _, path := range repoPaths {
			if err := removePathSecurely(rc, path); err != nil {
				logger.Warn("Failed to remove repo file", zap.String("path", path), zap.Error(err))
			}
		}
		// Update package cache
		if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
			logger.Warn("Failed to update package cache", zap.Error(err))
		}

	case "rhel":
		if err := removePathSecurely(rc, "/etc/yum.repos.d/hashicorp.repo"); err != nil {
			logger.Warn("Failed to remove repo file", zap.Error(err))
		}
	}

	return nil
}

func verifyCleanup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying cleanup completion")

	// Check for remaining processes
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"aux"},
	})
	if err == nil && strings.Contains(output, "vault") {
		logger.Warn("Vault processes may still be running")
	}

	// Check for remaining systemd services
	services := []string{"vault.service", "vault-agent-eos.service"}
	for _, service := range services {
		if err := execute.RunSimple(rc.Ctx, "systemctl", "is-active", service); err == nil {
			logger.Warn("Service still active", zap.String("service", service))
		}
	}

	// Check for critical files that should be gone
	criticalPaths := []string{
		"/etc/vault.d/vault.hcl",
		"/etc/vault-agent-eos.hcl",
		"/etc/systemd/system/vault.service",
		"/etc/systemd/system/vault-agent-eos.service",
		"/run/eos/vault_agent_eos.token",
	}

	foundPaths := []string{}
	for _, path := range criticalPaths {
		if _, err := os.Stat(path); err == nil {
			foundPaths = append(foundPaths, path)
		}
	}

	if len(foundPaths) > 0 {
		logger.Warn("Some critical files still exist",
			zap.Strings("remaining_files", foundPaths))
		return fmt.Errorf("cleanup incomplete - %d critical files remain", len(foundPaths))
	}

	// Reload systemd daemon to ensure service definitions are refreshed
	if err := execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload"); err != nil {
		logger.Warn("Failed to reload systemd daemon", zap.Error(err))
	}

	logger.Info(" Cleanup verification passed")
	return nil
}
