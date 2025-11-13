package cleanup

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveVaultPackages removes Vault packages based on the distribution
// Migrated from cmd/delete/secrets.go removeVaultPackages
func RemoveVaultPackages(rc *eos_io.RuntimeContext, distro string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Determine package removal method
	logger.Info("Assessing Vault package removal requirements",
		zap.String("distro", distro))

	// INTERVENE - Remove packages
	logger.Info("Removing Vault packages")

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
		logger.Warn("Unknown distro, skipping package removal",
			zap.String("distro", distro))
	}

	// EVALUATE - Log completion
	logger.Info("Vault package removal completed")

	return nil
}

// CleanupPackageRepos removes Vault package repository configurations
// Migrated from cmd/delete/secrets.go cleanupPackageRepos
func CleanupPackageRepos(rc *eos_io.RuntimeContext, distro string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Determine repository cleanup method
	logger.Info("Assessing package repository cleanup",
		zap.String("distro", distro))

	// INTERVENE - Remove repository configurations
	logger.Info("Cleaning up package repositories")

	switch distro {
	case "debian":
		repoPaths := []string{
			vault.HashiCorpKeyring,
			vault.HashiCorpAptList,
		}
		for _, path := range repoPaths {
			if err := RemovePathSecurely(rc, path); err != nil {
				logger.Warn("Failed to remove repo file",
					zap.String("path", path),
					zap.Error(err))
			}
		}

		// Update package cache
		if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
			logger.Warn("Failed to update package cache", zap.Error(err))
		}

	case "rhel":
		if err := RemovePathSecurely(rc, vault.HashiCorpYumRepo); err != nil {
			logger.Warn("Failed to remove repo file", zap.Error(err))
		}

	default:
		logger.Debug("No repository cleanup needed for distro",
			zap.String("distro", distro))
	}

	// EVALUATE - Log completion
	logger.Info("Package repository cleanup completed")

	return nil
}
