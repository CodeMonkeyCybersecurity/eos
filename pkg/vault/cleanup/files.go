package cleanup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PurgeVaultFiles removes all Vault-related files and directories
// Migrated from cmd/delete/secrets.go purgeVaultFiles
func PurgeVaultFiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Gather all paths to purge
	logger.Info("Assessing Vault files to purge")

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

	// INTERVENE - Remove files
	logger.Info("Purging Vault files and directories",
		zap.Int("total_paths", len(allPaths)))

	removedCount := 0
	for _, path := range allPaths {
		if strings.Contains(path, "*") {
			// Handle wildcard paths
			matches, err := filepath.Glob(path)
			if err != nil {
				logger.Warn("Failed to glob path",
					zap.String("path", path),
					zap.Error(err))
				continue
			}
			for _, match := range matches {
				if err := RemovePathSecurely(rc, match); err != nil {
					logger.Warn("Failed to remove path",
						zap.String("path", match),
						zap.Error(err))
				} else {
					removedCount++
				}
			}
		} else {
			// Handle direct paths
			if err := RemovePathSecurely(rc, path); err != nil {
				logger.Warn("Failed to remove path",
					zap.String("path", path),
					zap.Error(err))
			} else {
				removedCount++
			}
		}
	}

	// EVALUATE - Report results
	logger.Info("File purge completed",
		zap.Int("removed_count", removedCount),
		zap.Int("total_paths", len(allPaths)))

	return nil
}

// RemovePathSecurely removes a file or directory path
// Migrated from cmd/delete/secrets.go removePathSecurely
func RemovePathSecurely(rc *eos_io.RuntimeContext, path string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if path exists
	logger.Debug("Assessing path for removal", zap.String("path", path))

	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Debug("Path does not exist, skipping", zap.String("path", path))
		return nil // Path doesn't exist, nothing to do
	}

	// INTERVENE - Remove the path
	logger.Debug("Removing path", zap.String("path", path))

	// Use execute package instead of direct command execution
	if err := execute.RunSimple(rc.Ctx, "rm", "-rf", path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}

	// EVALUATE - Verify removal
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("path still exists after removal: %s", path)
	}

	logger.Info("Removed path", zap.String("path", path))
	return nil
}
