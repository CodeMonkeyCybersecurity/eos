package cleanup

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CleanupSystemHardening removes system hardening configurations for Vault
// Migrated from cmd/delete/secrets.go cleanupSystemHardening
func CleanupSystemHardening(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Identify hardening configurations
	logger.Info("Assessing system hardening configurations")

	hardeningPaths := []string{
		"/etc/systemd/system/vault.service.d/",
		"/etc/security/limits.d/vault-hardening.conf",
		"/etc/security/limits.d/vault-ulimits.conf",
		"/etc/logrotate.d/vault",
		"VaultBinaryPath-backup.sh",
		"/etc/systemd/system/vault-backup.timer",
		"/etc/systemd/system/vault-backup.service",
		"/etc/tmpfiles.d/eos.conf",
	}

	// INTERVENE - Remove hardening configurations
	logger.Info("Cleaning up system hardening configurations")

	for _, path := range hardeningPaths {
		if err := RemovePathSecurely(rc, path); err != nil {
			logger.Warn("Failed to remove hardening path",
				zap.String("path", path),
				zap.Error(err))
		}
	}

	// EVALUATE - Note manual review requirements
	logger.Warn("Manual review required for modified system configs",
		zap.String("note", "Check SSH, firewall, and other security configurations"))

	logger.Info("System hardening cleanup completed")

	return nil
}
