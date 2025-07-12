package cleanup

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CleanupEosUser removes the eos user and related files
// Migrated from cmd/delete/secrets.go cleanupEosUser
func CleanupEosUser(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if eos user exists
	logger.Info("Assessing eos user cleanup requirements")

	// INTERVENE - Remove user and related files
	logger.Info("Cleaning up eos user and related files")

	// Remove eos user home directory
	if err := RemovePathSecurely(rc, "/home/eos"); err != nil {
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
	if err := RemovePathSecurely(rc, "/etc/sudoers.d/eos"); err != nil {
		logger.Warn("Failed to remove eos sudoers file", zap.Error(err))
	}

	// Remove eos password file
	if err := RemovePathSecurely(rc, shared.SecretsDir+"/eos-passwd.json"); err != nil {
		logger.Warn("Failed to remove eos password file", zap.Error(err))
	}

	// EVALUATE - Log completion
	logger.Info("Eos user cleanup completed")

	return nil
}
