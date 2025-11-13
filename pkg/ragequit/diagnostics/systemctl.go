package diagnostics

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemctlDiagnostics runs systemd diagnostics
// Migrated from cmd/ragequit/ragequit.go systemctlDiagnostics
func SystemctlDiagnostics(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if systemd is available
	logger.Info("Assessing systemctl diagnostics requirements")

	if !system.CommandExists("systemctl") {
		logger.Info("Systemctl not available, skipping systemd diagnostics")
		return nil
	}

	homeDir := system.GetHomeDir()

	// INTERVENE - Collect systemd information
	logger.Debug("Collecting systemd diagnostics")

	// Failed units
	if failedUnits := system.RunCommandWithTimeout("systemctl", []string{"list-units", "--failed", "--no-pager"}, 5*time.Second); failedUnits != "" {
		outputFile := filepath.Join(homeDir, "ragequit-systemctl-failed.txt")
		if err := os.WriteFile(outputFile, []byte(failedUnits), shared.ConfigFilePerm); err != nil {
			logger.Warn("Failed to write failed units",
				zap.String("file", outputFile),
				zap.Error(err))
		} else {
			logger.Info("Failed units captured",
				zap.String("file", outputFile))
		}
	}

	// Pending jobs
	if pendingJobs := system.RunCommandWithTimeout("systemctl", []string{"list-jobs", "--no-pager"}, 5*time.Second); pendingJobs != "" {
		outputFile := filepath.Join(homeDir, "ragequit-systemctl-jobs.txt")
		if err := os.WriteFile(outputFile, []byte(pendingJobs), shared.ConfigFilePerm); err != nil {
			logger.Warn("Failed to write pending jobs",
				zap.String("file", outputFile),
				zap.Error(err))
		} else {
			logger.Info("Pending jobs captured",
				zap.String("file", outputFile))
		}
	}

	// Recent journal errors
	if system.CommandExists("journalctl") {
		if journalErrors := system.RunCommandWithTimeout("journalctl", []string{"-p", "err", "-n", "100", "--no-pager"}, 10*time.Second); journalErrors != "" {
			outputFile := filepath.Join(homeDir, "ragequit-journal-errors.txt")
			if err := os.WriteFile(outputFile, []byte(journalErrors), shared.ConfigFilePerm); err != nil {
				logger.Warn("Failed to write journal errors",
					zap.String("file", outputFile),
					zap.Error(err))
			} else {
				logger.Info("Journal errors captured",
					zap.String("file", outputFile))
			}
		}
	}

	// System status
	if systemStatus := system.RunCommandWithTimeout("systemctl", []string{"status", "--no-pager"}, 5*time.Second); systemStatus != "" {
		outputFile := filepath.Join(homeDir, "ragequit-systemctl-status.txt")
		if err := os.WriteFile(outputFile, []byte(systemStatus), shared.ConfigFilePerm); err != nil {
			logger.Warn("Failed to write system status",
				zap.String("file", outputFile),
				zap.Error(err))
		} else {
			logger.Info("System status captured",
				zap.String("file", outputFile))
		}
	}

	// EVALUATE - Log completion
	logger.Info("Systemctl diagnostics completed")

	return nil
}
