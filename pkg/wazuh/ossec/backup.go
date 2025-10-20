// pkg/wazuh/ossec/backup.go

package ossec

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateBackup creates a timestamped backup of the ossec.conf file
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check source file exists and is readable
// - Intervene: Copy file to backup location with timestamp
// - Evaluate: Verify backup was created successfully
func CreateBackup(rc *eos_io.RuntimeContext, sourcePath string, customBackupPath string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Assess: Check source file
	if _, err := os.Stat(sourcePath); err != nil {
		return "", fmt.Errorf("source file not accessible: %w", err)
	}

	// Determine backup path
	timestamp := time.Now().Unix()
	backupPath := customBackupPath
	if backupPath == "" {
		backupPath = fmt.Sprintf("%s.backup.%d", sourcePath, timestamp)
	}

	logger.Debug("Creating backup",
		zap.String("source", sourcePath),
		zap.String("backup", backupPath))

	// Intervene: Read and write backup
	input, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", fmt.Errorf("failed to read source file: %w", err)
	}

	if err := os.WriteFile(backupPath, input, 0640); err != nil {
		return "", fmt.Errorf("failed to write backup file: %w", err)
	}

	// Set proper ownership (root:wazuh)
	cmd := exec.Command("chown", "root:wazuh", backupPath)
	if err := cmd.Run(); err != nil {
		logger.Warn("Could not set ownership on backup", zap.Error(err))
	}

	// Evaluate: Verify backup exists
	if _, err := os.Stat(backupPath); err != nil {
		return "", fmt.Errorf("backup verification failed: %w", err)
	}

	logger.Info("Created backup successfully",
		zap.String("backup_path", backupPath),
		zap.Int("size_bytes", len(input)))

	return backupPath, nil
}

// RestoreBackup restores a configuration from a backup file
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Verify backup file exists and is readable
// - Intervene: Copy backup to original location
// - Evaluate: Verify restoration was successful
func RestoreBackup(rc *eos_io.RuntimeContext, backupPath, originalPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restoring from backup",
		zap.String("backup", backupPath),
		zap.String("destination", originalPath))

	// Assess: Check backup file
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file not accessible: %w", err)
	}

	// Intervene: Read backup and write to original location
	input, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	if err := os.WriteFile(originalPath, input, 0640); err != nil {
		return fmt.Errorf("failed to write restored file: %w", err)
	}

	// Evaluate: Verify restoration
	if _, err := os.Stat(originalPath); err != nil {
		return fmt.Errorf("restoration verification failed: %w", err)
	}

	logger.Info("Restored from backup successfully",
		zap.String("backup", backupPath),
		zap.Int("size_bytes", len(input)))

	return nil
}
