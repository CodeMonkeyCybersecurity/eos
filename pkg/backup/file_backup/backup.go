// pkg/backup/file_backup/backup.go
package file_backup

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BackupFile creates a backup of a file following Assess → Intervene → Evaluate pattern
func BackupFile(rc *eos_io.RuntimeContext, config *FileBackupConfig, sourcePath string, options *BackupOptions) (*FileBackupOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	start := time.Now()
	logger.Info("Assessing file backup request",
		zap.String("source", sourcePath),
		zap.Any("options", options))

	if config == nil {
		config = DefaultFileBackupConfig()
	}

	if options == nil {
		options = &BackupOptions{}
	}

	operation := &FileBackupOperation{
		SourcePath: sourcePath,
		Timestamp:  start,
		DryRun:     options.DryRun,
	}

	// Check if source file exists
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Source file does not exist: %v", err)
		return operation, fmt.Errorf("source file does not exist: %w", err)
	}

	operation.FileSize = sourceInfo.Size()

	// Generate backup name and path
	backupName := generateBackupName(sourcePath, options.CustomName, config)
	backupDir := options.BackupDir
	if backupDir == "" {
		backupDir = config.DefaultBackupDir
	}

	backupPath := filepath.Join(backupDir, backupName)
	operation.BackupName = backupName
	operation.BackupPath = backupPath

	// Check if backup already exists
	if _, err := os.Stat(backupPath); err == nil && !config.OverwriteExisting && !options.Force {
		operation.Success = false
		operation.Message = "Backup already exists and overwrite is not enabled"
		return operation, fmt.Errorf("backup already exists: %s", backupPath)
	}

	// INTERVENE
	if options.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would backup %s to %s", sourcePath, backupPath)
		operation.Duration = time.Since(start)
		logger.Info("Dry run: would perform backup",
			zap.String("source", sourcePath),
			zap.String("backup", backupPath))
		return operation, nil
	}

	logger.Info("Creating file backup",
		zap.String("source", sourcePath),
		zap.String("backup", backupPath))

	// Create backup directory if needed
	if config.CreateBackupDir {
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			operation.Success = false
			operation.Message = fmt.Sprintf("Failed to create backup directory: %v", err)
			return operation, fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// Copy the file
	if err := copyFile(sourcePath, backupPath, config.PreservePermissions); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to copy file: %v", err)
		return operation, fmt.Errorf("failed to copy file: %w", err)
	}

	// Get backup file size
	if backupInfo, err := os.Stat(backupPath); err == nil {
		operation.BackupSize = backupInfo.Size()
	}

	// Create symlink if requested
	if config.CreateSymlinks {
		symlinkPath := strings.TrimSuffix(backupPath, filepath.Ext(backupPath)) + "_latest" + filepath.Ext(backupPath)
		if err := createSymlink(backupPath, symlinkPath); err != nil {
			logger.Warn("Failed to create symlink", zap.Error(err))
		}
	}

	// EVALUATE
	// Verify backup if requested
	if config.VerifyAfterBackup {
		if err := verifyBackup(sourcePath, backupPath); err != nil {
			operation.Success = false
			operation.Message = fmt.Sprintf("Backup verification failed: %v", err)
			return operation, fmt.Errorf("backup verification failed: %w", err)
		}
	}

	operation.Success = true
	operation.Message = "Backup completed successfully"
	operation.Duration = time.Since(start)

	logger.Info("File backup completed successfully",
		zap.String("source", sourcePath),
		zap.String("backup", backupPath),
		zap.Duration("duration", operation.Duration),
		zap.Int64("size", operation.BackupSize))

	return operation, nil
}

// ListBackups lists all backups in a directory following Assess → Intervene → Evaluate pattern
func ListBackups(rc *eos_io.RuntimeContext, config *FileBackupConfig, backupDir string) (*BackupListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing backup listing request", zap.String("directory", backupDir))

	if config == nil {
		config = DefaultFileBackupConfig()
	}

	result := &BackupListResult{
		BackupDir: backupDir,
		Timestamp: time.Now(),
	}

	if backupDir == "" {
		backupDir = config.DefaultBackupDir
		result.BackupDir = backupDir
	}

	// INTERVENE
	logger.Info("Listing backups", zap.String("directory", backupDir))

	// Check if backup directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		result.TotalBackups = 0
		result.Backups = []BackupInfo{}
		logger.Info("Backup directory does not exist", zap.String("directory", backupDir))
		return result, nil
	}

	// Read directory contents
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			logger.Warn("Failed to get file info", zap.String("file", entry.Name()), zap.Error(err))
			continue
		}

		// Parse backup name to extract original file info
		originalFile, backupTime := parseBackupName(entry.Name(), config)

		backup := BackupInfo{
			Name:         entry.Name(),
			Path:         filepath.Join(backupDir, entry.Name()),
			OriginalFile: originalFile,
			BackupTime:   backupTime,
			Size:         info.Size(),
			ModTime:      info.ModTime(),
		}

		backups = append(backups, backup)
	}

	result.Backups = backups
	result.TotalBackups = len(backups)

	// EVALUATE
	logger.Info("Backup listing completed successfully",
		zap.String("directory", backupDir),
		zap.Int("count", result.TotalBackups))

	return result, nil
}

// RestoreFile restores a file from backup following Assess → Intervene → Evaluate pattern
func RestoreFile(rc *eos_io.RuntimeContext, config *FileBackupConfig, backupPath, restorePath string, force bool, dryRun bool) (*RestoreOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	start := time.Now()
	logger.Info("Assessing file restore request",
		zap.String("backup", backupPath),
		zap.String("restore", restorePath),
		zap.Bool("force", force),
		zap.Bool("dry_run", dryRun))

	if config == nil {
		config = DefaultFileBackupConfig()
	}

	operation := &RestoreOperation{
		BackupPath:  backupPath,
		RestorePath: restorePath,
		Timestamp:   start,
		DryRun:      dryRun,
	}

	// Check if backup file exists
	backupInfo, err := os.Stat(backupPath)
	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Backup file does not exist: %v", err)
		return operation, fmt.Errorf("backup file does not exist: %w", err)
	}

	operation.BackupSize = backupInfo.Size()

	// Check if restore target already exists
	if _, err := os.Stat(restorePath); err == nil && !force {
		operation.Success = false
		operation.Message = "Target file already exists and force is not enabled"
		return operation, fmt.Errorf("target file already exists: %s", restorePath)
	}

	// INTERVENE
	if dryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would restore %s to %s", backupPath, restorePath)
		operation.Duration = time.Since(start)
		logger.Info("Dry run: would perform restore",
			zap.String("backup", backupPath),
			zap.String("restore", restorePath))
		return operation, nil
	}

	logger.Info("Restoring file from backup",
		zap.String("backup", backupPath),
		zap.String("restore", restorePath))

	// Create restore directory if needed
	restoreDir := filepath.Dir(restorePath)
	if err := os.MkdirAll(restoreDir, 0755); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to create restore directory: %v", err)
		return operation, fmt.Errorf("failed to create restore directory: %w", err)
	}

	// Copy the backup file to restore location
	if err := copyFile(backupPath, restorePath, config.PreservePermissions); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to restore file: %v", err)
		return operation, fmt.Errorf("failed to restore file: %w", err)
	}

	// Get restored file size
	if restoreInfo, err := os.Stat(restorePath); err == nil {
		operation.RestoredSize = restoreInfo.Size()
	}

	operation.Success = true
	operation.Message = "Restore completed successfully"
	operation.Duration = time.Since(start)

	// EVALUATE
	logger.Info("File restore completed successfully",
		zap.String("backup", backupPath),
		zap.String("restore", restorePath),
		zap.Duration("duration", operation.Duration),
		zap.Int64("size", operation.RestoredSize))

	return operation, nil
}

// Helper functions

func generateBackupName(sourcePath, customName string, config *FileBackupConfig) string {
	if customName != "" {
		return customName
	}

	baseName := filepath.Base(sourcePath)
	timestamp := time.Now().Format(config.TimestampFormat)
	ext := filepath.Ext(baseName)
	nameWithoutExt := strings.TrimSuffix(baseName, ext)

	return fmt.Sprintf("%s_backup_%s%s", nameWithoutExt, timestamp, ext)
}

func parseBackupName(backupName string, config *FileBackupConfig) (string, time.Time) {
	// Try to extract timestamp from backup name
	// This is a simplified implementation
	parts := strings.Split(backupName, "_backup_")
	if len(parts) == 2 {
		originalName := parts[0]
		timestampPart := strings.TrimSuffix(parts[1], filepath.Ext(parts[1]))

		if backupTime, err := time.Parse(config.TimestampFormat, timestampPart); err == nil {
			return originalName + filepath.Ext(backupName), backupTime
		}
	}

	return backupName, time.Time{}
}

func copyFile(src, dst string, preservePermissions bool) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() {
		if err := sourceFile.Close(); err != nil {
			// Log error but don't fail backup
		}
	}()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		if err := destFile.Close(); err != nil {
			// Log error but don't fail backup
		}
	}()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	if preservePermissions {
		sourceInfo, err := sourceFile.Stat()
		if err == nil {
			_ = os.Chmod(dst, sourceInfo.Mode())
		}
	}

	return nil
}

func verifyBackup(sourcePath, backupPath string) error {
	sourceHash, err := calculateFileHash(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to calculate source hash: %w", err)
	}

	backupHash, err := calculateFileHash(backupPath)
	if err != nil {
		return fmt.Errorf("failed to calculate backup hash: %w", err)
	}

	if sourceHash != backupHash {
		return fmt.Errorf("backup verification failed: hash mismatch")
	}

	return nil
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func createSymlink(target, linkPath string) error {
	// Remove existing symlink if it exists
	if _, err := os.Lstat(linkPath); err == nil {
		_ = os.Remove(linkPath)
	}

	return os.Symlink(target, linkPath)
}
