package file_backup

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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

// FileBackupManager handles file backup operations
type FileBackupManager struct {
	config *FileBackupConfig
}

// NewFileBackupManager creates a new file backup manager
func NewFileBackupManager(config *FileBackupConfig) *FileBackupManager {
	if config == nil {
		config = DefaultFileBackupConfig()
	}

	return &FileBackupManager{
		config: config,
	}
}

// BackupFile creates a backup of a single file
func (fbm *FileBackupManager) BackupFile(rc *eos_io.RuntimeContext, sourcePath string, options *BackupOptions) (*FileBackupOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	if options == nil {
		options = DefaultBackupOptions()
	}

	operation := &FileBackupOperation{
		SourcePath: sourcePath,
		Timestamp:  time.Now(),
		DryRun:     options.DryRun,
	}

	logger.Info("Starting file backup operation",
		zap.String("source_path", sourcePath),
		zap.Bool("dry_run", options.DryRun))

	// Check if source file exists
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Source file does not exist: %v", err)
		logger.Error("Source file not found", zap.String("path", sourcePath), zap.Error(err))
		return operation, err
	}

	if sourceInfo.IsDir() {
		operation.Success = false
		operation.Message = "Source path is a directory, not a file"
		logger.Error("Source path is a directory", zap.String("path", sourcePath))
		return operation, fmt.Errorf("source path is a directory: %s", sourcePath)
	}

	operation.FileSize = sourceInfo.Size()

	// Determine backup directory
	backupDir := options.BackupDir
	if backupDir == "" {
		backupDir = fbm.config.DefaultBackupDir
	}

	// Expand environment variables
	backupDir = os.ExpandEnv(backupDir)

	// Create backup directory if needed
	if fbm.config.CreateBackupDir || options.DryRun {
		if !options.DryRun {
			if err := os.MkdirAll(backupDir, shared.ServiceDirPerm); err != nil {
				operation.Success = false
				operation.Message = fmt.Sprintf("Failed to create backup directory: %v", err)
				logger.Error("Failed to create backup directory", zap.String("dir", backupDir), zap.Error(err))
				return operation, err
			}
		}
		logger.Debug("Backup directory created/verified", zap.String("dir", backupDir))
	}

	// Generate backup filename
	backupName := fbm.generateBackupName(sourcePath, options.CustomName)
	backupPath := filepath.Join(backupDir, backupName)

	operation.BackupPath = backupPath
	operation.BackupName = backupName

	// Check if backup already exists
	if !options.Force && !options.DryRun {
		if _, err := os.Stat(backupPath); err == nil {
			if !fbm.config.OverwriteExisting {
				operation.Success = false
				operation.Message = fmt.Sprintf("Backup already exists: %s (use --force to overwrite)", backupPath)
				logger.Warn("Backup already exists", zap.String("backup_path", backupPath))
				return operation, fmt.Errorf("backup already exists: %s", backupPath)
			}
		}
	}

	// Interactive confirmation if enabled
	if options.Interactive && !options.DryRun {
		if !fbm.promptForConfirmation(sourcePath, backupPath) {
			operation.Success = false
			operation.Message = "Backup cancelled by user"
			logger.Info("Backup cancelled by user")
			return operation, nil
		}
	}

	if options.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would backup %s to %s", sourcePath, backupPath)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would backup file",
			zap.String("source", sourcePath),
			zap.String("backup", backupPath))
		return operation, nil
	}

	// Perform the backup
	if err := fbm.copyFile(sourcePath, backupPath, options.PreservePermissions); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Backup failed: %v", err)
		logger.Error("Backup copy failed", zap.Error(err))
		return operation, err
	}

	// Get backup file size
	if backupInfo, err := os.Stat(backupPath); err == nil {
		operation.BackupSize = backupInfo.Size()
	}

	// Verify backup if enabled
	if options.VerifyAfterBackup || fbm.config.VerifyAfterBackup {
		if err := fbm.verifyBackup(sourcePath, backupPath); err != nil {
			operation.Success = false
			operation.Message = fmt.Sprintf("Backup verification failed: %v", err)
			logger.Error("Backup verification failed", zap.Error(err))
			return operation, err
		}
		logger.Debug("Backup verification successful")
	}

	// Create symlink if requested
	if options.CreateSymlink || fbm.config.CreateSymlinks {
		symlinkPath := backupPath + ".latest"
		if err := fbm.createSymlink(backupPath, symlinkPath); err != nil {
			logger.Warn("Failed to create symlink", zap.Error(err))
			// Don't fail the operation for symlink errors
		}
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully backed up %s to %s", sourcePath, backupPath)
	operation.Duration = time.Since(startTime)

	logger.Info("File backup completed successfully",
		zap.String("source", sourcePath),
		zap.String("backup", backupPath),
		zap.Duration("duration", operation.Duration),
		zap.Int64("size", operation.FileSize))

	return operation, nil
}

// ListBackups lists all backup files in the backup directory
func (fbm *FileBackupManager) ListBackups(rc *eos_io.RuntimeContext, backupDir string) (*BackupListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if backupDir == "" {
		backupDir = fbm.config.DefaultBackupDir
	}
	backupDir = os.ExpandEnv(backupDir)

	logger.Info("Listing backups", zap.String("backup_dir", backupDir))

	result := &BackupListResult{
		BackupDir: backupDir,
		Backups:   make([]BackupInfo, 0),
		Timestamp: time.Now(),
	}

	// Check if backup directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		logger.Info("Backup directory does not exist", zap.String("dir", backupDir))
		return result, nil
	}

	// Walk through backup directory
	err := filepath.Walk(backupDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Warn("Error walking backup directory", zap.String("path", path), zap.Error(err))
			return nil // Continue walking
		}

		if info.IsDir() {
			return nil // Skip directories
		}

		// Skip symlinks and hidden files
		if strings.HasPrefix(info.Name(), ".") || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		backup := BackupInfo{
			Path:    path,
			Name:    info.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			IsValid: true,
		}

		// Try to extract original filename and backup time from name
		if originalFile, backupTime := fbm.ParseBackupName(info.Name()); originalFile != "" {
			backup.OriginalFile = originalFile
			backup.BackupTime = backupTime
		}

		result.Backups = append(result.Backups, backup)
		result.TotalSize += info.Size()

		return nil
	})

	if err != nil {
		logger.Error("Failed to walk backup directory", zap.Error(err))
		return nil, err
	}

	result.TotalBackups = len(result.Backups)

	logger.Info("Backup listing completed",
		zap.Int("total_backups", result.TotalBackups),
		zap.Int64("total_size", result.TotalSize))

	return result, nil
}

// RestoreFile restores a backup file to a specified location
func (fbm *FileBackupManager) RestoreFile(rc *eos_io.RuntimeContext, backupPath, restorePath string, force bool, dryRun bool) (*RestoreOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	operation := &RestoreOperation{
		BackupPath:  backupPath,
		RestorePath: restorePath,
		Timestamp:   time.Now(),
		DryRun:      dryRun,
	}

	logger.Info("Starting file restore operation",
		zap.String("backup_path", backupPath),
		zap.String("restore_path", restorePath),
		zap.Bool("dry_run", dryRun))

	// Check if backup file exists
	if _, err := os.Stat(backupPath); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Backup file does not exist: %v", err)
		logger.Error("Backup file not found", zap.String("path", backupPath), zap.Error(err))
		return operation, err
	}

	// Check if restore target already exists
	if !force && !dryRun {
		if _, err := os.Stat(restorePath); err == nil {
			operation.Success = false
			operation.Message = fmt.Sprintf("Target file already exists: %s (use --force to overwrite)", restorePath)
			logger.Warn("Target file already exists", zap.String("restore_path", restorePath))
			return operation, fmt.Errorf("target file already exists: %s", restorePath)
		}
	}

	if dryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would restore %s to %s", backupPath, restorePath)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would restore file")
		return operation, nil
	}

	// Create target directory if needed
	targetDir := filepath.Dir(restorePath)
	if err := os.MkdirAll(targetDir, shared.ServiceDirPerm); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to create target directory: %v", err)
		logger.Error("Failed to create target directory", zap.String("dir", targetDir), zap.Error(err))
		return operation, err
	}

	// Check if we're overwriting
	if _, err := os.Stat(restorePath); err == nil {
		operation.Overwritten = true
	}

	// Perform the restore
	if err := fbm.copyFile(backupPath, restorePath, fbm.config.PreservePermissions); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Restore failed: %v", err)
		logger.Error("Restore copy failed", zap.Error(err))
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully restored %s to %s", backupPath, restorePath)
	operation.Duration = time.Since(startTime)

	logger.Info("File restore completed successfully",
		zap.String("backup", backupPath),
		zap.String("restore", restorePath),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// Helper methods

func (fbm *FileBackupManager) generateBackupName(sourcePath, customName string) string {
	filename := filepath.Base(sourcePath)

	if customName != "" {
		filename = customName
	}

	timestamp := time.Now().Format(fbm.config.TimestampFormat)
	return fmt.Sprintf("%s.backup.%s", filename, timestamp)
}

// ParseBackupName parses a backup filename to extract original file and backup time
func (fbm *FileBackupManager) ParseBackupName(backupName string) (string, time.Time) {
	// Try to parse backup filename format: filename.backup.timestamp
	parts := strings.Split(backupName, ".backup.")
	if len(parts) != 2 {
		return "", time.Time{}
	}

	originalFile := parts[0]
	timestampStr := parts[1]

	// Try to parse timestamp
	if backupTime, err := time.Parse(fbm.config.TimestampFormat, timestampStr); err == nil {
		return originalFile, backupTime
	}

	return originalFile, time.Time{}
}

func (fbm *FileBackupManager) copyFile(src, dst string, preservePermissions bool) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = sourceFile.Close() }()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() { _ = destFile.Close() }()

	// Copy file contents
	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	// Preserve permissions if requested
	if preservePermissions {
		if sourceInfo, err := os.Stat(src); err == nil {
			if err := os.Chmod(dst, sourceInfo.Mode()); err != nil {
				return fmt.Errorf("failed to preserve permissions: %w", err)
			}
		}
	}

	return nil
}

func (fbm *FileBackupManager) verifyBackup(sourcePath, backupPath string) error {
	sourceHash, err := fbm.calculateFileHash(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to calculate source hash: %w", err)
	}

	backupHash, err := fbm.calculateFileHash(backupPath)
	if err != nil {
		return fmt.Errorf("failed to calculate backup hash: %w", err)
	}

	if sourceHash != backupHash {
		return fmt.Errorf("backup verification failed: hash mismatch")
	}

	return nil
}

func (fbm *FileBackupManager) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func (fbm *FileBackupManager) createSymlink(target, linkPath string) error {
	// Remove existing symlink if it exists
	if _, err := os.Lstat(linkPath); err == nil {
		if err := os.Remove(linkPath); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	return os.Symlink(target, linkPath)
}

func (fbm *FileBackupManager) promptForConfirmation(sourcePath, backupPath string) bool {
	fmt.Printf("Backup %s to %s? [y/N]: ", sourcePath, backupPath)
	var response string
	_, _ = fmt.Scanln(&response)
	return response == "y" || response == "Y" || response == "yes"
}
