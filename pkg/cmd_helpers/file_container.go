// Package cmd_helpers provides common helpers for command implementations
// to promote DRY principles and consistent behavior across the CLI
package cmd_helpers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/fileops"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	fileopsinfra "github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/fileops"
	"go.uber.org/zap"
)

// FileServiceContainer provides file operations for commands using domain services
type FileServiceContainer struct {
	Service *fileops.Service
	ctx     context.Context
	logger  *zap.Logger
}

// NewFileServiceContainer creates a new file service container with all dependencies
func NewFileServiceContainer(rc *eos_io.RuntimeContext) (*FileServiceContainer, error) {
	logger := rc.Log.Named("fileops")

	// Create infrastructure implementations
	fileOps := fileopsinfra.NewFileSystemOperations(logger)
	pathOps := fileopsinfra.NewPathOperations()
	templateOps := fileopsinfra.NewTemplateOperations(fileOps, pathOps, logger)
	safeOps := fileopsinfra.NewSafeFileOperations(fileOps, logger)

	// Create domain service
	service := fileops.NewService(fileOps, pathOps, templateOps, safeOps, logger)

	return &FileServiceContainer{
		Service: service,
		ctx:     rc.Ctx,
		logger:  logger,
	}, nil
}

// FileExists checks if a file exists (backward compatibility helper)
func (c *FileServiceContainer) FileExists(path string) bool {
	exists, err := c.Service.Exists(c.ctx, path)
	if err != nil {
		c.logger.Debug("Error checking file existence",
			zap.String("path", path),
			zap.Error(err))
		return false
	}
	return exists
}

// CopyFile copies a file with default permissions 0755 (backward compatibility)
func (c *FileServiceContainer) CopyFile(src, dst string) error {
	opts := fileops.CopyOptions{
		PreserveMode: false,
		DefaultMode:  0755,
		CreateDirs:   true,
	}

	result, err := c.Service.CopyFileWithOptions(c.ctx, src, dst, opts)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("copy operation failed: %v", result.Error)
	}

	return nil
}

// CopyFileWithPermissions copies a file with specific permissions
func (c *FileServiceContainer) CopyFileWithPermissions(src, dst string, perm os.FileMode) error {
	opts := fileops.CopyOptions{
		PreserveMode: false,
		DefaultMode:  perm,
		CreateDirs:   true,
	}

	result, err := c.Service.CopyFileWithOptions(c.ctx, src, dst, opts)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("copy operation failed: %v", result.Error)
	}

	return nil
}

// CopyFileWithBackup copies a file and creates a backup if destination exists
func (c *FileServiceContainer) CopyFileWithBackup(src, dst string) error {
	// Check if destination exists
	exists, err := c.Service.Exists(c.ctx, dst)
	if err != nil {
		return fmt.Errorf("failed to check destination: %w", err)
	}

	// Create backup if file exists
	if exists {
		backupPath := fmt.Sprintf("%s.backup.%d", dst, time.Now().Unix())
		if err := c.CopyFile(dst, backupPath); err != nil {
			c.logger.Warn("Failed to create backup",
				zap.String("file", dst),
				zap.String("backup", backupPath),
				zap.Error(err))
		} else {
			c.logger.Info("Created backup",
				zap.String("original", dst),
				zap.String("backup", backupPath))
		}
	}

	// Copy the file
	return c.CopyFile(src, dst)
}

// EnsureDirectory ensures a directory exists with the given permissions
func (c *FileServiceContainer) EnsureDirectory(path string, perm os.FileMode) error {
	return c.Service.EnsureDirectory(c.ctx, path, perm)
}

// ReadFile reads the entire contents of a file
func (c *FileServiceContainer) ReadFile(path string) ([]byte, error) {
	return c.Service.ReadFile(c.ctx, path)
}

// WriteFile writes data to a file with the given permissions
func (c *FileServiceContainer) WriteFile(path string, data []byte, perm os.FileMode) error {
	return c.Service.WriteFile(c.ctx, path, data, perm)
}

// SafeWriteFile writes a file with automatic backup of existing file
func (c *FileServiceContainer) SafeWriteFile(path string, data []byte, perm os.FileMode) error {
	return c.Service.SafeWriteFile(c.ctx, path, data, perm)
}

// CopyDirectory copies an entire directory tree
func (c *FileServiceContainer) CopyDirectory(src, dst string) error {
	opts := fileops.DefaultCopyOptions()
	filter := fileops.DefaultFileFilter()

	result, err := c.Service.CopyDirectory(c.ctx, src, dst, opts, filter)
	if err != nil {
		return err
	}

	if result.FailedFiles > 0 {
		return fmt.Errorf("failed to copy %d files out of %d",
			result.FailedFiles, result.TotalFiles)
	}

	c.logger.Info("Directory copied successfully",
		zap.String("source", src),
		zap.String("destination", dst),
		zap.Int("files_copied", result.SuccessfulFiles),
		zap.Duration("duration", result.Duration))

	return nil
}

// DeleteFile removes a file
func (c *FileServiceContainer) DeleteFile(path string) error {
	return c.Service.DeleteFile(c.ctx, path)
}

// ExtractTimestampFromBackupPath extracts timestamp from backup filename
// e.g., "file.py.2024-01-15-10-30-45.bak" -> "2024-01-15-10-30-45"
func ExtractTimestampFromBackupPath(backupPath string) string {
	base := filepath.Base(backupPath)

	// Remove extension
	if ext := filepath.Ext(base); ext != "" {
		base = base[:len(base)-len(ext)]
	}

	// Extract timestamp pattern (YYYY-MM-DD-HH-MM-SS)
	// This is a simplified version - could be enhanced with regex
	// For now, generate a new timestamp
	return time.Now().Format("2006-01-02-15-04-05")
}
