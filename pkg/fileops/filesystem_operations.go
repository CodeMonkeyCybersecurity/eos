// Package fileops provides infrastructure implementations for file operations
package fileops

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// FileSystemOperations provides filesystem operations
type FileSystemOperations struct {
	logger *zap.Logger
}

// NewFileSystemOperations creates a new filesystem operations implementation
func NewFileSystemOperations(logger *zap.Logger) *FileSystemOperations {
	return &FileSystemOperations{
		logger: logger.Named("filesystem"),
	}
}

// ReadFile reads the entire contents of a file
func (f *FileSystemOperations) ReadFile(ctx context.Context, path string) ([]byte, error) {
	f.logger.Debug("Reading file", zap.String("path", path))

	data, err := os.ReadFile(path)
	if err != nil {
		f.logger.Error("Failed to read file",
			zap.String("path", path),
			zap.Error(err))
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	f.logger.Debug("File read successfully",
		zap.String("path", path),
		zap.Int("size", len(data)))

	return data, nil
}

// WriteFile writes data to a file, creating it if necessary
func (f *FileSystemOperations) WriteFile(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	f.logger.Debug("Writing file",
		zap.String("path", path),
		zap.Int("size", len(data)),
		zap.String("permissions", perm.String()))

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		f.logger.Error("Failed to create directory",
			zap.String("dir", dir),
			zap.Error(err))
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(path, data, perm); err != nil {
		f.logger.Error("Failed to write file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	f.logger.Info("File written successfully",
		zap.String("path", path),
		zap.Int("size", len(data)))

	return nil
}

// CopyFile copies a file from source to destination
func (f *FileSystemOperations) CopyFile(ctx context.Context, src, dst string, perm os.FileMode) error {
	f.logger.Debug("Copying file",
		zap.String("src", src),
		zap.String("dst", dst))

	// Open source file
	sourceFile, err := os.Open(src)
	if err != nil {
		f.logger.Error("Failed to open source file",
			zap.String("src", src),
			zap.Error(err))
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer func() {
		if err := sourceFile.Close(); err != nil {
			f.logger.Warn("Failed to close source file", zap.Error(err))
		}
	}()

	// Get source file info
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file %s: %w", src, err)
	}

	// Ensure destination directory exists
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dstDir, err)
	}

	// Create destination file
	destFile, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		f.logger.Error("Failed to create destination file",
			zap.String("dst", dst),
			zap.Error(err))
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer func() {
		if err := destFile.Close(); err != nil {
			f.logger.Warn("Failed to close destination file", zap.Error(err))
		}
	}()

	// Copy contents
	bytesWritten, err := io.Copy(destFile, sourceFile)
	if err != nil {
		f.logger.Error("Failed to copy file contents",
			zap.String("src", src),
			zap.String("dst", dst),
			zap.Error(err))
		return fmt.Errorf("failed to copy contents from %s to %s: %w", src, dst, err)
	}

	f.logger.Info("File copied successfully",
		zap.String("src", src),
		zap.String("dst", dst),
		zap.Int64("size", sourceInfo.Size()),
		zap.Int64("bytes_written", bytesWritten))

	return nil
}

// MoveFile moves a file from source to destination
func (f *FileSystemOperations) MoveFile(ctx context.Context, src, dst string) error {
	f.logger.Debug("Moving file",
		zap.String("src", src),
		zap.String("dst", dst))

	// Try atomic rename first
	if err := os.Rename(src, dst); err == nil {
		f.logger.Info("File moved successfully (atomic)",
			zap.String("src", src),
			zap.String("dst", dst))
		return nil
	}

	// If rename failed (possibly cross-device), copy then delete
	f.logger.Debug("Atomic rename failed, falling back to copy+delete")

	// Copy the file
	if err := f.CopyFile(ctx, src, dst, 0644); err != nil {
		return fmt.Errorf("failed to copy file during move: %w", err)
	}

	// Delete the source
	if err := os.Remove(src); err != nil {
		f.logger.Warn("Failed to remove source after copy",
			zap.String("src", src),
			zap.Error(err))
	}

	f.logger.Info("File moved successfully",
		zap.String("src", src),
		zap.String("dst", dst))

	return nil
}

// DeleteFile removes a file
func (f *FileSystemOperations) DeleteFile(ctx context.Context, path string) error {
	if err := os.Remove(path); err != nil {
		f.logger.Error("Failed to delete file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to delete file %s: %w", path, err)
	}

	f.logger.Debug("File deleted successfully",
		zap.String("path", path))

	return nil
}

// Exists checks if a file or directory exists
func (f *FileSystemOperations) Exists(ctx context.Context, path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("failed to check if path exists %s: %w", path, err)
}

// CreateDirectory creates a directory with the specified permissions
func (f *FileSystemOperations) CreateDirectory(ctx context.Context, path string, perm os.FileMode) error {
	if err := os.MkdirAll(path, perm); err != nil {
		f.logger.Error("Failed to create directory",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	f.logger.Debug("Directory created successfully",
		zap.String("path", path),
		zap.String("permissions", perm.String()))

	return nil
}

// ListDirectory returns a list of files in a directory
func (f *FileSystemOperations) ListDirectory(ctx context.Context, path string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		f.logger.Error("Failed to list directory",
			zap.String("path", path),
			zap.Error(err))
		return nil, fmt.Errorf("failed to list directory %s: %w", path, err)
	}

	f.logger.Debug("Directory listed successfully",
		zap.String("path", path),
		zap.Int("entries", len(entries)))

	return entries, nil
}

// GetFileInfo returns information about a file
func (f *FileSystemOperations) GetFileInfo(ctx context.Context, path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		f.logger.Error("Failed to stat file",
			zap.String("path", path),
			zap.Error(err))
		return nil, fmt.Errorf("failed to stat file %s: %w", path, err)
	}

	return info, nil
}

// OpenFile opens a file with the specified flags and permissions
func (f *FileSystemOperations) OpenFile(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
	file, err := os.OpenFile(path, flag, perm)
	if err != nil {
		f.logger.Error("Failed to open file",
			zap.String("path", path),
			zap.Int("flags", flag),
			zap.Error(err))
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}

	f.logger.Debug("File opened successfully",
		zap.String("path", path))

	return file, nil
}
