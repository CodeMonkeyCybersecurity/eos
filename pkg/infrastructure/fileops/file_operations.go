// Package fileops provides infrastructure implementations for file operations
package fileops

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/fileops"
	"go.uber.org/zap"
)

// FileSystemOperations implements fileops.FileOperations using the OS file system
type FileSystemOperations struct {
	logger *zap.Logger
}

// NewFileSystemOperations creates a new file system operations implementation
func NewFileSystemOperations(logger *zap.Logger) *FileSystemOperations {
	return &FileSystemOperations{
		logger: logger,
	}
}

// ReadFile reads the entire contents of a file
func (f *FileSystemOperations) ReadFile(ctx context.Context, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		f.logger.Error("Failed to read file",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	
	f.logger.Debug("File read successfully",
		zap.String("path", path),
		zap.Int("size", len(data)),
	)
	
	return data, nil
}

// WriteFile writes data to a file, creating it if necessary
func (f *FileSystemOperations) WriteFile(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		f.logger.Error("Failed to write file",
			zap.String("path", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	
	f.logger.Debug("File written successfully",
		zap.String("path", path),
		zap.Int("size", len(data)),
		zap.String("permissions", perm.String()),
	)
	
	return nil
}

// CopyFile copies a file from source to destination
func (f *FileSystemOperations) CopyFile(ctx context.Context, src, dst string, perm os.FileMode) error {
	// Open source file
	srcFile, err := os.Open(src)
	if err != nil {
		f.logger.Error("Failed to open source file",
			zap.String("src", src),
			zap.Error(err),
		)
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer srcFile.Close()

	// Get source file info
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file %s: %w", src, err)
	}

	// Use source permissions if perm is 0
	if perm == 0 {
		perm = srcInfo.Mode()
	}

	// Create destination file
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		f.logger.Error("Failed to create destination file",
			zap.String("dst", dst),
			zap.Error(err),
		)
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer dstFile.Close()

	// Copy contents
	written, err := io.Copy(dstFile, srcFile)
	if err != nil {
		f.logger.Error("Failed to copy file contents",
			zap.String("src", src),
			zap.String("dst", dst),
			zap.Error(err),
		)
		return fmt.Errorf("failed to copy contents from %s to %s: %w", src, dst, err)
	}

	f.logger.Info("File copied successfully",
		zap.String("src", src),
		zap.String("dst", dst),
		zap.Int64("bytes", written),
	)

	return nil
}

// MoveFile moves a file from source to destination
func (f *FileSystemOperations) MoveFile(ctx context.Context, src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		// If rename fails (e.g., across filesystems), try copy and delete
		if err := f.CopyFile(ctx, src, dst, 0); err != nil {
			return fmt.Errorf("failed to move file %s to %s: %w", src, dst, err)
		}
		if err := os.Remove(src); err != nil {
			f.logger.Warn("Failed to remove source after copy",
				zap.String("src", src),
				zap.Error(err),
			)
		}
	}
	
	f.logger.Info("File moved successfully",
		zap.String("src", src),
		zap.String("dst", dst),
	)
	
	return nil
}

// DeleteFile removes a file
func (f *FileSystemOperations) DeleteFile(ctx context.Context, path string) error {
	if err := os.Remove(path); err != nil {
		f.logger.Error("Failed to delete file",
			zap.String("path", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to delete file %s: %w", path, err)
	}
	
	f.logger.Debug("File deleted successfully",
		zap.String("path", path),
	)
	
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
			zap.Error(err),
		)
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	
	f.logger.Debug("Directory created successfully",
		zap.String("path", path),
		zap.String("permissions", perm.String()),
	)
	
	return nil
}

// ListDirectory returns a list of files in a directory
func (f *FileSystemOperations) ListDirectory(ctx context.Context, path string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		f.logger.Error("Failed to list directory",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to list directory %s: %w", path, err)
	}
	
	f.logger.Debug("Directory listed successfully",
		zap.String("path", path),
		zap.Int("entries", len(entries)),
	)
	
	return entries, nil
}

// GetFileInfo returns information about a file
func (f *FileSystemOperations) GetFileInfo(ctx context.Context, path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		f.logger.Error("Failed to get file info",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get file info for %s: %w", path, err)
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
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	
	f.logger.Debug("File opened successfully",
		zap.String("path", path),
		zap.Int("flags", flag),
	)
	
	return file, nil
}

// PathOperationsImpl implements fileops.PathOperations
type PathOperationsImpl struct{}

// NewPathOperations creates a new path operations implementation
func NewPathOperations() *PathOperationsImpl {
	return &PathOperationsImpl{}
}

// JoinPath joins path elements
func (p *PathOperationsImpl) JoinPath(elem ...string) string {
	return filepath.Join(elem...)
}

// CleanPath returns the cleaned path
func (p *PathOperationsImpl) CleanPath(path string) string {
	return filepath.Clean(path)
}

// BaseName returns the base name of a path
func (p *PathOperationsImpl) BaseName(path string) string {
	return filepath.Base(path)
}

// DirName returns the directory of a path
func (p *PathOperationsImpl) DirName(path string) string {
	return filepath.Dir(path)
}

// IsAbsPath checks if a path is absolute
func (p *PathOperationsImpl) IsAbsPath(path string) bool {
	return filepath.IsAbs(path)
}

// RelPath returns a relative path
func (p *PathOperationsImpl) RelPath(basepath, targpath string) (string, error) {
	return filepath.Rel(basepath, targpath)
}

// ExpandPath expands environment variables and ~ in paths
func (p *PathOperationsImpl) ExpandPath(path string) string {
	// Expand ~ to home directory
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[1:])
		}
	}
	
	// Expand environment variables
	return os.ExpandEnv(path)
}

// SafeFileOperations implements fileops.SafeOperations
type SafeFileOperations struct {
	logger *zap.Logger
}

// NewSafeFileOperations creates a new safe file operations implementation
func NewSafeFileOperations(logger *zap.Logger) *SafeFileOperations {
	return &SafeFileOperations{
		logger: logger,
	}
}

// SafeClose closes a resource and logs errors
func (s *SafeFileOperations) SafeClose(ctx context.Context, closer io.Closer) error {
	if closer == nil {
		return nil
	}
	
	if err := closer.Close(); err != nil {
		s.logger.Warn("Failed to close resource",
			zap.String("type", fmt.Sprintf("%T", closer)),
			zap.Error(err),
		)
		return err
	}
	
	return nil
}

// SafeRemove removes a file and logs errors
func (s *SafeFileOperations) SafeRemove(ctx context.Context, path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		s.logger.Warn("Failed to remove file",
			zap.String("path", path),
			zap.Error(err),
		)
		return err
	}
	
	return nil
}

// SafeFlush flushes a writer and logs errors
func (s *SafeFileOperations) SafeFlush(ctx context.Context, writer io.Writer) error {
	if flusher, ok := writer.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			s.logger.Warn("Failed to flush writer",
				zap.String("type", fmt.Sprintf("%T", writer)),
				zap.Error(err),
			)
			return err
		}
	}
	
	return nil
}

// Ensure interfaces are implemented
var (
	_ fileops.FileOperations = (*FileSystemOperations)(nil)
	_ fileops.PathOperations = (*PathOperationsImpl)(nil)
	_ fileops.SafeOperations = (*SafeFileOperations)(nil)
)