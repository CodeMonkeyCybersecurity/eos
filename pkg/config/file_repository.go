// Package config provides infrastructure implementations for configuration management
package config

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// FileRepository implements Repository using the filesystem
type FileRepository struct {
	logger *zap.Logger
}

// NewFileRepository creates a new file-based repository
func NewFileRepository(logger *zap.Logger) *FileRepository {
	return &FileRepository{
		logger: logger.Named("file_repository"),
	}
}

// Read reads raw configuration data from a file
func (r *FileRepository) Read(ctx context.Context, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		r.logger.Error("Failed to read config file",
			zap.String("path", path),
			zap.Error(err))
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	r.logger.Debug("Config file read successfully",
		zap.String("path", path),
		zap.Int("size", len(data)))

	return data, nil
}

// Write writes raw configuration data to a file
func (r *FileRepository) Write(ctx context.Context, path string, data []byte, perm FilePermission) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(path, data, os.FileMode(perm)); err != nil {
		r.logger.Error("Failed to write config file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}

	r.logger.Info("Config file written successfully",
		zap.String("path", path),
		zap.Int("size", len(data)))

	return nil
}

// Exists checks if a configuration file exists
func (r *FileRepository) Exists(ctx context.Context, path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("failed to check if config file exists %s: %w", path, err)
}

// Delete removes a configuration file
func (r *FileRepository) Delete(ctx context.Context, path string) error {
	if err := os.Remove(path); err != nil {
		r.logger.Error("Failed to delete config file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to delete config file %s: %w", path, err)
	}

	r.logger.Info("Config file deleted successfully",
		zap.String("path", path))

	return nil
}

// Stat returns file information
func (r *FileRepository) Stat(ctx context.Context, path string) (FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, fmt.Errorf("failed to stat config file %s: %w", path, err)
	}

	return FileInfo{
		Path:        path,
		Size:        info.Size(),
		ModTime:     info.ModTime(),
		Permissions: FilePermission(info.Mode()),
	}, nil
}

// List lists configuration files in a directory
func (r *FileRepository) List(ctx context.Context, dir string) ([]FileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory %s: %w", dir, err)
	}

	var fileInfos []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		fileInfos = append(fileInfos, FileInfo{
			Path:        filepath.Join(dir, info.Name()),
			Size:        info.Size(),
			ModTime:     info.ModTime(),
			Permissions: FilePermission(info.Mode()),
		})
	}

	return fileInfos, nil
}
