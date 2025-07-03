// Package fileops provides domain services for file operations
package fileops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Service provides high-level file operation services
type Service struct {
	fileOps     FileOperations
	pathOps     PathOperations
	templateOps TemplateOperations
	safeOps     SafeOperations
	logger      *zap.Logger
}

// NewService creates a new file operations service
func NewService(
	fileOps FileOperations,
	pathOps PathOperations,
	templateOps TemplateOperations,
	safeOps SafeOperations,
	logger *zap.Logger,
) *Service {
	return &Service{
		fileOps:     fileOps,
		pathOps:     pathOps,
		templateOps: templateOps,
		safeOps:     safeOps,
		logger:      logger.Named("fileops.service"),
	}
}

// Basic operations delegated to infrastructure

// ReadFile reads a file
func (s *Service) ReadFile(ctx context.Context, path string) ([]byte, error) {
	return s.fileOps.ReadFile(ctx, path)
}

// WriteFile writes a file
func (s *Service) WriteFile(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	return s.fileOps.WriteFile(ctx, path, data, perm)
}

// Exists checks if a file exists
func (s *Service) Exists(ctx context.Context, path string) (bool, error) {
	return s.fileOps.Exists(ctx, path)
}

// DeleteFile deletes a file
func (s *Service) DeleteFile(ctx context.Context, path string) error {
	return s.fileOps.DeleteFile(ctx, path)
}

// High-level operations with business logic

// CopyFile copies a file with default options
func (s *Service) CopyFile(ctx context.Context, src, dst string) error {
	opts := DefaultCopyOptions()
	result, err := s.CopyFileWithOptions(ctx, src, dst, opts)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("copy operation failed: %v", result.Error)
	}
	return nil
}

// CopyFileWithOptions copies a file with custom options
func (s *Service) CopyFileWithOptions(ctx context.Context, src, dst string, opts CopyOptions) (*FileOperationResult, error) {
	start := time.Now()
	result := &FileOperationResult{
		Path:      dst,
		Operation: "copy",
		Success:   false,
	}

	// Create destination directory if needed
	if opts.CreateDirs {
		dstDir := s.pathOps.DirName(dst)
		if err := s.fileOps.CreateDirectory(ctx, dstDir, 0755); err != nil {
			result.Error = fmt.Errorf("failed to create destination directory: %w", err)
			return result, result.Error
		}
	}

	// Get source file info
	srcInfo, err := s.fileOps.GetFileInfo(ctx, src)
	if err != nil {
		result.Error = fmt.Errorf("failed to get source file info: %w", err)
		return result, result.Error
	}

	// Determine permissions
	perm := opts.DefaultMode
	if opts.PreserveMode {
		perm = srcInfo.Mode()
	}

	// Perform the copy
	if err := s.fileOps.CopyFile(ctx, src, dst, perm); err != nil {
		result.Error = fmt.Errorf("failed to copy file: %w", err)
		return result, result.Error
	}

	result.Success = true
	result.BytesRead = srcInfo.Size()
	result.BytesWritten = srcInfo.Size()
	result.Duration = time.Since(start)

	s.logger.Info("File copied successfully",
		zap.String("source", src),
		zap.String("destination", dst),
		zap.Int64("size", srcInfo.Size()),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// CopyDirectory copies a directory recursively
func (s *Service) CopyDirectory(ctx context.Context, src, dst string, opts CopyOptions, filter FileFilter) (*BatchOperationResult, error) {
	start := time.Now()
	batchResult := &BatchOperationResult{
		Results: []FileOperationResult{},
	}

	// Walk the source directory
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip if it doesn't match filter
		if !s.matchesFilter(path, info, filter) {
			return nil
		}

		// Calculate relative path
		relPath, err := s.pathOps.RelPath(src, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Calculate destination path
		dstPath := s.pathOps.JoinPath(dst, relPath)

		// Handle directories
		if info.IsDir() {
			if err := s.fileOps.CreateDirectory(ctx, dstPath, info.Mode()); err != nil {
				batchResult.FailedFiles++
				batchResult.Results = append(batchResult.Results, FileOperationResult{
					Path:      dstPath,
					Operation: "mkdir",
					Error:     err,
				})
				return nil // Continue with other files
			}
			return nil
		}

		// Copy file
		result, err := s.CopyFileWithOptions(ctx, path, dstPath, opts)
		if err != nil {
			batchResult.FailedFiles++
		} else {
			batchResult.SuccessfulFiles++
		}
		batchResult.Results = append(batchResult.Results, *result)

		return nil
	})

	if err != nil {
		return batchResult, fmt.Errorf("failed to walk directory: %w", err)
	}

	batchResult.TotalFiles = len(batchResult.Results)
	batchResult.Duration = time.Since(start)

	s.logger.Info("Directory copy completed",
		zap.String("source", src),
		zap.String("destination", dst),
		zap.Int("total_files", batchResult.TotalFiles),
		zap.Int("successful", batchResult.SuccessfulFiles),
		zap.Int("failed", batchResult.FailedFiles),
		zap.Duration("duration", batchResult.Duration))

	return batchResult, nil
}

// DeleteFiles deletes multiple files matching a pattern
func (s *Service) DeleteFiles(ctx context.Context, baseDir string, filter FileFilter) (*BatchOperationResult, error) {
	start := time.Now()
	batchResult := &BatchOperationResult{
		Results: []FileOperationResult{},
	}

	entries, err := s.fileOps.ListDirectory(ctx, baseDir)
	if err != nil {
		return batchResult, fmt.Errorf("failed to list directory: %w", err)
	}

	for _, entry := range entries {
		path := s.pathOps.JoinPath(baseDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if !s.matchesFilter(path, info, filter) {
			continue
		}

		result := FileOperationResult{
			Path:      path,
			Operation: "delete",
		}

		if err := s.fileOps.DeleteFile(ctx, path); err != nil {
			result.Error = err
			batchResult.FailedFiles++
		} else {
			result.Success = true
			batchResult.SuccessfulFiles++
		}

		batchResult.Results = append(batchResult.Results, result)
	}

	batchResult.TotalFiles = len(batchResult.Results)
	batchResult.Duration = time.Since(start)

	return batchResult, nil
}

// GetDirectoryInfo returns detailed information about a directory
func (s *Service) GetDirectoryInfo(ctx context.Context, path string) (*DirectoryInfo, error) {
	info := &DirectoryInfo{
		Path:        path,
		Files:       []FileMetadata{},
		Directories: []FileMetadata{},
	}

	entries, err := s.fileOps.ListDirectory(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	for _, entry := range entries {
		fullPath := s.pathOps.JoinPath(path, entry.Name())
		fileInfo, err := entry.Info()
		if err != nil {
			continue
		}

		metadata := FileMetadata{
			Path:        fullPath,
			Name:        entry.Name(),
			Size:        fileInfo.Size(),
			Mode:        fileInfo.Mode(),
			ModTime:     fileInfo.ModTime(),
			IsDir:       fileInfo.IsDir(),
			Permissions: fileInfo.Mode().String(),
		}

		if fileInfo.IsDir() {
			info.DirCount++
			info.Directories = append(info.Directories, metadata)
		} else {
			info.FileCount++
			info.TotalSize += fileInfo.Size()
			info.Files = append(info.Files, metadata)
		}
	}

	return info, nil
}

// ProcessTemplateDirectory processes all template files in a directory
func (s *Service) ProcessTemplateDirectory(ctx context.Context, srcDir, dstDir string, data TemplateData, patterns []string) error {
	// Default patterns if none provided
	if len(patterns) == 0 {
		patterns = []string{"*.tmpl", "*.template"}
	}

	// Convert TemplateData to replacements map for simple token replacement
	replacements := make(map[string]string)
	for k, v := range data.Variables {
		replacements[k] = v
	}
	for k, v := range data.Environment {
		replacements[k] = v
	}

	// Process templates
	return s.templateOps.ReplaceTokensInDirectory(ctx, srcDir, replacements, patterns)
}

// EnsureDirectory ensures a directory exists with proper permissions
func (s *Service) EnsureDirectory(ctx context.Context, path string, perm os.FileMode) error {
	exists, err := s.fileOps.Exists(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to check directory existence: %w", err)
	}

	if exists {
		info, err := s.fileOps.GetFileInfo(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to get directory info: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", path)
		}
		return nil
	}

	return s.fileOps.CreateDirectory(ctx, path, perm)
}

// SafeWriteFile writes a file with automatic backup
func (s *Service) SafeWriteFile(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	// Check if file exists
	exists, err := s.fileOps.Exists(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to check file existence: %w", err)
	}

	// Create backup if file exists
	if exists {
		backupPath := fmt.Sprintf("%s.backup.%d", path, time.Now().Unix())
		if err := s.fileOps.CopyFile(ctx, path, backupPath, perm); err != nil {
			s.logger.Warn("Failed to create backup",
				zap.String("path", path),
				zap.String("backup", backupPath),
				zap.Error(err))
		}
	}

	// Write the file
	if err := s.fileOps.WriteFile(ctx, path, data, perm); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	s.logger.Info("File written safely",
		zap.String("path", path),
		zap.Int("size", len(data)),
		zap.Bool("backup_created", exists))

	return nil
}

// matchesFilter checks if a file matches the given filter criteria
func (s *Service) matchesFilter(path string, info os.FileInfo, filter FileFilter) bool {
	// Check hidden files
	if !filter.IncludeHidden && strings.HasPrefix(s.pathOps.BaseName(path), ".") {
		return false
	}

	// Check size constraints
	if filter.MinSize > 0 && info.Size() < filter.MinSize {
		return false
	}
	if filter.MaxSize > 0 && info.Size() > filter.MaxSize {
		return false
	}

	// Check modification time
	if filter.ModifiedAfter != nil && info.ModTime().Before(*filter.ModifiedAfter) {
		return false
	}
	if filter.ModifiedBefore != nil && info.ModTime().After(*filter.ModifiedBefore) {
		return false
	}

	// Check file types
	if len(filter.FileTypes) > 0 {
		matched := false
		for _, ft := range filter.FileTypes {
			switch ft {
			case TypeRegular:
				if info.Mode().IsRegular() {
					matched = true
				}
			case TypeDirectory:
				if info.IsDir() {
					matched = true
				}
			case TypeSymlink:
				if info.Mode()&os.ModeSymlink != 0 {
					matched = true
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check include patterns
	if len(filter.IncludePatterns) > 0 {
		matched := false
		for _, pattern := range filter.IncludePatterns {
			if match, _ := filepath.Match(pattern, s.pathOps.BaseName(path)); match {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check exclude patterns
	for _, pattern := range filter.ExcludePatterns {
		if match, _ := filepath.Match(pattern, s.pathOps.BaseName(path)); match {
			return false
		}
	}

	return true
}

// Batch operations with progress reporting

// BatchCopy performs multiple copy operations
func (s *Service) BatchCopy(ctx context.Context, operations []struct{ Src, Dst string }, opts CopyOptions) (*BatchOperationResult, error) {
	start := time.Now()
	batchResult := &BatchOperationResult{
		Results:    make([]FileOperationResult, 0, len(operations)),
		TotalFiles: len(operations),
	}

	for _, op := range operations {
		result, err := s.CopyFileWithOptions(ctx, op.Src, op.Dst, opts)
		if err != nil || !result.Success {
			batchResult.FailedFiles++
		} else {
			batchResult.SuccessfulFiles++
		}
		batchResult.Results = append(batchResult.Results, *result)
	}

	batchResult.Duration = time.Since(start)
	return batchResult, nil
}
