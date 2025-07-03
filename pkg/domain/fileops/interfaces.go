// Package fileops defines domain interfaces for file operations

package fileops

import (
	"context"
	"io"
	"os"
)

// FileOperations defines the interface for file system operations
type FileOperations interface {
	// ReadFile reads the entire contents of a file
	ReadFile(ctx context.Context, path string) ([]byte, error)

	// WriteFile writes data to a file, creating it if necessary
	WriteFile(ctx context.Context, path string, data []byte, perm os.FileMode) error

	// CopyFile copies a file from source to destination
	CopyFile(ctx context.Context, src, dst string, perm os.FileMode) error

	// MoveFile moves a file from source to destination
	MoveFile(ctx context.Context, src, dst string) error

	// DeleteFile removes a file
	DeleteFile(ctx context.Context, path string) error

	// Exists checks if a file or directory exists
	Exists(ctx context.Context, path string) (bool, error)

	// CreateDirectory creates a directory with the specified permissions
	CreateDirectory(ctx context.Context, path string, perm os.FileMode) error

	// ListDirectory returns a list of files in a directory
	ListDirectory(ctx context.Context, path string) ([]os.DirEntry, error)

	// GetFileInfo returns information about a file
	GetFileInfo(ctx context.Context, path string) (os.FileInfo, error)

	// OpenFile opens a file with the specified flags and permissions
	OpenFile(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error)
}

// ArchiveOperations defines operations for archive handling
type ArchiveOperations interface {
	// CreateArchive creates an archive from files/directories
	CreateArchive(ctx context.Context, archivePath string, sources []string, format ArchiveFormat) error

	// ExtractArchive extracts an archive to a directory
	ExtractArchive(ctx context.Context, archivePath, destDir string) error

	// ListArchive lists contents of an archive
	ListArchive(ctx context.Context, archivePath string) ([]ArchiveEntry, error)
}

// PathOperations defines operations for path manipulation
type PathOperations interface {
	// JoinPath joins path elements
	JoinPath(elem ...string) string

	// CleanPath returns the cleaned path
	CleanPath(path string) string

	// BaseName returns the base name of a path
	BaseName(path string) string

	// DirName returns the directory of a path
	DirName(path string) string

	// IsAbsPath checks if a path is absolute
	IsAbsPath(path string) bool

	// RelPath returns a relative path
	RelPath(basepath, targpath string) (string, error)

	// ExpandPath expands environment variables and ~ in paths
	ExpandPath(path string) string
}

// TemplateOperations defines operations for template processing
type TemplateOperations interface {
	// ReplaceTokensInFile replaces tokens in a file
	ReplaceTokensInFile(ctx context.Context, path string, replacements map[string]string) error

	// ReplaceTokensInDirectory replaces tokens in all files in a directory
	ReplaceTokensInDirectory(ctx context.Context, dir string, replacements map[string]string, patterns []string) error

	// ProcessTemplate processes a template file with the given data
	ProcessTemplate(ctx context.Context, templatePath, outputPath string, data interface{}) error
}

// SafeOperations defines operations with safety features
type SafeOperations interface {
	// WithBackup performs an operation with automatic backup
	WithBackup(ctx context.Context, path string, operation func() error) (backupPath string, err error)

	// WithTransaction performs file operations transactionally
	WithTransaction(ctx context.Context, operations []FileOperation) error

	// WithLock performs an operation with file locking
	WithLock(ctx context.Context, path string, operation func() error) error
}
