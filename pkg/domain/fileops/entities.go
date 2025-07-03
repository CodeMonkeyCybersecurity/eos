// Package fileops contains domain entities and value objects
package fileops

import (
	"os"
	"time"
)

// ArchiveFormat represents supported archive formats
type ArchiveFormat string

const (
	FormatTar   ArchiveFormat = "tar"
	FormatTarGz ArchiveFormat = "tar.gz"
	FormatZip   ArchiveFormat = "zip"
	Format7z    ArchiveFormat = "7z"
)

// FileOperation represents a single file operation for transactions
type FileOperation struct {
	Type      OperationType
	Source    string
	Target    string
	Data      []byte
	Mode      os.FileMode
	Recursive bool
}

// OperationType defines types of file operations
type OperationType string

const (
	OpCreate OperationType = "create"
	OpCopy   OperationType = "copy"
	OpMove   OperationType = "move"
	OpDelete OperationType = "delete"
	OpMkdir  OperationType = "mkdir"
	OpChmod  OperationType = "chmod"
	OpChown  OperationType = "chown"
)

// CopyOptions defines options for file copying
type CopyOptions struct {
	// PreserveMode preserves original file permissions
	PreserveMode bool

	// PreserveOwner preserves file ownership (requires privileges)
	PreserveOwner bool

	// PreserveTimes preserves modification times
	PreserveTimes bool

	// CreateDirs creates missing parent directories
	CreateDirs bool

	// DefaultMode is used when PreserveMode is false
	DefaultMode os.FileMode

	// Overwrite allows overwriting existing files
	Overwrite bool

	// FollowSymlinks follows symbolic links
	FollowSymlinks bool
}

// FileFilter defines criteria for filtering files
type FileFilter struct {
	// IncludePatterns are glob patterns to include
	IncludePatterns []string

	// ExcludePatterns are glob patterns to exclude
	ExcludePatterns []string

	// MinSize is minimum file size in bytes
	MinSize int64

	// MaxSize is maximum file size in bytes
	MaxSize int64

	// ModifiedAfter filters files modified after this time
	ModifiedAfter *time.Time

	// ModifiedBefore filters files modified before this time
	ModifiedBefore *time.Time

	// FileTypes filters by file type (regular, directory, symlink)
	FileTypes []FileType

	// IncludeHidden includes hidden files (starting with .)
	IncludeHidden bool
}

// FileType represents types of files
type FileType string

const (
	TypeRegular   FileType = "regular"
	TypeDirectory FileType = "directory"
	TypeSymlink   FileType = "symlink"
	TypeDevice    FileType = "device"
	TypePipe      FileType = "pipe"
	TypeSocket    FileType = "socket"
)

// FileMetadata contains detailed file information
type FileMetadata struct {
	Path        string
	Name        string
	Size        int64
	Mode        os.FileMode
	ModTime     time.Time
	IsDir       bool
	IsSymlink   bool
	LinkTarget  string
	Owner       string
	Group       string
	Checksum    string
	MimeType    string
	Permissions string
}

// DirectoryInfo contains information about a directory
type DirectoryInfo struct {
	Path        string
	FileCount   int
	DirCount    int
	TotalSize   int64
	Files       []FileMetadata
	Directories []FileMetadata
}

// ArchiveEntry represents an entry in an archive
type ArchiveEntry struct {
	Path     string
	Size     int64
	Mode     os.FileMode
	ModTime  time.Time
	IsDir    bool
	Checksum string
}

// FileOperationResult contains the result of a file operation
type FileOperationResult struct {
	Path         string
	Operation    string
	Success      bool
	Error        error
	BackupPath   string
	BytesRead    int64
	BytesWritten int64
	Duration     time.Duration
}

// BatchOperationResult contains results of batch operations
type BatchOperationResult struct {
	TotalFiles      int
	SuccessfulFiles int
	FailedFiles     int
	Results         []FileOperationResult
	Duration        time.Duration
}

// TemplateData contains data for template processing
type TemplateData struct {
	Variables   map[string]string
	Environment map[string]string
	Functions   map[string]interface{}
}

// BackupOptions defines options for backup operations
type BackupOptions struct {
	// BackupDir specifies where to store backups
	BackupDir string

	// KeepBackups specifies how many backups to keep
	KeepBackups int

	// CompressBackups enables backup compression
	CompressBackups bool

	// BackupExtension is the extension for backup files
	BackupExtension string
}

// TransactionOptions defines options for transactional operations
type TransactionOptions struct {
	// Rollback on any error
	RollbackOnError bool

	// Continue on non-fatal errors
	ContinueOnError bool

	// Verify operations after completion
	Verify bool
}

// DefaultCopyOptions returns default copy options
func DefaultCopyOptions() CopyOptions {
	return CopyOptions{
		PreserveMode:   false,
		PreserveOwner:  false,
		PreserveTimes:  false,
		CreateDirs:     true,
		DefaultMode:    0644,
		Overwrite:      true,
		FollowSymlinks: false,
	}
}

// DefaultFileFilter returns a default file filter
func DefaultFileFilter() FileFilter {
	return FileFilter{
		IncludeHidden: false,
		FileTypes:     []FileType{TypeRegular, TypeDirectory},
	}
}

// DefaultBackupOptions returns default backup options
func DefaultBackupOptions() BackupOptions {
	return BackupOptions{
		BackupDir:       "",
		KeepBackups:     3,
		CompressBackups: false,
		BackupExtension: ".backup",
	}
}

// IsError returns true if the operation failed
func (r *FileOperationResult) IsError() bool {
	return !r.Success || r.Error != nil
}

// SuccessRate returns the success rate as a percentage
func (r *BatchOperationResult) SuccessRate() float64 {
	if r.TotalFiles == 0 {
		return 100.0
	}
	return float64(r.SuccessfulFiles) / float64(r.TotalFiles) * 100
}
