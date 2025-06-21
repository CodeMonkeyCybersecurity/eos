// Package fileops defines domain entities for file operations
package fileops

import (
	"os"
	"time"
)

// FileMetadata represents metadata about a file
type FileMetadata struct {
	Path         string      `json:"path"`
	Name         string      `json:"name"`
	Size         int64       `json:"size"`
	Mode         os.FileMode `json:"mode"`
	ModTime      time.Time   `json:"mod_time"`
	IsDir        bool        `json:"is_dir"`
	Owner        string      `json:"owner,omitempty"`
	Group        string      `json:"group,omitempty"`
	Permissions  string      `json:"permissions"`
	Checksum     string      `json:"checksum,omitempty"`
}

// DirectoryInfo represents information about a directory
type DirectoryInfo struct {
	Path        string         `json:"path"`
	FileCount   int            `json:"file_count"`
	DirCount    int            `json:"dir_count"`
	TotalSize   int64          `json:"total_size"`
	Files       []FileMetadata `json:"files,omitempty"`
	Directories []FileMetadata `json:"directories,omitempty"`
}

// CopyOptions represents options for file copy operations
type CopyOptions struct {
	Overwrite        bool        `json:"overwrite"`
	PreserveMode     bool        `json:"preserve_mode"`
	PreserveOwner    bool        `json:"preserve_owner"`
	PreserveTimes    bool        `json:"preserve_times"`
	CreateDirs       bool        `json:"create_dirs"`
	FollowSymlinks   bool        `json:"follow_symlinks"`
	DefaultMode      os.FileMode `json:"default_mode"`
}

// WatchEvent represents a file system watch event
type WatchEvent struct {
	Path      string    `json:"path"`
	Operation string    `json:"operation"` // create, write, remove, rename, chmod
	Timestamp time.Time `json:"timestamp"`
	OldPath   string    `json:"old_path,omitempty"` // for rename operations
}

// ArchiveEntry represents an entry in an archive
type ArchiveEntry struct {
	Path     string      `json:"path"`
	Size     int64       `json:"size"`
	Mode     os.FileMode `json:"mode"`
	ModTime  time.Time   `json:"mod_time"`
	IsDir    bool        `json:"is_dir"`
	Checksum string      `json:"checksum,omitempty"`
}

// TemplateData represents data for template processing
type TemplateData struct {
	Variables   map[string]string      `json:"variables"`
	Lists       map[string][]string    `json:"lists"`
	Objects     map[string]interface{} `json:"objects"`
	Environment map[string]string      `json:"environment"`
}

// FileOperationResult represents the result of a file operation
type FileOperationResult struct {
	Success      bool          `json:"success"`
	Path         string        `json:"path"`
	Operation    string        `json:"operation"`
	BytesWritten int64         `json:"bytes_written,omitempty"`
	BytesRead    int64         `json:"bytes_read,omitempty"`
	Duration     time.Duration `json:"duration"`
	Error        error         `json:"error,omitempty"`
}

// BatchOperationResult represents the result of batch file operations
type BatchOperationResult struct {
	TotalFiles      int                    `json:"total_files"`
	SuccessfulFiles int                    `json:"successful_files"`
	FailedFiles     int                    `json:"failed_files"`
	Results         []FileOperationResult  `json:"results"`
	Duration        time.Duration          `json:"duration"`
}

// FileFilter represents criteria for filtering files
type FileFilter struct {
	IncludePatterns []string      `json:"include_patterns"`
	ExcludePatterns []string      `json:"exclude_patterns"`
	MinSize         int64         `json:"min_size"`
	MaxSize         int64         `json:"max_size"`
	ModifiedAfter   *time.Time    `json:"modified_after,omitempty"`
	ModifiedBefore  *time.Time    `json:"modified_before,omitempty"`
	FileTypes       []string      `json:"file_types"` // extensions
	IncludeHidden   bool          `json:"include_hidden"`
}

// DefaultCopyOptions returns default copy options
func DefaultCopyOptions() CopyOptions {
	return CopyOptions{
		Overwrite:      false,
		PreserveMode:   true,
		PreserveOwner:  false,
		PreserveTimes:  true,
		CreateDirs:     true,
		FollowSymlinks: true,
		DefaultMode:    0644,
	}
}

// DefaultFileFilter returns a default file filter
func DefaultFileFilter() FileFilter {
	return FileFilter{
		IncludePatterns: []string{"*"},
		ExcludePatterns: []string{},
		MinSize:         0,
		MaxSize:         0,
		IncludeHidden:   false,
	}
}