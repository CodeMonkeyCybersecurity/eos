package file_backup

import (
	"time"
)

// FileBackupOperation represents a file backup operation
type FileBackupOperation struct {
	SourcePath string        `json:"source_path"`
	BackupPath string        `json:"backup_path"`
	BackupName string        `json:"backup_name"`
	Success    bool          `json:"success"`
	Message    string        `json:"message"`
	Timestamp  time.Time     `json:"timestamp"`
	Duration   time.Duration `json:"duration"`
	FileSize   int64         `json:"file_size"`
	BackupSize int64         `json:"backup_size"`
	DryRun     bool          `json:"dry_run"`
}

// FileBackupConfig contains configuration for file backup operations
type FileBackupConfig struct {
	DefaultBackupDir    string `json:"default_backup_dir" mapstructure:"default_backup_dir"`
	TimestampFormat     string `json:"timestamp_format" mapstructure:"timestamp_format"`
	CreateBackupDir     bool   `json:"create_backup_dir" mapstructure:"create_backup_dir"`
	VerifyAfterBackup   bool   `json:"verify_after_backup" mapstructure:"verify_after_backup"`
	OverwriteExisting   bool   `json:"overwrite_existing" mapstructure:"overwrite_existing"`
	PreservePermissions bool   `json:"preserve_permissions" mapstructure:"preserve_permissions"`
	CreateSymlinks      bool   `json:"create_symlinks" mapstructure:"create_symlinks"`
}

// DefaultFileBackupConfig returns a configuration with sensible defaults
func DefaultFileBackupConfig() *FileBackupConfig {
	return &FileBackupConfig{
		DefaultBackupDir:    "/tmp/eos-file-backups",
		TimestampFormat:     "Monday_2006-01-02_150405",
		CreateBackupDir:     true,
		VerifyAfterBackup:   true,
		OverwriteExisting:   false,
		PreservePermissions: true,
		CreateSymlinks:      false,
	}
}

// BackupOptions contains options for backup operations
type BackupOptions struct {
	BackupDir           string `json:"backup_dir"`
	CustomName          string `json:"custom_name"`
	Interactive         bool   `json:"interactive"`
	Force               bool   `json:"force"`
	DryRun              bool   `json:"dry_run"`
	VerifyAfterBackup   bool   `json:"verify_after_backup"`
	PreservePermissions bool   `json:"preserve_permissions"`
	CreateSymlink       bool   `json:"create_symlink"`
}

// DefaultBackupOptions returns options with sensible defaults
func DefaultBackupOptions() *BackupOptions {
	return &BackupOptions{
		Interactive:         false,
		Force:               false,
		DryRun:              false,
		VerifyAfterBackup:   true,
		PreservePermissions: true,
		CreateSymlink:       false,
	}
}

// BackupListResult contains results of listing backups
type BackupListResult struct {
	BackupDir    string       `json:"backup_dir"`
	Backups      []BackupInfo `json:"backups"`
	TotalBackups int          `json:"total_backups"`
	TotalSize    int64        `json:"total_size"`
	Timestamp    time.Time    `json:"timestamp"`
}

// BackupInfo represents information about a backup file
type BackupInfo struct {
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	OriginalFile string    `json:"original_file"`
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"mod_time"`
	BackupTime   time.Time `json:"backup_time"`
	IsValid      bool      `json:"is_valid"`
}

// RestoreOperation represents a file restore operation
type RestoreOperation struct {
	BackupPath    string        `json:"backup_path"`
	RestorePath   string        `json:"restore_path"`
	Success       bool          `json:"success"`
	Message       string        `json:"message"`
	Timestamp     time.Time     `json:"timestamp"`
	Duration      time.Duration `json:"duration"`
	DryRun        bool          `json:"dry_run"`
	Overwritten   bool          `json:"overwritten"`
	BackupSize    int64         `json:"backup_size"`
	RestoredSize  int64         `json:"restored_size"`
}
