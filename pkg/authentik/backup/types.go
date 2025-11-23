// pkg/authentik/backup/types.go
package backup

import "time"

// Config holds configuration for backup operations
type Config struct {
	// API connection
	URL   string
	Token string

	// Output configuration
	Output string
	Format string

	// Selective backup options
	Types     []string
	Apps      []string
	Providers []string

	// Security options
	IncludeSecrets bool
	ExtractWazuh   bool

	// Legacy filesystem backup options
	IncludeMedia    bool
	IncludeDatabase bool
	Path            string

	// Common options
	OutputDir string
}

// BackupFileInfo contains metadata about a backup file
type BackupFileInfo struct {
	Path             string
	Size             int64
	ModTime          time.Time
	SourceURL        string
	AuthentikVersion string
	Providers        int
	Applications     int
	PropertyMappings int
	Flows            int
	Stages           int
	Groups           int
	Policies         int
	Certificates     int
	Blueprints       int
	Outposts         int
	Tenants          int
}

// RestoreConfig holds configuration for restore operations
type RestoreConfig struct {
	BackupFile     string
	URL            string
	Token          string
	DryRun         bool
	SkipExisting   bool
	UpdateExisting bool
	OnlyTypes      []string
	SkipTypes      []string
	CreateBackup   bool
	Force          bool
}

// ListConfig holds configuration for list operations
type ListConfig struct {
	BackupDir string
}

// ShowConfig holds configuration for show operations
type ShowConfig struct {
	BackupFile string
	Latest     bool
	BackupDir  string
}
