package file_backup

// CommandConfig holds all flag configurations for file backup commands
// Migrated from cmd/backup/file.go package-level variables
type CommandConfig struct {
	// Backup command flags
	BackupDir        string
	CustomName       string
	Interactive      bool
	Force            bool
	DryRun           bool
	NoVerify         bool
	NoPreserve       bool
	CreateSymlink    bool
	OutputJSON       bool

	// List command flags
	ListBackupDir  string
	ListOutputJSON bool

	// Restore command flags
	RestoreForce      bool
	RestoreDryRun     bool
	RestoreOutputJSON bool
}

// NewCommandConfig creates a new CommandConfig with defaults
// Migrated from cmd/backup/file.go flag variable initialization
func NewCommandConfig() *CommandConfig {
	return &CommandConfig{}
}