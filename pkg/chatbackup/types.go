// pkg/chatbackup/types.go
// Types for machine-wide AI chat and context backup
//
// RATIONALE: Declarative registry of AI tools and their data locations
// enables extensible, testable backup without hardcoded paths scattered
// across shell scripts.

package chatbackup

// ToolSource represents an AI coding tool whose data we back up.
// Each tool declares where its data lives and what patterns to include.
type ToolSource struct {
	// Name is a human-readable identifier (e.g., "claude-code")
	Name string

	// Description explains what this tool is
	Description string

	// Paths are directories or files to back up, relative to the scan root.
	// Supports:
	//   - Absolute paths (e.g., "/home/henry/.claude/projects")
	//   - Home-relative with ~ (e.g., "~/.claude/projects")
	//   - Glob-relative patterns resolved at runtime
	Paths []SourcePath
}

// SourcePath describes a single backup path with include/exclude patterns.
type SourcePath struct {
	// Path is the directory or file to back up
	// Supports ~ for home directory expansion
	Path string

	// Includes are glob patterns to include (empty = everything)
	Includes []string

	// Excludes are glob patterns to exclude
	Excludes []string

	// Description explains what this path contains
	Description string
}

// RetentionPolicy configures how long to keep snapshots.
type RetentionPolicy struct {
	// KeepWithin keeps ALL snapshots within this duration (e.g., "48h")
	KeepWithin string

	// KeepHourly keeps N hourly snapshots after KeepWithin period
	KeepHourly int

	// KeepDaily keeps N daily snapshots
	KeepDaily int

	// KeepWeekly keeps N weekly snapshots
	KeepWeekly int

	// KeepMonthly keeps N monthly snapshots
	KeepMonthly int
}

// DefaultRetentionPolicy returns sensible defaults for chat backups.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		KeepWithin:  DefaultKeepWithin,
		KeepHourly:  DefaultKeepHourly,
		KeepDaily:   DefaultKeepDaily,
		KeepWeekly:  DefaultKeepWeekly,
		KeepMonthly: DefaultKeepMonthly,
	}
}

// BackupConfig holds configuration for a backup run.
type BackupConfig struct {
	// User is the user whose data to back up (defaults to current user)
	User string

	// HomeDir is resolved at runtime from User
	HomeDir string

	// AllUsers enables machine-wide backup across detected local user homes.
	AllUsers bool

	// ExtraScanDirs are additional directories to scan for project-level
	// AI context files (CLAUDE.md, AGENTS.md, .claude/ dirs)
	// Default per-user: ["/opt"]
	// Default all-users: [DefaultProjectScanDir, DefaultHomeScanDir]
	ExtraScanDirs []string

	// Retention configures snapshot retention policy
	Retention RetentionPolicy

	// DryRun shows what would be done without making changes
	DryRun bool

	// Verbose enables detailed logging of each path scanned
	Verbose bool
}

// DefaultBackupConfig returns sensible defaults.
func DefaultBackupConfig() BackupConfig {
	return BackupConfig{
		ExtraScanDirs: []string{DefaultProjectScanDir},
		Retention:     DefaultRetentionPolicy(),
	}
}

// ScheduleConfig holds configuration for scheduled backups.
type ScheduleConfig struct {
	// BackupConfig embeds the backup configuration
	BackupConfig

	// BackupCron is the cron schedule for backups (default: hourly)
	BackupCron string

	// PruneCron is the cron schedule for pruning (default: daily 3:05am)
	PruneCron string
}

// DefaultScheduleConfig returns sensible defaults.
func DefaultScheduleConfig() ScheduleConfig {
	return ScheduleConfig{
		BackupConfig: DefaultBackupConfig(),
		BackupCron:   DefaultBackupCron,
		PruneCron:    DefaultPruneCron,
	}
}

// BackupResult holds the result of a backup run.
type BackupResult struct {
	// SnapshotID is the restic snapshot ID created
	SnapshotID string

	// PathsBackedUp lists the paths that were included
	PathsBackedUp []string

	// PathsSkipped lists paths that were not found
	PathsSkipped []string

	// FilesNew is the count of new files in this snapshot
	FilesNew int

	// FilesChanged is the count of changed files
	FilesChanged int

	// FilesUnmodified is the count of unchanged files
	FilesUnmodified int

	// BytesAdded is the number of new bytes added to the repo
	BytesAdded int64

	// TotalDuration is how long the backup took
	TotalDuration string

	// ToolsFound lists which AI tools had data to back up
	ToolsFound []string

	// UsersScanned lists users whose homes were scanned during this run.
	UsersScanned []string
}

// ScheduleResult holds the result of schedule setup.
type ScheduleResult struct {
	// CronConfigured indicates if cron was set up
	CronConfigured bool

	// BackupCron is the backup cron expression
	BackupCron string

	// PruneCron is the prune cron expression
	PruneCron string

	// RepoPath is the restic repository path
	RepoPath string

	// PasswordFile is the path to the password file
	PasswordFile string

	// PasswordGenerated is true if a new password was created
	PasswordGenerated bool

	// Warnings contains non-fatal issues
	Warnings []string
}

// BackupStatus tracks backup health for monitoring/alerting.
type BackupStatus struct {
	// LastAttempt is the RFC3339 timestamp of the latest backup attempt.
	LastAttempt string `json:"last_attempt,omitempty"`

	// LastRunState is the outcome of the latest backup attempt.
	// Values: success, failure, noop
	LastRunState string `json:"last_run_state,omitempty"`

	// LastSuccess is the RFC3339 timestamp of last successful backup
	LastSuccess string `json:"last_success,omitempty"`

	// LastFailure is the RFC3339 timestamp of last failed backup
	LastFailure string `json:"last_failure,omitempty"`

	// LastError is a compact human-readable error for the latest failed attempt.
	LastError string `json:"last_error,omitempty"`

	// LastSnapshotID is the ID of the most recent snapshot
	LastSnapshotID string `json:"last_snapshot_id,omitempty"`

	// BytesAdded is bytes added in last backup
	BytesAdded int64 `json:"bytes_added,omitempty"`

	// TotalSnapshots is the current snapshot count
	TotalSnapshots int `json:"total_snapshots,omitempty"`

	// SuccessCount is cumulative successful backups
	SuccessCount int `json:"success_count"`

	// FailureCount is cumulative failed backups
	FailureCount int `json:"failure_count"`

	// FirstBackup is the RFC3339 timestamp of first successful backup
	FirstBackup string `json:"first_backup,omitempty"`

	// ToolsFound lists AI tools discovered in last run
	ToolsFound []string `json:"tools_found,omitempty"`

	// UsersScanned lists users whose homes were scanned in the last run.
	UsersScanned []string `json:"users_scanned,omitempty"`

	// PathsBackedUpCount is the number of included paths in the last run.
	PathsBackedUpCount int `json:"paths_backed_up_count,omitempty"`

	// PathsSkippedCount is the number of skipped paths in the last run.
	PathsSkippedCount int `json:"paths_skipped_count,omitempty"`
}

// BackupManifest records exactly what was included in a successful backup run.
type BackupManifest struct {
	RunAt         string   `json:"run_at"`
	SnapshotID    string   `json:"snapshot_id"`
	UsersScanned  []string `json:"users_scanned,omitempty"`
	ToolsFound    []string `json:"tools_found,omitempty"`
	PathsIncluded []string `json:"paths_included,omitempty"`
	PathsSkipped  []string `json:"paths_skipped,omitempty"`
}
