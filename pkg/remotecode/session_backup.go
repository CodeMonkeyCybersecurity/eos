// pkg/remotecode/session_backup.go
// Session backup functionality for Claude Code and Codex coding sessions
//
// RATIONALE: Coding sessions in Claude Code and Codex store conversation data
// locally but can be compacted or lost. This provides automatic periodic backups
// for auditing, reference, and data preservation.
//
// Data locations:
// - Claude Code: ~/.claude/projects/{project-path}/*.jsonl, ~/.claude/todos/, ~/.claude/file-history/
// - Codex: ~/.codex/sessions/{year}/{month}/{day}/*.jsonl

package remotecode

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Session backup constants
const (
	// BackupScriptName is the name of the backup script
	BackupScriptName = "backup-coding-sessions.sh"

	// SetupScriptName is the name of the interactive setup script
	SetupScriptName = "setup-coding-session-backups.sh"

	// ExportScriptName is the name of the export script
	ExportScriptName = "export-coding-sessions.sh"

	// PruneScriptName is the name of the restic prune script
	PruneScriptName = "prune-coding-sessions.sh"

	// DefaultBackupInterval is the default cron interval (hourly)
	DefaultBackupInterval = "0 * * * *"

	// DefaultPruneInterval is the default cron interval for prune (daily at 3am)
	DefaultPruneInterval = "0 3 * * *"

	// BackupScriptPerm is the permission for backup scripts
	BackupScriptPerm = 0755

	// Restic repository paths (relative to home directory)
	// ResticRepoDir is the default local restic repository
	ResticRepoDir = ".eos/restic/coding-sessions"

	// ResticPasswordFile stores the repository password
	ResticPasswordFile = ".eos/restic/password"

	// ResticLogFile stores backup/prune logs
	ResticLogFile = ".eos/restic/backup.log"

	// ResticStatusFile stores backup status as JSON
	ResticStatusFile = ".eos/restic/status.json"

	// ResticPasswordPerm is the permission for the password file
	// SECURITY: Owner read-only to prevent password exposure via ps or /proc
	ResticPasswordPerm = 0400

	// ResticRepoPerm is the permission for the repository directory
	// SECURITY: Owner-only access to encrypted backup data
	ResticRepoPerm = 0700

	// ResticDirPerm is the permission for the .eos/restic directory
	ResticDirPerm = 0700

	// MigrationRequiredSuccesses is the number of successful backups required
	// before prompting to migrate from tar.gz
	MigrationRequiredSuccesses = 10

	// MigrationRequiredDays is the minimum days since first backup
	// before prompting to migrate from tar.gz
	MigrationRequiredDays = 7
)

// SessionBackupConfig holds configuration for session backup setup
type SessionBackupConfig struct {
	// User is the user to set up backups for
	User string

	// BackupDir is the directory to store backups (DEPRECATED: use restic repo)
	BackupDir string

	// BinDir is the directory to install scripts
	BinDir string

	// CronInterval is the cron schedule (e.g., "0 * * * *" for hourly)
	CronInterval string

	// DryRun shows what would be done without making changes
	DryRun bool

	// UseRestic enables restic-based backups with deduplication
	UseRestic bool

	// RetentionPolicy configures snapshot retention (restic only)
	RetentionPolicy *ResticRetentionPolicy
}

// ResticRetentionPolicy configures how long to keep snapshots
type ResticRetentionPolicy struct {
	// KeepWithin keeps ALL snapshots within this duration (e.g., "48h")
	// Provides fine-grained recovery for recent work
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

// ResticBackupStatus tracks backup health for migration decisions
type ResticBackupStatus struct {
	// LastSuccess is the timestamp of last successful backup
	LastSuccess string `json:"last_success,omitempty"`

	// LastFailure is the timestamp of last failed backup (if any)
	LastFailure string `json:"last_failure,omitempty"`

	// LastSnapshotID is the ID of the most recent snapshot
	LastSnapshotID string `json:"last_snapshot_id,omitempty"`

	// BytesAdded is bytes added in last backup (for dedup stats)
	BytesAdded int64 `json:"bytes_added,omitempty"`

	// TotalSnapshots is the current snapshot count
	TotalSnapshots int `json:"total_snapshots,omitempty"`

	// SuccessfulBackupCount is cumulative successful backups
	SuccessfulBackupCount int `json:"successful_backup_count"`

	// FirstBackup is the timestamp of first successful backup
	FirstBackup string `json:"first_backup,omitempty"`
}

// DefaultRetentionPolicy returns sensible defaults for coding session backups
func DefaultRetentionPolicy() *ResticRetentionPolicy {
	return &ResticRetentionPolicy{
		KeepWithin:  "48h", // Keep everything for 48 hours
		KeepHourly:  24,    // Then 24 hourly snapshots
		KeepDaily:   7,     // Then 7 daily
		KeepWeekly:  4,     // Then 4 weekly
		KeepMonthly: 12,    // Then 12 monthly
	}
}

// ValidateResticDuration validates a duration string for restic's --keep-within flag
// Accepts:
// - Go durations: "48h", "168h", "720h"
// - Restic durations: "2d", "7d", "1m", "1y" (days, months, years)
// Returns an error with remediation guidance if invalid
func ValidateResticDuration(s string) error {
	if s == "" {
		return fmt.Errorf("duration cannot be empty; use format like '48h', '7d', '1m', or '1y'")
	}

	// Try Go duration first (supports hours, minutes, seconds)
	if _, err := time.ParseDuration(s); err == nil {
		return nil
	}

	// Check restic-specific format: number + unit (d=days, m=months, y=years)
	// Restic also supports h (hours) which Go handles above
	resticDurationPattern := regexp.MustCompile(`^\d+[hdmy]$`)
	if resticDurationPattern.MatchString(s) {
		return nil
	}

	return fmt.Errorf("invalid duration format %q: use Go duration (e.g., '48h', '168h') "+
		"or restic format (e.g., '7d', '1m', '1y')", s)
}

// SessionBackupResult holds the result of session backup setup
type SessionBackupResult struct {
	// ScriptsInstalled lists the scripts that were installed
	ScriptsInstalled []string

	// CronConfigured indicates if cron was set up
	CronConfigured bool

	// CronInterval is the interval configured
	CronInterval string

	// BackupDir is the backup directory (or restic repo path)
	BackupDir string

	// ClaudeDataFound indicates if Claude Code data was found
	ClaudeDataFound bool

	// CodexDataFound indicates if Codex data was found
	CodexDataFound bool

	// Warnings contains any non-fatal issues
	Warnings []string

	// UseRestic indicates if restic-based backups are configured
	UseRestic bool

	// ResticRepoPath is the path to the restic repository
	ResticRepoPath string

	// ResticPasswordFile is the path to the password file
	ResticPasswordFile string

	// ResticPassword is the generated password (shown once to user)
	// SECURITY: Only populated during initial setup, not stored in result
	ResticPassword string
}

// =============================================================================
// Restic Helper Functions
// =============================================================================

// ensureShellDependencies checks if jq and flock are available
// These are required by the backup and prune scripts for:
// - jq: JSON parsing for status updates, health checks, export
// - flock: Preventing concurrent backup/prune runs
func ensureShellDependencies(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	deps := []struct {
		name    string
		purpose string
	}{
		{"jq", "JSON parsing for status tracking and health checks"},
		{"flock", "preventing concurrent backup runs"},
	}

	var missing []string
	for _, dep := range deps {
		if _, err := exec.LookPath(dep.name); err != nil {
			missing = append(missing, dep.name)
			logger.Debug("Dependency not found",
				zap.String("name", dep.name),
				zap.String("purpose", dep.purpose))
		}
	}

	if len(missing) == 0 {
		logger.Debug("All shell dependencies available")
		return nil
	}

	logger.Warn("Missing dependencies for backup scripts",
		zap.Strings("missing", missing))

	// Human-centric: offer to install rather than failing
	missingList := strings.Join(missing, ", ")
	proceed, err := interaction.PromptYesNoSafe(rc,
		fmt.Sprintf("Required tools missing: %s\n"+
			"These are needed for backup status tracking and concurrent run protection.\n"+
			"Install with: sudo apt install %s\n"+
			"Would you like to install them now?",
			missingList,
			strings.Join(missing, " ")),
		true)
	if err != nil {
		return fmt.Errorf("required dependencies (%s) not installed; install with: sudo apt install %s",
			missingList, strings.Join(missing, " "))
	}

	if !proceed {
		return fmt.Errorf("required dependencies (%s) not installed; install with: sudo apt install %s",
			missingList, strings.Join(missing, " "))
	}

	// Attempt installation
	logger.Info("Installing dependencies via apt", zap.Strings("packages", missing))
	args := append([]string{"install", "-y"}, missing...)
	cmd := exec.Command("apt", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install dependencies: %w\nInstall manually with: sudo apt install %s",
			err, strings.Join(missing, " "))
	}

	// Verify installation
	for _, dep := range missing {
		if _, err := exec.LookPath(dep); err != nil {
			return fmt.Errorf("dependency %s installation failed; install manually with: sudo apt install %s",
				dep, dep)
		}
	}

	logger.Info("Dependencies installed successfully", zap.Strings("packages", missing))
	return nil
}

// ensureResticInstalled checks if restic is available and offers to install if missing
func ensureResticInstalled(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if _, err := exec.LookPath("restic"); err == nil {
		logger.Debug("restic is installed")
		return nil
	}

	logger.Warn("restic not found, prompting for installation")

	// Use human-centric pattern: offer to install rather than failing
	proceed, promptErr := interaction.PromptYesNoSafe(rc,
		"restic is required for deduplicated backups but is not installed.\n"+
			"Install with: sudo apt install restic\n"+
			"Would you like to install it now?",
		true)
	if promptErr != nil {
		return fmt.Errorf("restic is required: install with 'sudo apt install restic'")
	}

	if !proceed {
		return fmt.Errorf("restic is required for backup functionality; install with 'sudo apt install restic'")
	}

	// Attempt installation
	logger.Info("Installing restic via apt")
	cmd := exec.Command("apt", "install", "-y", "restic")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install restic: %w\nInstall manually with: sudo apt install restic", err)
	}

	// Verify installation
	if _, err := exec.LookPath("restic"); err != nil {
		return fmt.Errorf("restic installation failed; install manually with: sudo apt install restic")
	}

	logger.Info("restic installed successfully")
	return nil
}

// generateResticPassword creates a secure password for the repository
func generateResticPassword(passwordFile string) (string, error) {
	// Use alphanumeric password for maximum compatibility
	// 32 chars = ~190 bits entropy (exceeds AES-128)
	password, err := crypto.GenerateURLSafePassword(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(passwordFile)
	if err := os.MkdirAll(parentDir, ResticDirPerm); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %w", parentDir, err)
	}

	// Write with secure permissions
	// SECURITY: 0400 = owner read-only, prevents exposure via ps or /proc
	if err := os.WriteFile(passwordFile, []byte(password), ResticPasswordPerm); err != nil {
		return "", fmt.Errorf("failed to write password file: %w", err)
	}

	return password, nil
}

// initResticRepo initializes a new restic repository (idempotent)
func initResticRepo(rc *eos_io.RuntimeContext, repoPath, passwordFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if already initialized by verifying config exists
	checkCmd := exec.Command("restic", "-r", repoPath, "--password-file", passwordFile, "cat", "config")
	if err := checkCmd.Run(); err == nil {
		logger.Info("Restic repository already initialized", zap.String("repo", repoPath))
		return nil
	}

	// Ensure repository directory exists
	if err := os.MkdirAll(repoPath, ResticRepoPerm); err != nil {
		return fmt.Errorf("failed to create repository directory %s: %w", repoPath, err)
	}

	// Initialize repository
	logger.Info("Initializing restic repository", zap.String("repo", repoPath))
	cmd := exec.Command("restic", "-r", repoPath, "--password-file", passwordFile, "init")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to initialize restic repository: %w\nOutput: %s", err, string(output))
	}

	logger.Info("Restic repository initialized", zap.String("repo", repoPath))
	return nil
}

// readResticStatus reads the backup status file
func readResticStatus(statusFile string) (*ResticBackupStatus, error) {
	data, err := os.ReadFile(statusFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &ResticBackupStatus{}, nil
		}
		return nil, err
	}

	var status ResticBackupStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// writeResticStatus writes the backup status file
func writeResticStatus(statusFile string, status *ResticBackupStatus) error {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statusFile, data, 0644)
}

// checkMigrationEligible checks if user should be prompted to migrate from tar.gz
// Requires: N successful backups over at least 7 days
func checkMigrationEligible(rc *eos_io.RuntimeContext, homeDir string) (bool, string) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if old tar.gz backups exist
	oldBackupDir := filepath.Join(homeDir, "coding-session-backups")
	if _, err := os.Stat(oldBackupDir); os.IsNotExist(err) {
		return false, "" // Nothing to migrate
	}

	// Check restic status
	statusFile := filepath.Join(homeDir, ResticStatusFile)
	status, err := readResticStatus(statusFile)
	if err != nil {
		logger.Debug("Could not read restic status", zap.Error(err))
		return false, oldBackupDir
	}

	// Check success count threshold
	if status.SuccessfulBackupCount < MigrationRequiredSuccesses {
		logger.Debug("Not enough successful backups for migration",
			zap.Int("count", status.SuccessfulBackupCount),
			zap.Int("required", MigrationRequiredSuccesses))
		return false, oldBackupDir
	}

	// Check time threshold
	if status.FirstBackup == "" {
		return false, oldBackupDir
	}

	firstBackup, err := time.Parse(time.RFC3339, status.FirstBackup)
	if err != nil {
		logger.Debug("Could not parse first backup time", zap.Error(err))
		return false, oldBackupDir
	}

	daysSinceFirst := time.Since(firstBackup).Hours() / 24
	if daysSinceFirst < float64(MigrationRequiredDays) {
		logger.Debug("Not enough days since first backup",
			zap.Float64("days", daysSinceFirst),
			zap.Int("required", MigrationRequiredDays))
		return false, oldBackupDir
	}

	logger.Info("Migration eligible",
		zap.Int("successful_backups", status.SuccessfulBackupCount),
		zap.Float64("days_since_first", daysSinceFirst))

	return true, oldBackupDir
}

// promptMigration prompts the user to clean up old tar.gz backups after restic
// has proven itself with N successful backups over 7+ days
func promptMigration(rc *eos_io.RuntimeContext, homeDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	eligible, oldBackupDir := checkMigrationEligible(rc, homeDir)
	if !eligible {
		return nil // Not eligible yet
	}

	// Calculate size of old backups
	var totalSize int64
	err := filepath.Walk(oldBackupDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil {
		logger.Debug("Could not calculate old backup size", zap.Error(err))
	}

	// Format size for display
	sizeStr := formatBytes(totalSize)

	logger.Info("Old tar.gz backups found",
		zap.String("path", oldBackupDir),
		zap.String("size", sizeStr))

	// Prompt user - default No for safety
	proceed, err := interaction.PromptYesNoSafe(rc,
		fmt.Sprintf("Restic backups have been running successfully.\n"+
			"Old tar.gz backups found at %s (%s).\n"+
			"These are no longer needed - remove them to save space?",
			oldBackupDir, sizeStr),
		false) // Default: No (safe)
	if err != nil {
		return nil // Non-fatal, just skip migration
	}

	if !proceed {
		logger.Info("User declined to remove old backups")
		return nil
	}

	// Remove old backups
	if err := os.RemoveAll(oldBackupDir); err != nil {
		logger.Warn("Failed to remove old backups", zap.String("path", oldBackupDir), zap.Error(err))
		return nil // Non-fatal
	}

	logger.Info("Removed old tar.gz backups",
		zap.String("path", oldBackupDir),
		zap.String("size_freed", sizeStr))

	return nil
}

// SetupSessionBackups installs restic-based backup scripts and configures cron
// ASSESS: Check for existing installation, find Claude/Codex data, check restic
// INTERVENE: Initialize restic repo, install scripts, configure cron
// EVALUATE: Verify installation, display password
//
// NOTE: As of 2025-01, restic is mandatory for session backups.
// The --use-restic flag is deprecated and ignored; restic provides
// block-level deduplication and AES-256 encryption which tar.gz cannot match.
func SetupSessionBackups(rc *eos_io.RuntimeContext, config *SessionBackupConfig) (*SessionBackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Warn if user explicitly set --use-restic=false (deprecated, ignored)
	if !config.UseRestic {
		logger.Warn("--use-restic=false is deprecated and ignored; restic is now mandatory for session backups",
			zap.String("reason", "restic provides block-level deduplication and AES-256 encryption"))
	}

	logger.Info("Setting up coding session backups (restic)",
		zap.String("user", config.User),
		zap.Bool("dry_run", config.DryRun))

	result := &SessionBackupResult{
		ScriptsInstalled: []string{},
		Warnings:         []string{},
		UseRestic:        true, // Always true now
	}

	// Get home directory
	homeDir, err := getHomeDir(config.User)
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	// Set defaults
	if config.BinDir == "" {
		config.BinDir = filepath.Join(homeDir, "bin")
	}

	if config.CronInterval == "" {
		config.CronInterval = DefaultBackupInterval
	}
	result.CronInterval = config.CronInterval

	if config.RetentionPolicy == nil {
		config.RetentionPolicy = DefaultRetentionPolicy()
	}

	// Validate retention policy duration (fail fast on invalid input)
	if err := ValidateResticDuration(config.RetentionPolicy.KeepWithin); err != nil {
		return nil, fmt.Errorf("invalid --keep-within value: %w", err)
	}

	// Set restic paths
	resticDir := filepath.Join(homeDir, ".eos", "restic")
	repoPath := filepath.Join(homeDir, ResticRepoDir)
	passwordFile := filepath.Join(homeDir, ResticPasswordFile)

	result.BackupDir = repoPath
	result.ResticRepoPath = repoPath
	result.ResticPasswordFile = passwordFile

	// ASSESS: Check for Claude Code and Codex data
	claudeDir := filepath.Join(homeDir, ".claude")
	codexDir := filepath.Join(homeDir, ".codex")

	if _, err := os.Stat(claudeDir); err == nil {
		result.ClaudeDataFound = true
		logger.Info("Found Claude Code data", zap.String("path", claudeDir))
	}

	if _, err := os.Stat(codexDir); err == nil {
		result.CodexDataFound = true
		logger.Info("Found Codex data", zap.String("path", codexDir))
	}

	if !result.ClaudeDataFound && !result.CodexDataFound {
		result.Warnings = append(result.Warnings,
			"No Claude Code or Codex data found. Backups will be set up but won't capture anything until you use these tools.")
		logger.Warn("No coding session data found")
	}

	// DRY RUN: Show what would be done
	if config.DryRun {
		logger.Info("DRY RUN: Would set up restic-based session backups",
			zap.String("bin_dir", config.BinDir),
			zap.String("restic_repo", repoPath),
			zap.String("cron_interval", config.CronInterval))
		result.ScriptsInstalled = []string{
			BackupScriptName + " (would install)",
			PruneScriptName + " (would install)",
			SetupScriptName + " (would install)",
			ExportScriptName + " (would install)",
		}
		result.CronConfigured = false
		return result, nil
	}

	// ASSESS: Check for restic
	if err := ensureResticInstalled(rc); err != nil {
		return nil, fmt.Errorf("restic setup failed: %w", err)
	}

	// ASSESS: Check for shell dependencies (jq, flock)
	if err := ensureShellDependencies(rc); err != nil {
		return nil, fmt.Errorf("dependency setup failed: %w", err)
	}

	// INTERVENE: Create directories
	if err := os.MkdirAll(config.BinDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bin directory %s: %w", config.BinDir, err)
	}

	if err := os.MkdirAll(resticDir, ResticDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create restic directory %s: %w", resticDir, err)
	}

	// INTERVENE: Generate password if needed (only on first setup)
	passwordGenerated := false
	if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
		password, err := generateResticPassword(passwordFile)
		if err != nil {
			return nil, fmt.Errorf("failed to generate repository password: %w", err)
		}
		result.ResticPassword = password
		passwordGenerated = true
		logger.Info("Generated restic repository password",
			zap.String("file", passwordFile))
	}

	// INTERVENE: Initialize restic repository
	if err := initResticRepo(rc, repoPath, passwordFile); err != nil {
		return nil, fmt.Errorf("failed to initialize restic repository: %w", err)
	}

	// INTERVENE: Install backup script
	backupScriptPath := filepath.Join(config.BinDir, BackupScriptName)
	if err := installBackupScript(backupScriptPath, config, homeDir); err != nil {
		return nil, fmt.Errorf("failed to install backup script: %w", err)
	}
	result.ScriptsInstalled = append(result.ScriptsInstalled, backupScriptPath)
	logger.Info("Installed backup script", zap.String("path", backupScriptPath))

	// INTERVENE: Install prune script
	pruneScriptPath := filepath.Join(config.BinDir, PruneScriptName)
	if err := installPruneScript(pruneScriptPath, config, homeDir); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Failed to install prune script: %v", err))
	} else {
		result.ScriptsInstalled = append(result.ScriptsInstalled, pruneScriptPath)
		logger.Info("Installed prune script", zap.String("path", pruneScriptPath))
	}

	// INTERVENE: Install setup script
	setupScriptPath := filepath.Join(config.BinDir, SetupScriptName)
	if err := installSetupScript(setupScriptPath, config, homeDir); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Failed to install setup script: %v", err))
	} else {
		result.ScriptsInstalled = append(result.ScriptsInstalled, setupScriptPath)
		logger.Info("Installed setup script", zap.String("path", setupScriptPath))
	}

	// INTERVENE: Install export script (unchanged from tar.gz version)
	exportScriptPath := filepath.Join(config.BinDir, ExportScriptName)
	if err := installExportScript(exportScriptPath); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Failed to install export script: %v", err))
	} else {
		result.ScriptsInstalled = append(result.ScriptsInstalled, exportScriptPath)
		logger.Info("Installed export script", zap.String("path", exportScriptPath))
	}

	// INTERVENE: Configure cron (backup hourly + prune daily)
	if err := configureResticCron(rc, config, backupScriptPath, pruneScriptPath, homeDir); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Failed to configure cron: %v. Run '%s' to set up manually.", err, setupScriptPath))
	} else {
		result.CronConfigured = true
		logger.Info("Configured cron jobs",
			zap.String("backup_interval", config.CronInterval),
			zap.String("prune_interval", DefaultPruneInterval))
	}

	// Change ownership if running as root for a non-root user
	if os.Geteuid() == 0 && config.User != "" && config.User != "root" {
		chownPaths := []string{config.BinDir, resticDir}
		for _, path := range result.ScriptsInstalled {
			chownPaths = append(chownPaths, path)
		}
		for _, path := range chownPaths {
			if err := chownToUser(path, config.User); err != nil {
				logger.Warn("Failed to change ownership", zap.String("path", path), zap.Error(err))
			}
		}
	}

	// EVALUATE: Log completion and display password if new
	logger.Info("Session backup setup completed",
		zap.Int("scripts_installed", len(result.ScriptsInstalled)),
		zap.Bool("cron_configured", result.CronConfigured),
		zap.String("restic_repo", repoPath))

	if passwordGenerated {
		// Show password to user ONCE - critical for recovery
		// SECURITY: Do NOT log the password value via structured logging
		// as it may be forwarded to centralized log systems (Splunk, Datadog, etc.)
		logger.Info("IMPORTANT: Save your restic repository password!")
		logger.Info("If lost, your backups will be UNRECOVERABLE")
		logger.Info("Password saved to file",
			zap.String("path", passwordFile),
			zap.String("view_command", "cat "+passwordFile))
		logger.Info("Or run: " + setupScriptPath + " and select 'Show repository password'")
	}

	// Check for migration from old tar.gz backups
	// Only prompts if restic has N successful backups over 7+ days
	if err := promptMigration(rc, homeDir); err != nil {
		// Non-fatal - log but continue
		logger.Debug("Migration prompt failed", zap.Error(err))
	}

	return result, nil
}

// installBackupScript writes the restic backup script to disk
// Uses flock to prevent concurrent runs, writes status file for health monitoring
func installBackupScript(path string, config *SessionBackupConfig, homeDir string) error {
	repoPath := filepath.Join(homeDir, ResticRepoDir)
	passwordFile := filepath.Join(homeDir, ResticPasswordFile)
	logFile := filepath.Join(homeDir, ResticLogFile)
	statusFile := filepath.Join(homeDir, ResticStatusFile)
	lockFile := filepath.Join(homeDir, ".eos/restic/backup.lock")

	script := fmt.Sprintf(`#!/bin/bash
# Backup Claude Code and Codex sessions using restic
# Automatically generated by eos create code
# Run via cron (hourly by default) - does NOT prune (separate script)

set -euo pipefail

RESTIC_REPO="%s"
RESTIC_PASSWORD_FILE="%s"
LOG_FILE="%s"
STATUS_FILE="%s"
LOCK_FILE="%s"

mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$(dirname "$STATUS_FILE")"

log() {
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] $*" | tee -a "$LOG_FILE"
}

update_status() {
    local success="$1"
    local snapshot_id="${2:-}"
    local bytes_added="${3:-0}"

    # Read existing status
    local count=0
    local first_backup=""
    if [[ -f "$STATUS_FILE" ]]; then
        count=$(jq -r '.successful_backup_count // 0' "$STATUS_FILE" 2>/dev/null || echo "0")
        first_backup=$(jq -r '.first_backup // ""' "$STATUS_FILE" 2>/dev/null || echo "")
    fi

    local now=$(date -Iseconds)

    if [[ "$success" == "true" ]]; then
        count=$((count + 1))
        if [[ -z "$first_backup" ]]; then
            first_backup="$now"
        fi

        # Get snapshot count
        local total_snapshots=$(restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" snapshots --json 2>/dev/null | jq 'length' 2>/dev/null || echo "0")

        cat > "$STATUS_FILE" <<EOF
{
  "last_success": "$now",
  "last_snapshot_id": "$snapshot_id",
  "bytes_added": $bytes_added,
  "total_snapshots": $total_snapshots,
  "successful_backup_count": $count,
  "first_backup": "$first_backup"
}
EOF
    else
        # Update with failure
        local existing=$(cat "$STATUS_FILE" 2>/dev/null || echo '{}')
        echo "$existing" | jq --arg now "$now" '.last_failure = $now' > "$STATUS_FILE.tmp" && mv "$STATUS_FILE.tmp" "$STATUS_FILE"
    fi
}

# Use flock to prevent concurrent runs
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    log "Another backup is already running, skipping"
    exit 0
fi

# Check dependencies
if ! command -v restic &>/dev/null; then
    log "ERROR: restic not found. Install with: sudo apt install restic"
    update_status "false"
    exit 1
fi

if [[ ! -f "$RESTIC_PASSWORD_FILE" ]]; then
    log "ERROR: Password file not found at $RESTIC_PASSWORD_FILE"
    log "Run: eos create code --user $(whoami)"
    update_status "false"
    exit 1
fi

# Check repository
if ! restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" cat config &>/dev/null; then
    log "ERROR: Repository not initialized at $RESTIC_REPO"
    update_status "false"
    exit 1
fi

# Build paths to backup
BACKUP_PATHS=()
[[ -d "$HOME/.claude/projects" ]] && BACKUP_PATHS+=("$HOME/.claude/projects")
[[ -d "$HOME/.claude/todos" ]] && BACKUP_PATHS+=("$HOME/.claude/todos")
[[ -d "$HOME/.claude/file-history" ]] && BACKUP_PATHS+=("$HOME/.claude/file-history")
[[ -d "$HOME/.codex/sessions" ]] && BACKUP_PATHS+=("$HOME/.codex/sessions")

if [[ ${#BACKUP_PATHS[@]} -eq 0 ]]; then
    log "No Claude Code or Codex data found"
    exit 0
fi

log "Starting backup of ${#BACKUP_PATHS[@]} paths"

# Run backup (no prune - separate script handles that)
RESTIC_OUTPUT=$(restic -r "$RESTIC_REPO" \
    --password-file "$RESTIC_PASSWORD_FILE" \
    backup \
    --tag "coding-sessions" \
    --tag "auto" \
    --exclude ".claude/downloads" \
    --exclude ".claude/statsig" \
    --exclude ".claude/telemetry" \
    --exclude ".claude/cache" \
    --exclude "*.tmp" \
    --exclude "*.log" \
    --json \
    "${BACKUP_PATHS[@]}" 2>&1) || {
    log "ERROR: Backup failed"
    log "Output: $RESTIC_OUTPUT"
    update_status "false"
    exit 1
}

# Parse JSON output for snapshot ID and bytes added
SNAPSHOT_ID=$(echo "$RESTIC_OUTPUT" | jq -r 'select(.message_type == "summary") | .snapshot_id' 2>/dev/null | head -1 || echo "")
BYTES_ADDED=$(echo "$RESTIC_OUTPUT" | jq -r 'select(.message_type == "summary") | .data_added' 2>/dev/null | head -1 || echo "0")

if [[ -z "$SNAPSHOT_ID" ]]; then
    # Fallback: try non-JSON parsing
    SNAPSHOT_ID=$(echo "$RESTIC_OUTPUT" | grep -oP 'snapshot \K[a-f0-9]+' | head -1 || echo "unknown")
fi

log "Backup successful: snapshot $SNAPSHOT_ID (added: $BYTES_ADDED bytes)"
update_status "true" "$SNAPSHOT_ID" "${BYTES_ADDED:-0}"

log "Backup complete"
`, repoPath, passwordFile, logFile, statusFile, lockFile)

	return os.WriteFile(path, []byte(script), BackupScriptPerm)
}

// installPruneScript writes the restic prune script to disk
// Runs daily to apply retention policy (separate from backup to avoid lock contention)
// Uses same lock file as backup script to prevent concurrent runs
func installPruneScript(path string, config *SessionBackupConfig, homeDir string) error {
	repoPath := filepath.Join(homeDir, ResticRepoDir)
	passwordFile := filepath.Join(homeDir, ResticPasswordFile)
	logFile := filepath.Join(homeDir, ResticLogFile)
	lockFile := filepath.Join(homeDir, ".eos/restic/backup.lock") // Same lock as backup script

	// Get retention policy
	retention := config.RetentionPolicy
	if retention == nil {
		retention = DefaultRetentionPolicy()
	}

	script := fmt.Sprintf(`#!/bin/bash
# Apply retention policy to restic repository
# Automatically generated by eos create code
# Run via cron daily at 3am (separate from backup to avoid locks)
# Uses same lock file as backup script to prevent concurrent runs

set -euo pipefail

RESTIC_REPO="%s"
RESTIC_PASSWORD_FILE="%s"
LOG_FILE="%s"
LOCK_FILE="%s"

log() {
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] PRUNE: $*" | tee -a "$LOG_FILE"
}

# Use flock to prevent concurrent runs with backup script
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    log "Backup or prune already running, skipping"
    exit 0
fi

if [[ ! -f "$RESTIC_PASSWORD_FILE" ]]; then
    log "ERROR: Password file not found"
    exit 1
fi

if ! restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" cat config &>/dev/null; then
    log "ERROR: Repository not initialized"
    exit 1
fi

log "Starting retention policy enforcement"

# Retention policy:
# - Keep ALL snapshots within %s (fine-grained recent recovery)
# - Keep %d hourly snapshots after that
# - Keep %d daily snapshots
# - Keep %d weekly snapshots
# - Keep %d monthly snapshots

restic -r "$RESTIC_REPO" \
    --password-file "$RESTIC_PASSWORD_FILE" \
    forget \
    --tag "coding-sessions" \
    --keep-within %s \
    --keep-hourly %d \
    --keep-daily %d \
    --keep-weekly %d \
    --keep-monthly %d \
    --prune \
    2>&1 | while read -r line; do log "  $line"; done

# Show repo stats
log "Repository statistics:"
restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" stats 2>&1 | while read -r line; do log "  $line"; done

log "Prune complete"
`, repoPath, passwordFile, logFile, lockFile,
		retention.KeepWithin, retention.KeepHourly, retention.KeepDaily, retention.KeepWeekly, retention.KeepMonthly,
		retention.KeepWithin, retention.KeepHourly, retention.KeepDaily, retention.KeepWeekly, retention.KeepMonthly)

	return os.WriteFile(path, []byte(script), BackupScriptPerm)
}

// installSetupScript writes the interactive setup/management script to disk
// Includes health check, snapshot listing, restore, and password display
func installSetupScript(path string, config *SessionBackupConfig, homeDir string) error {
	repoPath := filepath.Join(homeDir, ResticRepoDir)
	passwordFile := filepath.Join(homeDir, ResticPasswordFile)
	logFile := filepath.Join(homeDir, ResticLogFile)
	statusFile := filepath.Join(homeDir, ResticStatusFile)
	backupScript := filepath.Join(homeDir, "bin", BackupScriptName)
	pruneScript := filepath.Join(homeDir, "bin", PruneScriptName)

	script := fmt.Sprintf(`#!/bin/bash
# Interactive management for coding session backups (restic-based)
# Automatically generated by eos create code

set -euo pipefail

RESTIC_REPO="%s"
RESTIC_PASSWORD_FILE="%s"
LOG_FILE="%s"
STATUS_FILE="%s"
BACKUP_SCRIPT="%s"
PRUNE_SCRIPT="%s"
CRON_BACKUP_MARKER="backup-coding-sessions.sh"
CRON_PRUNE_MARKER="prune-coding-sessions.sh"

echo "=== Coding Session Backup Manager (Restic) ==="
echo ""

# Check dependencies
if ! command -v restic &>/dev/null; then
    echo "Error: restic not installed"
    echo "Install with: sudo apt install restic"
    exit 1
fi

# Show status
echo "Status:"

# Repository status
if restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" cat config &>/dev/null 2>&1; then
    SNAPSHOTS=$(restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" snapshots --json 2>/dev/null | jq 'length' 2>/dev/null || echo "?")
    REPO_SIZE=$(restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" stats --mode raw-data 2>/dev/null | grep -oP 'Total Size:\s+\K.*' || echo "unknown")
    echo "  Repository: initialized"
    echo "  Snapshots: $SNAPSHOTS"
    echo "  Size: $REPO_SIZE"
else
    echo "  Repository: NOT initialized"
fi

# Health check from status file
if [[ -f "$STATUS_FILE" ]]; then
    LAST_SUCCESS=$(jq -r '.last_success // "never"' "$STATUS_FILE" 2>/dev/null || echo "never")
    LAST_FAILURE=$(jq -r '.last_failure // "none"' "$STATUS_FILE" 2>/dev/null || echo "none")
    SUCCESS_COUNT=$(jq -r '.successful_backup_count // 0' "$STATUS_FILE" 2>/dev/null || echo "0")

    if [[ "$LAST_SUCCESS" != "never" && "$LAST_SUCCESS" != "null" ]]; then
        LAST_EPOCH=$(date -d "$LAST_SUCCESS" +%%s 2>/dev/null || echo "0")
        NOW_EPOCH=$(date +%%s)
        HOURS_AGO=$(( (NOW_EPOCH - LAST_EPOCH) / 3600 ))
        if [[ $HOURS_AGO -gt 24 ]]; then
            echo "  Last backup: $HOURS_AGO hours ago (WARNING: stale)"
        else
            echo "  Last backup: $HOURS_AGO hours ago"
        fi
    else
        echo "  Last backup: never"
    fi

    if [[ "$LAST_FAILURE" != "none" && "$LAST_FAILURE" != "null" ]]; then
        echo "  Last failure: $LAST_FAILURE"
    fi
    echo "  Successful backups: $SUCCESS_COUNT"
else
    echo "  Status: no backups recorded yet"
fi

# Cron status
BACKUP_CRON=$(crontab -l 2>/dev/null | grep "$CRON_BACKUP_MARKER" || true)
PRUNE_CRON=$(crontab -l 2>/dev/null | grep "$CRON_PRUNE_MARKER" || true)
echo ""
echo "Cron Jobs:"
if [[ -n "$BACKUP_CRON" ]]; then
    echo "  Backup: $(echo "$BACKUP_CRON" | awk '{print $1, $2, $3, $4, $5}')"
else
    echo "  Backup: not scheduled"
fi
if [[ -n "$PRUNE_CRON" ]]; then
    echo "  Prune: $(echo "$PRUNE_CRON" | awk '{print $1, $2, $3, $4, $5}')"
else
    echo "  Prune: not scheduled"
fi

# Source data sizes
echo ""
echo "Source Data:"
echo "  Claude Code: $(du -sh "$HOME/.claude" 2>/dev/null | cut -f1 || echo "N/A")"
echo "  Codex: $(du -sh "$HOME/.codex" 2>/dev/null | cut -f1 || echo "N/A")"
echo ""

# Menu
echo "Options:"
echo "  1) Enable hourly backups + daily prune"
echo "  2) Enable 30-minute backups + daily prune"
echo "  3) Disable automatic backups"
echo "  4) Run backup now"
echo "  5) Run prune now"
echo "  6) List snapshots"
echo "  7) Restore from snapshot"
echo "  8) Check backup health"
echo "  9) Show repository password"
echo "  10) View log"
echo "  11) Exit"
echo ""
read -p "Select [1-11]: " choice

setup_cron() {
    local backup_schedule="$1"
    local desc="$2"

    # Remove existing
    crontab -l 2>/dev/null | grep -v "$CRON_BACKUP_MARKER" | grep -v "$CRON_PRUNE_MARKER" | crontab - 2>/dev/null || true

    # Add new
    (crontab -l 2>/dev/null
     echo ""
     echo "# Coding session backups ($desc)"
     echo "$backup_schedule $BACKUP_SCRIPT"
     echo "# Coding session prune (daily 3am)"
     echo "0 3 * * * $PRUNE_SCRIPT"
    ) | crontab -

    echo "Configured: $desc"
}

case "$choice" in
    1) setup_cron "0 * * * *" "hourly backup, daily prune" ;;
    2) setup_cron "*/30 * * * *" "30-min backup, daily prune" ;;
    3)
        crontab -l 2>/dev/null | grep -v "$CRON_BACKUP_MARKER" | grep -v "$CRON_PRUNE_MARKER" | crontab - 2>/dev/null || true
        echo "Automatic backups disabled"
        ;;
    4) "$BACKUP_SCRIPT" ;;
    5) "$PRUNE_SCRIPT" ;;
    6) restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" snapshots --tag coding-sessions ;;
    7)
        restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" snapshots --tag coding-sessions
        echo ""
        read -p "Snapshot ID to restore: " sid
        read -p "Target directory [~/restored-sessions]: " tgt
        tgt="${tgt:-$HOME/restored-sessions}"
        mkdir -p "$tgt"
        restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" restore "$sid" --target "$tgt"
        echo "Restored to: $tgt"
        ;;
    8)
        echo ""
        echo "=== Backup Health Check ==="
        if [[ -f "$STATUS_FILE" ]]; then
            echo "Status file: $STATUS_FILE"
            cat "$STATUS_FILE" | jq .
        else
            echo "No status file found - backups may not have run yet"
        fi
        echo ""
        echo "Repository check:"
        restic -r "$RESTIC_REPO" --password-file "$RESTIC_PASSWORD_FILE" check 2>&1 || echo "Check failed!"
        ;;
    9)
        echo ""
        echo "========================================"
        echo "  IMPORTANT: Save this password!"
        echo "  If lost, backups are UNRECOVERABLE"
        echo "========================================"
        echo ""
        echo "Password: $(cat "$RESTIC_PASSWORD_FILE")"
        echo ""
        echo "Password file: $RESTIC_PASSWORD_FILE"
        echo ""
        ;;
    10) tail -50 "$LOG_FILE" 2>/dev/null || echo "No log yet" ;;
    11) exit 0 ;;
    *) echo "Invalid option" ;;
esac
`, repoPath, passwordFile, logFile, statusFile, backupScript, pruneScript)

	return os.WriteFile(path, []byte(script), BackupScriptPerm)
}

// installExportScript writes the export-to-markdown script to disk
func installExportScript(path string) error {
	script := `#!/bin/bash
# Export Claude Code and Codex sessions to readable markdown
# Automatically generated by eos create code
# Usage: export-coding-sessions.sh [--today|--all|--session UUID]

set -euo pipefail

EXPORT_DIR="${EXPORT_DIR:-$HOME/coding-session-exports}"
MODE="${1:-today}"

mkdir -p "$EXPORT_DIR"

export_claude_session() {
    local jsonl_file="$1"
    local session_id=$(basename "$jsonl_file" .jsonl)
    local project_dir=$(basename "$(dirname "$jsonl_file")")
    local output_file="$EXPORT_DIR/claude-${project_dir}-${session_id}.md"

    if [[ -f "$output_file" ]]; then
        return  # Already exported
    fi

    echo "# Claude Code Session: $session_id" > "$output_file"
    echo "Project: $project_dir" >> "$output_file"
    echo "" >> "$output_file"

    # Extract conversation turns
    jq -r '
        select(.type == "user" or .type == "assistant") |
        "## " + (.type | ascii_upcase) + " (" + .timestamp + ")\n\n" +
        (if .message.content then
            (.message.content | if type == "array" then
                map(select(.type == "text") | .text) | join("\n")
            else
                .
            end)
        else
            "(no content)"
        end) + "\n\n---\n"
    ' "$jsonl_file" >> "$output_file" 2>/dev/null || true

    echo "Exported: $output_file"
}

export_codex_session() {
    local jsonl_file="$1"
    local filename=$(basename "$jsonl_file" .jsonl)
    local output_file="$EXPORT_DIR/codex-${filename}.md"

    if [[ -f "$output_file" ]]; then
        return
    fi

    # Get session metadata
    local cwd=$(jq -r 'select(.type == "session_meta") | .payload.cwd // "unknown"' "$jsonl_file" | head -1)
    local branch=$(jq -r 'select(.type == "session_meta") | .payload.git.branch // "unknown"' "$jsonl_file" | head -1)

    echo "# Codex Session: $filename" > "$output_file"
    echo "Working Directory: $cwd" >> "$output_file"
    echo "Branch: $branch" >> "$output_file"
    echo "" >> "$output_file"

    # Extract messages
    jq -r '
        select(.type == "message") |
        "## " + (.payload.role | ascii_upcase) + " (" + .timestamp + ")\n\n" +
        (if .payload.content then
            (.payload.content | if type == "array" then
                map(select(.type == "text" or .type == "output_text") | (.text // .output_text // "")) | join("\n")
            elif type == "string" then
                .
            else
                "(structured content)"
            end)
        else
            "(no content)"
        end) + "\n\n---\n"
    ' "$jsonl_file" >> "$output_file" 2>/dev/null || true

    echo "Exported: $output_file"
}

case "$MODE" in
    --today)
        TODAY=$(date +%Y/%m/%d)
        # Claude - find today's modified sessions
        find "$HOME/.claude/projects" -name "*.jsonl" -mtime 0 2>/dev/null | while read -r f; do
            export_claude_session "$f"
        done

        # Codex - today's directory
        if [[ -d "$HOME/.codex/sessions/$TODAY" ]]; then
            find "$HOME/.codex/sessions/$TODAY" -name "*.jsonl" | while read -r f; do
                export_codex_session "$f"
            done
        fi
        ;;

    --all)
        find "$HOME/.claude/projects" -name "*.jsonl" 2>/dev/null | while read -r f; do
            export_claude_session "$f"
        done

        find "$HOME/.codex/sessions" -name "*.jsonl" 2>/dev/null | while read -r f; do
            export_codex_session "$f"
        done
        ;;

    --session)
        UUID="${2:-}"
        if [[ -z "$UUID" ]]; then
            echo "Usage: $0 --session UUID"
            exit 1
        fi
        # Find matching session
        find "$HOME/.claude/projects" "$HOME/.codex/sessions" -name "*${UUID}*" 2>/dev/null | while read -r f; do
            if [[ "$f" == *".claude"* ]]; then
                export_claude_session "$f"
            else
                export_codex_session "$f"
            fi
        done
        ;;

    *)
        echo "Usage: $0 [--today|--all|--session UUID]"
        exit 1
        ;;
esac

echo "Exports saved to: $EXPORT_DIR"
`

	if err := os.WriteFile(path, []byte(script), BackupScriptPerm); err != nil {
		return err
	}
	return nil
}

// configureResticCron sets up cron jobs for backup (hourly) and prune (daily)
// Separate jobs avoid lock contention
func configureResticCron(rc *eos_io.RuntimeContext, config *SessionBackupConfig, backupScriptPath, pruneScriptPath, homeDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if cron is available
	if _, err := exec.LookPath("crontab"); err != nil {
		return fmt.Errorf("crontab not found: %w", err)
	}

	// Get current crontab
	var existingCron string
	cmd := exec.Command("crontab", "-l")
	if config.User != "" && config.User != "root" && os.Geteuid() == 0 {
		cmd = exec.Command("crontab", "-u", config.User, "-l")
	}
	if output, err := cmd.Output(); err == nil {
		existingCron = string(output)
	}

	// Check if already configured (idempotent)
	backupMarker := BackupScriptName
	pruneMarker := PruneScriptName
	if strings.Contains(existingCron, backupMarker) && strings.Contains(existingCron, pruneMarker) {
		logger.Info("Cron jobs already configured, skipping")
		return nil
	}

	// Remove any existing entries for our scripts (to allow reconfiguration)
	lines := strings.Split(existingCron, "\n")
	var cleanedLines []string
	skipNext := false
	for _, line := range lines {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.Contains(line, "Coding session backups") || strings.Contains(line, "Coding session prune") {
			skipNext = true // Skip the comment and the following cron line
			continue
		}
		if strings.Contains(line, backupMarker) || strings.Contains(line, pruneMarker) {
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}
	existingCron = strings.Join(cleanedLines, "\n")

	// Add new cron entries
	cronEntries := fmt.Sprintf(`
# Coding session backups (added by eos create code)
%s %s
# Coding session prune (daily at 3am)
%s %s
`, config.CronInterval, backupScriptPath, DefaultPruneInterval, pruneScriptPath)

	newCron := strings.TrimRight(existingCron, "\n") + cronEntries

	// Install new crontab
	installCmd := exec.Command("crontab", "-")
	if config.User != "" && config.User != "root" && os.Geteuid() == 0 {
		installCmd = exec.Command("crontab", "-u", config.User, "-")
	}
	installCmd.Stdin = strings.NewReader(newCron)

	if output, err := installCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install crontab: %w (output: %s)", err, string(output))
	}

	logger.Info("Installed cron jobs for session backups",
		zap.String("backup_schedule", config.CronInterval),
		zap.String("prune_schedule", DefaultPruneInterval))

	return nil
}

// configureCron sets up the cron job for backups (legacy, kept for compatibility)
func configureCron(rc *eos_io.RuntimeContext, config *SessionBackupConfig, backupScriptPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if cron is available
	if _, err := exec.LookPath("crontab"); err != nil {
		return fmt.Errorf("crontab not found: %w", err)
	}

	// Get current crontab
	var existingCron string
	cmd := exec.Command("crontab", "-l")
	if config.User != "" && config.User != "root" && os.Geteuid() == 0 {
		cmd = exec.Command("crontab", "-u", config.User, "-l")
	}
	if output, err := cmd.Output(); err == nil {
		existingCron = string(output)
	}

	// Check if already configured (idempotent)
	cronMarker := BackupScriptName
	if strings.Contains(existingCron, cronMarker) {
		logger.Info("Cron job already configured, skipping")
		return nil
	}

	// Add new cron entry
	logFile := filepath.Join(config.BackupDir, "backup.log")
	cronEntry := fmt.Sprintf("\n# Coding session backups (added by eos create code)\n%s %s >> %s 2>&1\n",
		config.CronInterval, backupScriptPath, logFile)

	newCron := existingCron + cronEntry

	// Install new crontab
	installCmd := exec.Command("crontab", "-")
	if config.User != "" && config.User != "root" && os.Geteuid() == 0 {
		installCmd = exec.Command("crontab", "-u", config.User, "-")
	}
	installCmd.Stdin = strings.NewReader(newCron)

	if output, err := installCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install crontab: %w (output: %s)", err, string(output))
	}

	logger.Info("Installed cron job for session backups",
		zap.String("schedule", config.CronInterval),
		zap.String("script", backupScriptPath))

	return nil
}

// getHomeDir returns the home directory for a user
func getHomeDir(username string) (string, error) {
	if username == "" || username == "root" {
		return "/root", nil
	}

	homeDir := filepath.Join("/home", username)
	if _, err := os.Stat(homeDir); err != nil {
		// Try to get from environment
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser == username {
			if sudoHome := os.Getenv("HOME"); sudoHome != "" && sudoHome != "/root" {
				return sudoHome, nil
			}
		}
		return "", fmt.Errorf("home directory not found for user %s", username)
	}

	return homeDir, nil
}

// chownToUser changes ownership of a path to a user
func chownToUser(path, username string) error {
	cmd := exec.Command("chown", "-R", username+":"+username, path)
	return cmd.Run()
}

// CheckSessionBackupInstalled checks if session backups are already set up
func CheckSessionBackupInstalled(username string) (bool, error) {
	homeDir, err := getHomeDir(username)
	if err != nil {
		return false, err
	}

	backupScript := filepath.Join(homeDir, "bin", BackupScriptName)
	if _, err := os.Stat(backupScript); err != nil {
		return false, nil
	}

	return true, nil
}

// PromptSessionBackupSetup asks the user if they want to set up session backups
func PromptSessionBackupSetup(rc *eos_io.RuntimeContext, config *Config) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if already installed
	installed, err := CheckSessionBackupInstalled(config.User)
	if err != nil {
		logger.Warn("Could not check session backup status", zap.Error(err))
	}
	if installed {
		logger.Info("Session backup already installed, skipping prompt")
		return false, nil
	}

	// Check if any coding data exists
	homeDir, _ := getHomeDir(config.User)
	claudeExists := false
	codexExists := false

	if homeDir != "" {
		if _, err := os.Stat(filepath.Join(homeDir, ".claude")); err == nil {
			claudeExists = true
		}
		if _, err := os.Stat(filepath.Join(homeDir, ".codex")); err == nil {
			codexExists = true
		}
	}

	if !claudeExists && !codexExists {
		logger.Info("No Claude Code or Codex data found, skipping backup setup prompt")
		return false, nil
	}

	// Prompt user (default No for safety - user must opt-in)
	proceed, err := interaction.PromptYesNoSafe(rc,
		"Set up automatic hourly backups of your Claude Code and Codex sessions? "+
			"(This preserves conversation history for auditing/reference)", false)
	if err != nil {
		return false, fmt.Errorf("failed to get user input: %w", err)
	}

	return proceed, nil
}

// FormatSessionBackupResult formats the session backup result for display
func FormatSessionBackupResult(result *SessionBackupResult) string {
	var sb strings.Builder

	sb.WriteString("\nSession Backup Setup (Restic)\n")
	sb.WriteString(strings.Repeat("-", 35) + "\n")

	if len(result.ScriptsInstalled) > 0 {
		sb.WriteString("Scripts installed:\n")
		for _, script := range result.ScriptsInstalled {
			sb.WriteString(fmt.Sprintf("  %s\n", script))
		}
	}

	if result.CronConfigured {
		sb.WriteString(fmt.Sprintf("Backup schedule: %s\n", result.CronInterval))
		sb.WriteString(fmt.Sprintf("Prune schedule: %s (daily)\n", DefaultPruneInterval))
	}

	if result.UseRestic {
		sb.WriteString(fmt.Sprintf("Restic repository: %s\n", result.ResticRepoPath))
		sb.WriteString(fmt.Sprintf("Password file: %s\n", result.ResticPasswordFile))
	} else {
		sb.WriteString(fmt.Sprintf("Backup directory: %s\n", result.BackupDir))
	}

	sb.WriteString("\nData sources:\n")
	if result.ClaudeDataFound {
		sb.WriteString("  Claude Code (~/.claude): found\n")
	} else {
		sb.WriteString("  Claude Code (~/.claude): not found\n")
	}
	if result.CodexDataFound {
		sb.WriteString("  Codex (~/.codex): found\n")
	} else {
		sb.WriteString("  Codex (~/.codex): not found\n")
	}

	// Show password if newly generated (critical for recovery)
	if result.ResticPassword != "" {
		sb.WriteString("\n")
		sb.WriteString("========================================\n")
		sb.WriteString("  IMPORTANT: Save this password!\n")
		sb.WriteString("  If lost, backups are UNRECOVERABLE\n")
		sb.WriteString("========================================\n")
		sb.WriteString(fmt.Sprintf("Password: %s\n", result.ResticPassword))
		sb.WriteString(fmt.Sprintf("File: %s\n", result.ResticPasswordFile))
		sb.WriteString("========================================\n")
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("\nNotes:\n")
		for _, warning := range result.Warnings {
			sb.WriteString(fmt.Sprintf("  ! %s\n", warning))
		}
	}

	sb.WriteString("\nCommands:\n")
	sb.WriteString("  Manage backups:  ~/bin/setup-coding-session-backups.sh\n")
	sb.WriteString("  Export to MD:    ~/bin/export-coding-sessions.sh --today\n")
	sb.WriteString("  List snapshots:  restic -r ~/.eos/restic/coding-sessions snapshots\n")
	sb.WriteString("  Show password:   cat ~/.eos/restic/password\n")

	return sb.String()
}
