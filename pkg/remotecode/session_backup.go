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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

	// DefaultBackupInterval is the default cron interval (hourly)
	DefaultBackupInterval = "0 * * * *"

	// BackupScriptPerm is the permission for backup scripts
	BackupScriptPerm = 0755
)

// SessionBackupConfig holds configuration for session backup setup
type SessionBackupConfig struct {
	// User is the user to set up backups for
	User string

	// BackupDir is the directory to store backups
	BackupDir string

	// BinDir is the directory to install scripts
	BinDir string

	// CronInterval is the cron schedule (e.g., "0 * * * *" for hourly)
	CronInterval string

	// DryRun shows what would be done without making changes
	DryRun bool
}

// SessionBackupResult holds the result of session backup setup
type SessionBackupResult struct {
	// ScriptsInstalled lists the scripts that were installed
	ScriptsInstalled []string

	// CronConfigured indicates if cron was set up
	CronConfigured bool

	// CronInterval is the interval configured
	CronInterval string

	// BackupDir is the backup directory
	BackupDir string

	// ClaudeDataFound indicates if Claude Code data was found
	ClaudeDataFound bool

	// CodexDataFound indicates if Codex data was found
	CodexDataFound bool

	// Warnings contains any non-fatal issues
	Warnings []string
}

// SetupSessionBackups installs backup scripts and configures cron
// ASSESS: Check for existing installation, find Claude/Codex data
// INTERVENE: Install scripts, configure cron
// EVALUATE: Verify installation
func SetupSessionBackups(rc *eos_io.RuntimeContext, config *SessionBackupConfig) (*SessionBackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up coding session backups",
		zap.String("user", config.User),
		zap.String("backup_dir", config.BackupDir),
		zap.Bool("dry_run", config.DryRun))

	result := &SessionBackupResult{
		ScriptsInstalled: []string{},
		Warnings:         []string{},
		BackupDir:        config.BackupDir,
	}

	// Get home directory
	homeDir, err := getHomeDir(config.User)
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	// Set defaults
	if config.BackupDir == "" {
		config.BackupDir = filepath.Join(homeDir, "coding-session-backups")
	}
	result.BackupDir = config.BackupDir

	if config.BinDir == "" {
		config.BinDir = filepath.Join(homeDir, "bin")
	}

	if config.CronInterval == "" {
		config.CronInterval = DefaultBackupInterval
	}
	result.CronInterval = config.CronInterval

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

	if config.DryRun {
		logger.Info("DRY RUN: Would install backup scripts and configure cron",
			zap.String("bin_dir", config.BinDir),
			zap.String("backup_dir", config.BackupDir),
			zap.String("cron_interval", config.CronInterval))
		result.ScriptsInstalled = []string{
			BackupScriptName + " (would install)",
			SetupScriptName + " (would install)",
			ExportScriptName + " (would install)",
		}
		result.CronConfigured = false
		return result, nil
	}

	// INTERVENE: Create directories
	if err := os.MkdirAll(config.BinDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bin directory %s: %w", config.BinDir, err)
	}

	if err := os.MkdirAll(config.BackupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory %s: %w", config.BackupDir, err)
	}

	// INTERVENE: Install backup script
	backupScriptPath := filepath.Join(config.BinDir, BackupScriptName)
	if err := installBackupScript(backupScriptPath, config.BackupDir); err != nil {
		return nil, fmt.Errorf("failed to install backup script: %w", err)
	}
	result.ScriptsInstalled = append(result.ScriptsInstalled, backupScriptPath)
	logger.Info("Installed backup script", zap.String("path", backupScriptPath))

	// INTERVENE: Install setup script
	setupScriptPath := filepath.Join(config.BinDir, SetupScriptName)
	if err := installSetupScript(setupScriptPath, backupScriptPath, config.BackupDir); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Failed to install setup script: %v", err))
	} else {
		result.ScriptsInstalled = append(result.ScriptsInstalled, setupScriptPath)
		logger.Info("Installed setup script", zap.String("path", setupScriptPath))
	}

	// INTERVENE: Install export script
	exportScriptPath := filepath.Join(config.BinDir, ExportScriptName)
	if err := installExportScript(exportScriptPath); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Failed to install export script: %v", err))
	} else {
		result.ScriptsInstalled = append(result.ScriptsInstalled, exportScriptPath)
		logger.Info("Installed export script", zap.String("path", exportScriptPath))
	}

	// INTERVENE: Configure cron
	if err := configureCron(rc, config, backupScriptPath); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Failed to configure cron: %v. Run '%s' to set up manually.", err, setupScriptPath))
	} else {
		result.CronConfigured = true
		logger.Info("Configured cron job", zap.String("interval", config.CronInterval))
	}

	// Change ownership if running as root for a non-root user
	if os.Geteuid() == 0 && config.User != "" && config.User != "root" {
		chownPaths := []string{config.BinDir, config.BackupDir}
		for _, path := range result.ScriptsInstalled {
			chownPaths = append(chownPaths, path)
		}
		for _, path := range chownPaths {
			if err := chownToUser(path, config.User); err != nil {
				logger.Warn("Failed to change ownership", zap.String("path", path), zap.Error(err))
			}
		}
	}

	logger.Info("Session backup setup completed",
		zap.Int("scripts_installed", len(result.ScriptsInstalled)),
		zap.Bool("cron_configured", result.CronConfigured))

	return result, nil
}

// installBackupScript writes the backup script to disk
func installBackupScript(path, backupDir string) error {
	script := fmt.Sprintf(`#!/bin/bash
# Backup Claude Code and Codex conversation sessions
# Automatically generated by eos create code
# Run via cron every hour (or as configured)

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-%s}"
TIMESTAMP=$(date +%%Y-%%m-%%d_%%H-%%M)
DATE_DIR=$(date +%%Y/%%m/%%d)

# Create backup directory structure
mkdir -p "$BACKUP_DIR/$DATE_DIR"

# Backup Claude Code sessions
if [[ -d "$HOME/.claude" ]]; then
    CLAUDE_BACKUP="$BACKUP_DIR/$DATE_DIR/claude-$TIMESTAMP.tar.gz"
    tar -czf "$CLAUDE_BACKUP" \
        -C "$HOME" \
        --exclude='.claude/downloads' \
        --exclude='.claude/statsig' \
        --exclude='.claude/telemetry' \
        .claude/projects \
        .claude/todos \
        .claude/file-history \
        2>/dev/null || true

    if [[ -f "$CLAUDE_BACKUP" ]]; then
        SIZE=$(du -h "$CLAUDE_BACKUP" | cut -f1)
        echo "[$(date)] Claude Code backup: $CLAUDE_BACKUP ($SIZE)"
    fi
fi

# Backup Codex sessions
if [[ -d "$HOME/.codex/sessions" ]]; then
    CODEX_BACKUP="$BACKUP_DIR/$DATE_DIR/codex-$TIMESTAMP.tar.gz"
    tar -czf "$CODEX_BACKUP" \
        -C "$HOME" \
        .codex/sessions \
        2>/dev/null || true

    if [[ -f "$CODEX_BACKUP" ]]; then
        SIZE=$(du -h "$CODEX_BACKUP" | cut -f1)
        echo "[$(date)] Codex backup: $CODEX_BACKUP ($SIZE)"
    fi
fi

# Deduplicate: remove backups identical to previous (within same day)
for tool in claude codex; do
    LATEST=$(ls -t "$BACKUP_DIR/$DATE_DIR/$tool-"*.tar.gz 2>/dev/null | head -1)
    PREVIOUS=$(ls -t "$BACKUP_DIR/$DATE_DIR/$tool-"*.tar.gz 2>/dev/null | head -2 | tail -1)

    if [[ -n "$LATEST" && -n "$PREVIOUS" && "$LATEST" != "$PREVIOUS" ]]; then
        if cmp -s "$LATEST" "$PREVIOUS" 2>/dev/null; then
            rm "$LATEST"
            echo "[$(date)] Removed duplicate: $LATEST (identical to previous)"
        fi
    fi
done

echo "[$(date)] Backup complete"
`, backupDir)

	if err := os.WriteFile(path, []byte(script), BackupScriptPerm); err != nil {
		return err
	}
	return nil
}

// installSetupScript writes the interactive setup script to disk
func installSetupScript(path, backupScriptPath, backupDir string) error {
	script := fmt.Sprintf(`#!/bin/bash
# Interactive setup for coding session backups
# Automatically generated by eos create code

set -euo pipefail

BACKUP_SCRIPT="%s"
BACKUP_DIR="%s"
CRON_MARKER="backup-coding-sessions.sh"

echo "=== Coding Session Backup Setup ==="
echo ""

# Check if backup script exists
if [[ ! -x "$BACKUP_SCRIPT" ]]; then
    echo "Error: Backup script not found at $BACKUP_SCRIPT"
    echo "Please run 'eos create code' to install it."
    exit 1
fi

# Show current status
echo "Current Status:"
echo ""

# Check for existing cron job
EXISTING_CRON=$(crontab -l 2>/dev/null | grep "$CRON_MARKER" || true)
if [[ -n "$EXISTING_CRON" ]]; then
    echo "  Cron job: Active"
    echo "  Schedule: $(echo "$EXISTING_CRON" | awk '{print $1, $2, $3, $4, $5}')"
else
    echo "  Cron job: Not configured"
fi

# Check backup directory
if [[ -d "$BACKUP_DIR" ]]; then
    BACKUP_COUNT=$(find "$BACKUP_DIR" -name "*.tar.gz" 2>/dev/null | wc -l)
    BACKUP_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
    echo "  Backup dir: $BACKUP_DIR"
    echo "  Backups: $BACKUP_COUNT files ($BACKUP_SIZE)"
else
    echo "  Backup dir: Not created yet"
fi

# Check source data
CLAUDE_SIZE=$(du -sh "$HOME/.claude" 2>/dev/null | cut -f1 || echo "N/A")
CODEX_SIZE=$(du -sh "$HOME/.codex" 2>/dev/null | cut -f1 || echo "N/A")
echo ""
echo "Source Data:"
echo "  Claude Code (~/.claude): $CLAUDE_SIZE"
echo "  Codex (~/.codex): $CODEX_SIZE"
echo ""

# Menu
echo "Options:"
echo "  1) Enable backups every 30 minutes"
echo "  2) Enable backups every hour"
echo "  3) Enable backups every 6 hours"
echo "  4) Enable daily backups (midnight)"
echo "  5) Disable automatic backups"
echo "  6) Run backup now"
echo "  7) View backup log"
echo "  8) Exit"
echo ""

read -p "Select option [1-8]: " choice

remove_existing_cron() {
    crontab -l 2>/dev/null | grep -v "$CRON_MARKER" | crontab - 2>/dev/null || true
}

add_cron_job() {
    local schedule="$1"
    local description="$2"
    remove_existing_cron
    (crontab -l 2>/dev/null; echo ""; echo "# Coding session backups ($description)"; echo "$schedule $BACKUP_SCRIPT >> $BACKUP_DIR/backup.log 2>&1") | crontab -
    echo "Cron job configured: $description"
}

case "$choice" in
    1) add_cron_job "*/30 * * * *" "every 30 minutes" ;;
    2) add_cron_job "0 * * * *" "every hour" ;;
    3) add_cron_job "0 */6 * * *" "every 6 hours" ;;
    4) add_cron_job "0 0 * * *" "daily at midnight" ;;
    5) remove_existing_cron; echo "Automatic backups disabled" ;;
    6) echo "Running backup..."; "$BACKUP_SCRIPT" ;;
    7) if [[ -f "$BACKUP_DIR/backup.log" ]]; then echo "Last 20 log entries:"; tail -20 "$BACKUP_DIR/backup.log"; else echo "No backup log found yet."; fi ;;
    8) echo "Exiting."; exit 0 ;;
    *) echo "Invalid option"; exit 1 ;;
esac

echo ""
echo "Current cron jobs:"
crontab -l 2>/dev/null | grep -A1 "$CRON_MARKER" || echo "  (none)"
`, backupScriptPath, backupDir)

	if err := os.WriteFile(path, []byte(script), BackupScriptPerm); err != nil {
		return err
	}
	return nil
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

// configureCron sets up the cron job for backups
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

	sb.WriteString("\nSession Backup Setup\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")

	if len(result.ScriptsInstalled) > 0 {
		sb.WriteString("Scripts installed:\n")
		for _, script := range result.ScriptsInstalled {
			sb.WriteString(fmt.Sprintf("  %s\n", script))
		}
	}

	if result.CronConfigured {
		sb.WriteString(fmt.Sprintf("Cron schedule: %s\n", result.CronInterval))
	}

	sb.WriteString(fmt.Sprintf("Backup directory: %s\n", result.BackupDir))

	if result.ClaudeDataFound {
		sb.WriteString("  Claude Code data: found\n")
	}
	if result.CodexDataFound {
		sb.WriteString("  Codex data: found\n")
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("\nNotes:\n")
		for _, warning := range result.Warnings {
			sb.WriteString(fmt.Sprintf("  ! %s\n", warning))
		}
	}

	sb.WriteString("\nTo manage backups interactively:\n")
	sb.WriteString("  ~/bin/setup-coding-session-backups.sh\n")
	sb.WriteString("\nTo export sessions to Markdown:\n")
	sb.WriteString("  ~/bin/export-coding-sessions.sh --today\n")

	return sb.String()
}
