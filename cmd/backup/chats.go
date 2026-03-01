// cmd/backup/chats.go
// Command orchestration for machine-wide AI chat archive backup
//
// Provides: eos backup chats [--setup|--prune|--list|--dry-run]
//
// This command backs up conversations, settings, and context files from
// all AI coding tools (Claude Code, Codex, VS Code, Windsurf, Cursor,
// Continue, Amazon Q, Aider) plus project-level CLAUDE.md/AGENTS.md files.

package backup

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/chatbackup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var chatsCmd = &cobra.Command{
	Use:   "chats",
	Short: "Back up AI coding tool conversations, settings, and context",
	Long: `Machine-wide backup of all AI coding assistant data using restic.

Backs up conversations, settings, memory files, and project context from:
  - Claude Code (~/.claude): sessions, settings, MEMORY.md, todos, plans
  - OpenAI Codex (~/.codex): sessions, config, skills
  - VS Code (~/.config/Code): Cline, Roo Code, Copilot chat history
  - Windsurf (~/.config/Windsurf): global storage, settings
  - Cursor (~/.config/Cursor): state database, settings
  - Continue (~/.continue): sessions, config
  - Amazon Q (~/.aws/amazonq): chat history
  - Aider (~/.aider.*): chat history
  - Project context: CLAUDE.md, AGENTS.md, .claude/ dirs in /opt/

Features:
  - Hourly deduplication via restic (block-level)
  - AES-256 encryption at rest
  - Retention policy (48h all, 24 hourly, 7 daily, 4 weekly, 12 monthly)
  - Scheduled via cron (--setup)

Examples:
  # First-time setup (creates repo, password, cron job)
  sudo eos backup chats --setup

  # Run a backup now
  eos backup chats

  # Preview what would be backed up
  eos backup chats --dry-run

  # Apply retention policy (prune old snapshots)
  eos backup chats --prune

  # List existing snapshots
  eos backup chats --list

  # Backup for a specific user
  sudo eos backup chats --user henry`,

	RunE: eos.Wrap(runBackupChats),
}

func init() {
	BackupCmd.AddCommand(chatsCmd)

	chatsCmd.Flags().Bool("setup", false, "Initialize restic repository, generate password, and configure hourly cron")
	chatsCmd.Flags().Bool("prune", false, "Apply retention policy to remove old snapshots")
	chatsCmd.Flags().Bool("list", false, "List existing snapshots")
	chatsCmd.Flags().Bool("dry-run", false, "Show what would be backed up without making changes")
	chatsCmd.Flags().String("user", "", "User whose data to back up (defaults to current user or SUDO_USER)")
	chatsCmd.Flags().StringSlice("scan-dirs", []string{"/opt"}, "Additional directories to scan for project-level AI context files")
	chatsCmd.Flags().Bool("verbose", false, "Show detailed path discovery logging")

	// Retention flags (for --setup and --prune)
	chatsCmd.Flags().String("keep-within", chatbackup.DefaultKeepWithin, "Keep all snapshots within this duration")
	chatsCmd.Flags().Int("keep-hourly", chatbackup.DefaultKeepHourly, "Hourly snapshots to keep after keep-within")
	chatsCmd.Flags().Int("keep-daily", chatbackup.DefaultKeepDaily, "Daily snapshots to keep")
	chatsCmd.Flags().Int("keep-weekly", chatbackup.DefaultKeepWeekly, "Weekly snapshots to keep")
	chatsCmd.Flags().Int("keep-monthly", chatbackup.DefaultKeepMonthly, "Monthly snapshots to keep")

	// Schedule flags (for --setup)
	chatsCmd.Flags().String("backup-cron", chatbackup.DefaultBackupCron, "Cron schedule for backups")
	chatsCmd.Flags().String("prune-cron", chatbackup.DefaultPruneCron, "Cron schedule for pruning")
}

func runBackupChats(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}

	// Parse user flag with fallback to SUDO_USER
	username, _ := cmd.Flags().GetString("user")
	if username == "" {
		username = resolveCurrentUser()
	}

	// Parse retention policy
	retention := chatbackup.DefaultRetentionPolicy()
	if cmd.Flags().Changed("keep-within") {
		retention.KeepWithin, _ = cmd.Flags().GetString("keep-within")
	}
	if cmd.Flags().Changed("keep-hourly") {
		retention.KeepHourly, _ = cmd.Flags().GetInt("keep-hourly")
	}
	if cmd.Flags().Changed("keep-daily") {
		retention.KeepDaily, _ = cmd.Flags().GetInt("keep-daily")
	}
	if cmd.Flags().Changed("keep-weekly") {
		retention.KeepWeekly, _ = cmd.Flags().GetInt("keep-weekly")
	}
	if cmd.Flags().Changed("keep-monthly") {
		retention.KeepMonthly, _ = cmd.Flags().GetInt("keep-monthly")
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	verbose, _ := cmd.Flags().GetBool("verbose")
	scanDirs, _ := cmd.Flags().GetStringSlice("scan-dirs")

	// Route to the appropriate operation
	doSetup, _ := cmd.Flags().GetBool("setup")
	doPrune, _ := cmd.Flags().GetBool("prune")
	doList, _ := cmd.Flags().GetBool("list")

	switch {
	case doSetup:
		return runSetup(rc, logger, cmd, username, retention, dryRun)
	case doPrune:
		return runPrune(rc, logger, username, retention, dryRun)
	case doList:
		return runList(rc, logger, username)
	default:
		return runBackup(rc, logger, username, retention, scanDirs, dryRun, verbose)
	}
}

func runSetup(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, cmd *cobra.Command, username string, retention chatbackup.RetentionPolicy, dryRun bool) error {
	backupCron, _ := cmd.Flags().GetString("backup-cron")
	pruneCron, _ := cmd.Flags().GetString("prune-cron")

	config := chatbackup.ScheduleConfig{
		BackupConfig: chatbackup.BackupConfig{
			User:      username,
			Retention: retention,
			DryRun:    dryRun,
		},
		BackupCron: backupCron,
		PruneCron:  pruneCron,
	}

	result, err := chatbackup.Setup(rc, config)
	if err != nil {
		return fmt.Errorf("chat archive setup failed: %w", err)
	}

	// Display results
	logger.Info("Chat archive setup complete",
		zap.Bool("cron_configured", result.CronConfigured),
		zap.Bool("password_generated", result.PasswordGenerated),
		zap.String("repo", result.RepoPath),
		zap.String("password_file", result.PasswordFile),
		zap.String("backup_cron", result.BackupCron),
		zap.String("prune_cron", result.PruneCron))

	if result.PasswordGenerated {
		logger.Info("IMPORTANT: Save your restic password! View with: cat " + result.PasswordFile)
	}

	for _, w := range result.Warnings {
		logger.Warn("Setup warning", zap.String("warning", w))
	}

	return nil
}

func runPrune(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, username string, retention chatbackup.RetentionPolicy, dryRun bool) error {
	config := chatbackup.BackupConfig{
		User:      username,
		Retention: retention,
		DryRun:    dryRun,
	}

	if err := chatbackup.RunPrune(rc, config); err != nil {
		return fmt.Errorf("chat archive prune failed: %w", err)
	}

	logger.Info("Chat archive prune completed")
	return nil
}

func runList(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, username string) error {
	homeDir, err := resolveHomeDirForUser(username)
	if err != nil {
		return err
	}

	repoPath := filepath.Join(homeDir, chatbackup.ResticRepoSubdir)
	passwordFile := filepath.Join(homeDir, chatbackup.ResticPasswordSubdir)

	logger.Info("Listing chat archive snapshots",
		zap.String("repo", repoPath))

	cmd := exec.CommandContext(rc.Ctx, "restic",
		"-r", repoPath,
		"--password-file", passwordFile,
		"snapshots",
		"--tag", chatbackup.BackupTag)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to list snapshots: %w\n"+
			"Run 'eos backup chats --setup' if not yet initialized", err)
	}

	return nil
}

func runBackup(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, username string, retention chatbackup.RetentionPolicy, scanDirs []string, dryRun, verbose bool) error {
	config := chatbackup.BackupConfig{
		User:          username,
		ExtraScanDirs: scanDirs,
		Retention:     retention,
		DryRun:        dryRun,
		Verbose:       verbose,
	}

	result, err := chatbackup.RunBackup(rc, config)
	if err != nil {
		return fmt.Errorf("chat archive backup failed: %w", err)
	}

	// Display results
	if result.SnapshotID != "" {
		logger.Info("Chat archive backup completed",
			zap.String("snapshot_id", result.SnapshotID),
			zap.Strings("tools_found", result.ToolsFound),
			zap.Int("files_new", result.FilesNew),
			zap.Int("files_changed", result.FilesChanged),
			zap.Int("files_unmodified", result.FilesUnmodified),
			zap.Int64("bytes_added", result.BytesAdded),
			zap.String("duration", result.TotalDuration),
			zap.Int("paths_backed_up", len(result.PathsBackedUp)),
			zap.Int("paths_skipped", len(result.PathsSkipped)))
	} else if dryRun {
		logger.Info("DRY RUN complete",
			zap.Strings("tools_found", result.ToolsFound),
			zap.Int("paths_would_backup", len(result.PathsBackedUp)),
			zap.Int("paths_not_found", len(result.PathsSkipped)))
	} else {
		logger.Info("No AI tool data found to back up")
	}

	return nil
}

// resolveCurrentUser determines the effective user for backup.
// When running via sudo, falls back to SUDO_USER.
func resolveCurrentUser() string {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		return sudoUser
	}

	u, err := user.Current()
	if err != nil {
		return ""
	}

	return u.Username
}

// resolveHomeDirForUser resolves a user's home directory.
func resolveHomeDirForUser(username string) (string, error) {
	if username == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not determine current user home directory: %w", err)
		}
		return homeDir, nil
	}

	if username == "root" {
		return "/root", nil
	}

	homeDir := filepath.Join("/home", username)
	if _, err := os.Stat(homeDir); err != nil {
		return "", fmt.Errorf("home directory not found for user %s", username)
	}

	return homeDir, nil
}

// FormatResult formats a backup result for display.
func FormatResult(result *chatbackup.BackupResult) string {
	var sb strings.Builder

	sb.WriteString("\nChat Archive Backup Results\n")
	sb.WriteString(strings.Repeat("-", 35) + "\n")

	if result.SnapshotID != "" {
		sb.WriteString(fmt.Sprintf("Snapshot: %s\n", result.SnapshotID))
		sb.WriteString(fmt.Sprintf("Duration: %s\n", result.TotalDuration))
		sb.WriteString(fmt.Sprintf("Files: %d new, %d changed, %d unmodified\n",
			result.FilesNew, result.FilesChanged, result.FilesUnmodified))
		sb.WriteString(fmt.Sprintf("Data added: %d bytes\n", result.BytesAdded))
	}

	if len(result.ToolsFound) > 0 {
		sb.WriteString(fmt.Sprintf("Tools: %s\n", strings.Join(result.ToolsFound, ", ")))
	}

	return sb.String()
}
