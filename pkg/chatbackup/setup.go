// pkg/chatbackup/setup.go
// Setup and scheduling for automated chat backups
//
// Follows Assess → Intervene → Evaluate pattern:
//   ASSESS:     Check restic, check existing setup, check dependencies
//   INTERVENE:  Init repo, generate password, configure cron
//   EVALUATE:   Verify setup, report results
//
// RATIONALE: Extracted from the 1,605-line session_backup.go monolith.
// This focuses solely on setup/scheduling, separate from backup execution.

package chatbackup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Setup initializes the chat archive infrastructure: restic repo, password, and cron.
//
// ASSESS: Check restic installed, check if already set up
// INTERVENE: Create repo, generate password, configure cron
// EVALUATE: Verify and report
func Setup(rc *eos_io.RuntimeContext, config ScheduleConfig) (*ScheduleResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	result := &ScheduleResult{
		Warnings: []string{},
	}

	// ASSESS: Resolve home directory
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = resolveHomeDir(config.User)
		if err != nil {
			return nil, &opError{Op: "resolve home directory", Err: err}
		}
	}

	repoPath := filepath.Join(homeDir, ResticRepoSubdir)
	passwordFile := filepath.Join(homeDir, ResticPasswordSubdir)
	resticDir := filepath.Dir(repoPath)

	result.RepoPath = repoPath
	result.PasswordFile = passwordFile
	result.BackupCron = config.BackupCron
	result.PruneCron = config.PruneCron

	logger.Info("Setting up chat archive backup",
		zap.String("user", config.User),
		zap.String("repo", repoPath),
		zap.String("backup_cron", config.BackupCron),
		zap.String("prune_cron", config.PruneCron),
		zap.Bool("dry_run", config.DryRun))

	if config.DryRun {
		logger.Info("DRY RUN: Would set up chat archive backup",
			zap.String("repo", repoPath),
			zap.String("password_file", passwordFile))
		return result, nil
	}

	// ASSESS: Check restic
	if err := ensureRestic(rc); err != nil {
		return nil, err
	}

	// INTERVENE: Create directories
	if err := os.MkdirAll(resticDir, ResticDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", resticDir, err)
	}

	// INTERVENE: Generate password if needed (only on first setup)
	if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
		if err := generatePassword(passwordFile); err != nil {
			return nil, fmt.Errorf("failed to generate repository password: %w", err)
		}
		result.PasswordGenerated = true
		logger.Info("Generated restic repository password",
			zap.String("file", passwordFile))
	} else {
		logger.Info("Password file already exists, reusing",
			zap.String("file", passwordFile))
	}

	// INTERVENE: Initialize restic repository (idempotent)
	if err := initRepo(rc, repoPath, passwordFile); err != nil {
		return nil, fmt.Errorf("failed to initialize restic repository: %w", err)
	}

	// INTERVENE: Configure cron
	if err := configureCron(rc, config, homeDir); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Failed to configure cron: %v", err))
		logger.Warn("Cron configuration failed", zap.Error(err))
	} else {
		result.CronConfigured = true
	}

	// INTERVENE: Fix ownership if running as root for another user
	if os.Geteuid() == 0 && config.User != "" && config.User != "root" {
		if err := chownToUser(resticDir, config.User); err != nil {
			logger.Warn("Failed to change ownership",
				zap.String("path", resticDir),
				zap.Error(err))
		}
	}

	// EVALUATE: Log completion
	logger.Info("Chat archive setup completed",
		zap.Bool("cron_configured", result.CronConfigured),
		zap.Bool("password_generated", result.PasswordGenerated),
		zap.String("repo", repoPath))

	if result.PasswordGenerated {
		logger.Info("IMPORTANT: Your restic password is stored at: " + passwordFile)
		logger.Info("View it with: cat " + passwordFile)
		logger.Info("If lost, your backups will be UNRECOVERABLE")
	}

	return result, nil
}

// ensureRestic checks if restic is installed and offers to install if missing.
func ensureRestic(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if _, err := exec.LookPath("restic"); err == nil {
		logger.Debug("restic is installed")
		return nil
	}

	logger.Warn("restic not found", zap.String("hint", "install with: sudo apt install restic"))
	return fmt.Errorf("restic is required for backup functionality; install with 'sudo apt install restic'")
}

// generatePassword creates a secure password file.
func generatePassword(passwordFile string) error {
	password, err := crypto.GenerateURLSafePassword(PasswordLength)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	parentDir := filepath.Dir(passwordFile)
	if err := os.MkdirAll(parentDir, ResticDirPerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", parentDir, err)
	}

	if err := os.WriteFile(passwordFile, []byte(password), PasswordFilePerm); err != nil {
		return fmt.Errorf("failed to write password file: %w", err)
	}

	return nil
}

// initRepo initializes a restic repository (idempotent).
func initRepo(rc *eos_io.RuntimeContext, repoPath, passwordFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if already initialized
	if err := checkRepoInitialized(rc.Ctx, repoPath, passwordFile); err == nil {
		logger.Info("Restic repository already initialized",
			zap.String("repo", repoPath))
		return nil
	}

	// Create directory
	if err := os.MkdirAll(repoPath, RepoDirPerm); err != nil {
		return fmt.Errorf("failed to create repository directory %s: %w", repoPath, err)
	}

	// Initialize
	logger.Info("Initializing restic repository",
		zap.String("repo", repoPath))

	initCtx, cancel := context.WithTimeout(rc.Ctx, ResticCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(initCtx, "restic",
		"-r", repoPath,
		"--password-file", passwordFile,
		"init")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to initialize restic repository: %w\nOutput: %s", err, string(output))
	}

	logger.Info("Restic repository initialized",
		zap.String("repo", repoPath))
	return nil
}

// configureCron sets up cron jobs for backup and prune.
func configureCron(rc *eos_io.RuntimeContext, config ScheduleConfig, homeDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if _, err := exec.LookPath("crontab"); err != nil {
		return fmt.Errorf("crontab not found: %w", err)
	}

	// Get current crontab
	var existingCron string
	crontabCmd := exec.Command("crontab", "-l")
	if config.User != "" && config.User != "root" && os.Geteuid() == 0 {
		crontabCmd = exec.Command("crontab", "-u", config.User, "-l")
	}
	if output, err := crontabCmd.Output(); err == nil {
		existingCron = string(output)
	}

	// Remove existing chat-archive entries (idempotent reconfiguration)
	lines := strings.Split(existingCron, "\n")
	var cleanedLines []string
	for _, line := range lines {
		if strings.Contains(line, CronMarker) {
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}
	existingCron = strings.Join(cleanedLines, "\n")

	// Build the eos backup chats command
	eosBin, err := os.Executable()
	if err != nil {
		eosBin = "/usr/local/bin/eos"
	}
	eosBin = shellQuote(eosBin)

	userArg := ""
	if config.User != "" {
		userArg = " --user " + shellQuote(config.User)
	}

	// Add new cron entries
	cronEntries := fmt.Sprintf(
		"\n# %s: hourly chat archive backup\n"+
			"%s %s backup chats%s 2>&1 | logger -t %s\n"+
			"# %s: daily chat archive prune\n"+
			"%s %s backup chats --prune%s 2>&1 | logger -t %s\n",
		CronMarker, config.BackupCron, eosBin, userArg, CronMarker,
		CronMarker, config.PruneCron, eosBin, userArg, CronMarker,
	)

	newCron := strings.TrimRight(existingCron, "\n") + cronEntries

	// Install crontab
	installCmd := exec.Command("crontab", "-")
	if config.User != "" && config.User != "root" && os.Geteuid() == 0 {
		installCmd = exec.Command("crontab", "-u", config.User, "-")
	}
	installCmd.Stdin = strings.NewReader(newCron)

	if output, err := installCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install crontab: %w (output: %s)", err, string(output))
	}

	logger.Info("Configured cron jobs for chat archive",
		zap.String("backup_schedule", config.BackupCron),
		zap.String("prune_schedule", config.PruneCron))

	return nil
}

// RunPrune applies the retention policy to the restic repository.
func RunPrune(rc *eos_io.RuntimeContext, config BackupConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	homeDir, err := resolveHomeDir(config.User)
	if config.HomeDir != "" {
		homeDir = config.HomeDir
		err = nil
	}
	if err != nil {
		return &opError{Op: "resolve home directory", Err: err}
	}

	repoPath := filepath.Join(homeDir, ResticRepoSubdir)
	passwordFile := filepath.Join(homeDir, ResticPasswordSubdir)

	logger.Info("Running chat archive prune",
		zap.String("repo", repoPath),
		zap.String("keep_within", config.Retention.KeepWithin),
		zap.Int("keep_hourly", config.Retention.KeepHourly),
		zap.Int("keep_daily", config.Retention.KeepDaily))

	if config.DryRun {
		logger.Info("DRY RUN: Would prune with retention policy",
			zap.String("keep_within", config.Retention.KeepWithin))
		return nil
	}

	if err := checkRepoInitialized(rc.Ctx, repoPath, passwordFile); err != nil {
		return fmt.Errorf("restic repository not initialized at %s: %w\n"+
			"Run 'eos backup chats --setup' to initialize", repoPath, err)
	}

	args := []string{
		"-r", repoPath,
		"--password-file", passwordFile,
		"forget",
		"--tag", BackupTag,
		"--keep-within", config.Retention.KeepWithin,
		"--keep-hourly", fmt.Sprintf("%d", config.Retention.KeepHourly),
		"--keep-daily", fmt.Sprintf("%d", config.Retention.KeepDaily),
		"--keep-weekly", fmt.Sprintf("%d", config.Retention.KeepWeekly),
		"--keep-monthly", fmt.Sprintf("%d", config.Retention.KeepMonthly),
		"--prune",
	}

	pruneCtx, cancel := context.WithTimeout(rc.Ctx, PruneTimeout)
	defer cancel()

	cmd := exec.CommandContext(pruneCtx, "restic", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if pruneCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("restic prune timed out after %s", PruneTimeout)
		}
		return fmt.Errorf("restic prune failed: %w\nOutput: %s", err, string(output))
	}

	logger.Info("Chat archive prune completed",
		zap.String("output", string(output)))

	return nil
}

// chownToUser changes ownership of a path to a user.
func chownToUser(path, username string) error {
	cmd := exec.Command("chown", "-R", username+":"+username, path)
	return cmd.Run()
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
