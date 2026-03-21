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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	backup_schedule "github.com/CodeMonkeyCybersecurity/eos/pkg/backup/schedule"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/systemd"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var findLegacyRepositoriesFn = findLegacyRepositories

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

	users, err := resolveBackupUsers(config.BackupConfig)
	if err != nil {
		return nil, &opError{Op: "resolve backup users", Err: err}
	}
	pathsCfg, err := resolveStoragePaths(config.BackupConfig, users)
	if err != nil {
		return nil, &opError{Op: "resolve storage paths", Err: err}
	}

	result.RepoPath = pathsCfg.Repo
	result.PasswordFile = pathsCfg.PasswordFile
	result.BackupCron = config.BackupCron
	result.PruneCron = config.PruneCron

	logger.Info("Setting up chat archive backup",
		zap.String("user", config.User),
		zap.Bool("all_users", config.AllUsers),
		zap.String("repo", pathsCfg.Repo),
		zap.String("backup_cron", config.BackupCron),
		zap.String("prune_cron", config.PruneCron),
		zap.Bool("dry_run", config.DryRun))

	if config.DryRun {
		logger.Info("DRY RUN: Would set up chat archive backup",
			zap.String("repo", pathsCfg.Repo),
			zap.String("password_file", pathsCfg.PasswordFile))
		return result, nil
	}

	// ASSESS: Check restic
	if err := ensureRestic(rc); err != nil {
		return nil, err
	}

	// INTERVENE: Create directories
	for _, dir := range []string{
		filepath.Dir(pathsCfg.Repo),
		filepath.Dir(pathsCfg.PasswordFile),
		filepath.Dir(pathsCfg.StatusFile),
		filepath.Dir(pathsCfg.ManifestFile),
		filepath.Dir(pathsCfg.LockFile),
	} {
		if err := os.MkdirAll(dir, ResticDirPerm); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// INTERVENE: Generate password if needed (only on first setup)
	if _, err := os.Stat(pathsCfg.PasswordFile); os.IsNotExist(err) {
		if err := generatePassword(pathsCfg.PasswordFile); err != nil {
			return nil, fmt.Errorf("failed to generate repository password: %w", err)
		}
		result.PasswordGenerated = true
		logger.Info("Generated restic repository password",
			zap.String("file", pathsCfg.PasswordFile))
	} else {
		logger.Info("Password file already exists, reusing",
			zap.String("file", pathsCfg.PasswordFile))
	}

	// INTERVENE: Initialize restic repository (idempotent)
	if err := initRepo(rc, pathsCfg.Repo, pathsCfg.PasswordFile); err != nil {
		return nil, fmt.Errorf("failed to initialize restic repository: %w", err)
	}

	if config.AllUsers {
		if err := migrateLegacyRepositories(rc, pathsCfg); err != nil {
			return nil, fmt.Errorf("failed to migrate legacy chat archive repository: %w", err)
		}
		if err := configureSystemdTimers(rc, config); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Failed to configure systemd timers: %v", err))
			logger.Warn("Systemd timer configuration failed", zap.Error(err))
		} else {
			result.CronConfigured = true
		}
		if err := cleanupLegacyCronEntries(rc, users); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Failed to clean legacy cron entries: %v", err))
			logger.Warn("Legacy cron cleanup failed", zap.Error(err))
		}
	} else {
		homeDir := users[0].HomeDir
		if err := configureCron(rc, config, homeDir); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Failed to configure cron: %v", err))
			logger.Warn("Cron configuration failed", zap.Error(err))
		} else {
			result.CronConfigured = true
		}

		// INTERVENE: Fix ownership if running as root for another user.
		if osGeteuid() == 0 && config.User != "" && config.User != "root" {
			eosDir := filepath.Join(homeDir, ".eos")
			if err := chownToUser(eosDir, config.User); err != nil {
				logger.Warn("Failed to change ownership of .eos directory",
					zap.String("path", eosDir),
					zap.Error(err))
			}
		}
	}

	// EVALUATE: Log completion
	logger.Info("Chat archive setup completed",
		zap.Bool("cron_configured", result.CronConfigured),
		zap.Bool("password_generated", result.PasswordGenerated),
		zap.String("repo", pathsCfg.Repo))

	if result.PasswordGenerated {
		logger.Info("IMPORTANT: Your restic password is stored at: " + pathsCfg.PasswordFile)
		logger.Info("View it with: cat " + pathsCfg.PasswordFile)
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
	return fmt.Errorf("%w", ErrResticNotInstalled)
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
	if config.User != "" && config.User != "root" && osGeteuid() == 0 {
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
	if config.User != "" && config.User != "root" && osGeteuid() == 0 {
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

func configureSystemdTimers(rc *eos_io.RuntimeContext, config ScheduleConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	eosBin, err := os.Executable()
	if err != nil {
		eosBin = "/usr/local/bin/eos"
	}

	backupService := fmt.Sprintf(`[Unit]
Description=Eos Chat Archive Backup
After=network.target

[Service]
Type=oneshot
ExecStart=%s backup chats --all-users
User=root
StandardOutput=journal
StandardError=journal
`, eosBin)

	backupTimer := fmt.Sprintf(`[Unit]
Description=Eos Chat Archive Backup Timer

[Timer]
OnCalendar=%s
Persistent=true

[Install]
WantedBy=timers.target
`, backupCronToOnCalendar(rc, config.BackupCron))

	pruneService := fmt.Sprintf(`[Unit]
Description=Eos Chat Archive Prune
After=network.target

[Service]
Type=oneshot
ExecStart=%s backup chats --all-users --prune
User=root
StandardOutput=journal
StandardError=journal
`, eosBin)

	pruneTimer := fmt.Sprintf(`[Unit]
Description=Eos Chat Archive Prune Timer

[Timer]
OnCalendar=%s
Persistent=true

[Install]
WantedBy=timers.target
`, backupCronToOnCalendar(rc, config.PruneCron))

	units := map[string]string{
		BackupServiceName: backupService,
		BackupTimerName:   backupTimer,
		PruneServiceName:  pruneService,
		PruneTimerName:    pruneTimer,
	}

	for name, content := range units {
		path := filepath.Join(SystemdUnitDir, name)
		if err := os.MkdirAll(filepath.Dir(path), ResticDirPerm); err != nil {
			return fmt.Errorf("create unit directory: %w", err)
		}
		if err := os.WriteFile(path, []byte(content), SystemdUnitPerm); err != nil {
			return fmt.Errorf("write unit %s: %w", name, err)
		}
	}

	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", BackupTimerName},
		{"systemctl", "start", BackupTimerName},
		{"systemctl", "enable", PruneTimerName},
		{"systemctl", "start", PruneTimerName},
	} {
		if err := systemd.RunSystemctl(rc, args...); err != nil {
			return err
		}
	}

	logger.Info("Configured machine-wide chat backup timers",
		zap.String("backup_timer", BackupTimerName),
		zap.String("prune_timer", PruneTimerName))
	return nil
}

// RunPrune applies the retention policy to the restic repository.
func RunPrune(rc *eos_io.RuntimeContext, config BackupConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	users, err := resolveBackupUsers(config)
	if err != nil {
		return &opError{Op: "resolve backup users", Err: err}
	}
	pathsCfg, err := resolveStoragePaths(config, users)
	if err != nil {
		return &opError{Op: "resolve storage paths", Err: err}
	}

	logger.Info("Running chat archive prune",
		zap.String("repo", pathsCfg.Repo),
		zap.String("keep_within", config.Retention.KeepWithin),
		zap.Int("keep_hourly", config.Retention.KeepHourly),
		zap.Int("keep_daily", config.Retention.KeepDaily))

	if config.DryRun {
		logger.Info("DRY RUN: Would prune with retention policy",
			zap.String("keep_within", config.Retention.KeepWithin))
		return nil
	}

	if err := checkRepoInitialized(rc.Ctx, pathsCfg.Repo, pathsCfg.PasswordFile); err != nil {
		return fmt.Errorf("%w at %s: %v\n"+
			"Run 'eos backup chats --setup' to initialize", ErrRepositoryNotInitialized, pathsCfg.Repo, err)
	}

	args := []string{
		"-r", pathsCfg.Repo,
		"--password-file", pathsCfg.PasswordFile,
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
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return filepath.Walk(path, func(current string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return os.Chown(current, uid, gid)
	})
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func backupCronToOnCalendar(rc *eos_io.RuntimeContext, cron string) string {
	if cron == "" {
		return "hourly"
	}
	return backup_schedule.CronToOnCalendar(rc, cron)
}

func migrateLegacyRepositories(rc *eos_io.RuntimeContext, destination storagePaths) error {
	hasSnapshots, err := repoHasTaggedSnapshots(rc, destination.Repo, destination.PasswordFile)
	if err != nil {
		return err
	}
	if hasSnapshots {
		return nil
	}

	sources := findLegacyRepositoriesFn()
	for _, source := range sources {
		if source.Repo == destination.Repo {
			continue
		}
		if err := copySnapshots(rc, source, destination); err != nil {
			return err
		}
	}
	return nil
}

func findLegacyRepositories() []storagePaths {
	users, err := listScannedUsers()
	if err != nil {
		return nil
	}
	sources := make([]storagePaths, 0, len(users))
	for _, scanned := range users {
		homeDir := scanned.HomeDir
		repo := filepath.Join(homeDir, ResticRepoSubdir)
		password := filepath.Join(homeDir, ResticPasswordSubdir)
		if _, err := os.Stat(repo); err != nil {
			continue
		}
		if _, err := os.Stat(password); err != nil {
			continue
		}
		sources = append(sources, storagePaths{
			Repo:         repo,
			PasswordFile: password,
			StatusFile:   filepath.Join(homeDir, ResticStatusSubdir),
			ManifestFile: filepath.Join(homeDir, ".eos/restic/chat-archive-manifest.json"),
			LockFile:     filepath.Join(homeDir, ResticLockSubdir),
		})
	}
	return sources
}

func copySnapshots(rc *eos_io.RuntimeContext, source, destination storagePaths) error {
	copyCtx, cancel := context.WithTimeout(rc.Ctx, PruneTimeout)
	defer cancel()

	cmd := exec.CommandContext(copyCtx, "restic", //nolint:gosec // args are validated constants and repo paths, not user input
		"-r", destination.Repo,
		"--password-file", destination.PasswordFile,
		"copy",
		"--from-repo", source.Repo,
		"--from-password-file", source.PasswordFile,
		"--tag", BackupTag,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restic copy failed from %s: %w\nOutput: %s", source.Repo, err, string(output))
	}
	return nil
}

func repoHasTaggedSnapshots(rc *eos_io.RuntimeContext, repoPath, passwordFile string) (bool, error) {
	cmdCtx, cancel := context.WithTimeout(rc.Ctx, ResticCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "restic",
		"-r", repoPath,
		"--password-file", passwordFile,
		"snapshots",
		"--tag", BackupTag,
		"--json",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "no such file or directory") {
			return false, nil
		}
		return false, fmt.Errorf("check snapshots: %w\nOutput: %s", err, string(output))
	}

	var snapshots []map[string]any
	if err := json.Unmarshal(output, &snapshots); err != nil {
		return false, nil
	}
	return len(snapshots) > 0, nil
}

func cleanupLegacyCronEntries(_ *eos_io.RuntimeContext, users []scannedUser) error {
	var errs []string
	for _, scanned := range users {
		if scanned.Username == "" || scanned.Username == "root" {
			continue
		}
		if err := removeCronMarkerForUser(scanned.Username); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", scanned.Username, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func removeCronMarkerForUser(username string) error {
	if _, err := exec.LookPath("crontab"); err != nil {
		return nil //nolint:nilerr // crontab not installed is a valid no-op, not an error
	}

	listCmd := exec.Command("crontab", "-u", username, "-l")
	output, err := listCmd.Output()
	if err != nil {
		return nil //nolint:nilerr // user has no crontab is a valid no-op, not an error
	}

	lines := strings.Split(string(output), "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, CronMarker) {
			continue
		}
		cleaned = append(cleaned, line)
	}

	newCron := strings.TrimSpace(strings.Join(cleaned, "\n"))
	installCmd := exec.Command("crontab", "-u", username, "-")
	installCmd.Stdin = strings.NewReader(newCron + "\n")
	if output, err := installCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install cleaned crontab: %w (output: %s)", err, string(output))
	}
	return nil
}
