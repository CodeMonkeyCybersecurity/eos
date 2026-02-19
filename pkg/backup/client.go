// pkg/backup/client.go

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Client wraps restic functionality with Eos patterns
type Client struct {
	rc         *eos_io.RuntimeContext
	config     *Config
	repository *Repository
}

// NewClient creates a new backup client
func NewClient(rc *eos_io.RuntimeContext, repoName string) (*Client, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating backup client", zap.String("repository", repoName))

	config, err := LoadConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	repo, exists := config.Repositories[repoName]
	if !exists {
		return nil, fmt.Errorf("repository %q not found in configuration", repoName)
	}

	return &Client{
		rc:         rc,
		config:     config,
		repository: &repo,
	}, nil
}

// RunRestic executes restic with proper environment and logging
// SECURITY: Uses password file instead of environment variable to prevent
// password exposure via 'ps auxe' (CVSS 7.5 vulnerability mitigation)
func (c *Client) RunRestic(args ...string) ([]byte, error) {
	return c.runResticWithInitRetry(false, args...)
}

func (c *Client) runResticWithInitRetry(initAttempted bool, args ...string) ([]byte, error) {
	logger := otelzap.Ctx(c.rc.Ctx)

	if err := c.ensureResticAvailable(); err != nil {
		return nil, err
	}

	// Get repository password
	password, err := c.getRepositoryPassword()
	if err != nil {
		return nil, fmt.Errorf("getting repository password: %w", err)
	}

	// SECURITY FIX: Create temporary password file with restrictive permissions
	// This prevents password exposure in process environment variables
	passwordFile, err := os.CreateTemp("", "restic-password-*")
	if err != nil {
		return nil, fmt.Errorf("creating temporary password file: %w", err)
	}
	defer os.Remove(passwordFile.Name()) // Clean up immediately after use
	defer passwordFile.Close()

	// Set restrictive permissions (owner read-only)
	if err := os.Chmod(passwordFile.Name(), shared.ReadOnlySecretFilePerm); err != nil {
		return nil, fmt.Errorf("setting password file permissions: %w", err)
	}

	// Write password to file
	if _, err := passwordFile.WriteString(password); err != nil {
		return nil, fmt.Errorf("writing password to temporary file: %w", err)
	}
	if err := passwordFile.Sync(); err != nil {
		return nil, fmt.Errorf("syncing password file: %w", err)
	}

	// Build command with password file
	cmd := exec.CommandContext(c.rc.Ctx, "restic", args...)

	// Set environment (WITHOUT password)
	env := os.Environ()
	env = append(env, fmt.Sprintf("RESTIC_REPOSITORY=%s", c.repository.URL))
	env = append(env, fmt.Sprintf("RESTIC_PASSWORD_FILE=%s", passwordFile.Name()))

	// Add backend-specific environment variables
	for k, v := range c.repository.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	cmd.Env = env

	// Log command execution (without password)
	safeArgs := make([]string, len(args))
	copy(safeArgs, args)
	logger.Info("Executing restic command",
		zap.Strings("args", safeArgs),
		zap.String("repository", c.repository.URL),
		zap.String("backend", c.repository.Backend))

	// Execute with timing
	start := time.Now()
	outputBytes, err := cmd.CombinedOutput()
	duration := time.Since(start)
	output := string(outputBytes)

	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			logger.Error("Restic binary not found in PATH",
				zap.Error(err),
				zap.String("binary", ResticBinaryName),
				zap.Strings("args", safeArgs),
				zap.String("repository", c.repository.URL),
				zap.String("backend", c.repository.Backend))
			return outputBytes, fmt.Errorf("%w: install the %s binary and ensure it is in PATH", ErrResticNotInstalled, ResticBinaryName)
		}

		if !initAttempted && isRepositoryInitializationError(output) {
			if handleErr := c.handleRepositoryNotInitialized(output); handleErr != nil {
				return nil, handleErr
			}
			// Repository initialized, retry original command once.
			return c.runResticWithInitRetry(true, args...)
		}

		logger.Error("Restic command failed",
			zap.Error(err),
			zap.String("output", output),
			zap.Duration("duration", duration))
		return outputBytes, fmt.Errorf("restic %s: %w\n%s", args[0], err, output)
	}

	logger.Info("Restic command completed",
		zap.String("command", args[0]),
		zap.Duration("duration", duration),
		zap.Int("output_bytes", len(outputBytes)))

	return outputBytes, nil
}

// ensureResticAvailable verifies restic is in PATH and offers to install it if missing.
func (c *Client) ensureResticAvailable() error {
	if _, err := interaction.CheckDependencyInstalled(ResticBinaryName); err == nil {
		return nil
	}

	// In non-interactive environments we cannot prompt, so return the standard dependency error.
	if !interaction.IsTTY() {
		return fmt.Errorf("%w: install the %s binary and ensure it is in PATH", ErrResticNotInstalled, ResticBinaryName)
	}

	autoInstall := os.Geteuid() == 0
	installCmd := "apt-get update && apt-get install -y restic"
	if !autoInstall {
		installCmd = "sudo apt-get update && sudo apt-get install -y restic"
	}

	config := interaction.DependencyConfig{
		Name:           "Restic",
		Description:    "Encrypted, deduplicated backups required for eos backup operations",
		CheckCommand:   ResticBinaryName,
		CheckArgs:      []string{"version"},
		InstallCmd:     installCmd,
		Required:       true,
		AutoInstall:    autoInstall,
		InstallTimeout: 15 * time.Minute,
	}

	result, err := interaction.CheckDependencyWithPrompt(c.rc, config)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrResticNotInstalled, err)
	}

	if result == nil || !result.Found {
		return fmt.Errorf("%w: install the %s binary and ensure it is in PATH", ErrResticNotInstalled, ResticBinaryName)
	}

	return nil
}

// isRepositoryInitializationError detects restic output indicating repository initialization issues.
func isRepositoryInitializationError(output string) bool {
	lower := strings.ToLower(output)
	if lower == "" {
		return false
	}

	switch {
	case strings.Contains(lower, "is there a repository at the following location"):
		return true
	case strings.Contains(lower, "unable to open config file"):
		return true
	case strings.Contains(lower, "repository does not exist"):
		return true
	case strings.Contains(lower, "no such repository"):
		return true
	case strings.Contains(lower, "config file is not there"):
		return true
	default:
		return false
	}
}

// handleRepositoryNotInitialized prompts the user to initialize the repository when possible.
func (c *Client) handleRepositoryNotInitialized(resticOutput string) error {
	logger := otelzap.Ctx(c.rc.Ctx)

	logger.Warn("Restic repository appears uninitialized",
		zap.String("repository", c.repository.URL),
		zap.String("backend", c.repository.Backend),
		zap.String("restic_output", strings.TrimSpace(resticOutput)))

	message := fmt.Sprintf("Restic repository at %s is not initialized.", c.repository.URL)

	if !interaction.IsTTY() {
		return fmt.Errorf("%w: %s Initialize it with 'restic init' and rerun the command.", ErrRepositoryNotInitialized, message)
	}

	logger.Info("terminal prompt:", zap.String("output", "⚠ "+message))
	logger.Info("terminal prompt:", zap.String("output",
		"Initializing the repository will run: restic init --repository-version "+ResticRepositoryVersion))
	logger.Info("terminal prompt:", zap.String("output",
		fmt.Sprintf("Repository: %s", c.repository.URL)))

	if c.repository.Backend == "local" && strings.HasPrefix(c.repository.URL, "/") {
		logger.Info("terminal prompt:", zap.String("output",
			fmt.Sprintf("Ensure the directory exists and is writable: sudo mkdir -p %s", c.repository.URL)))
	}

	consent := interaction.PromptYesNo(c.rc.Ctx, "Initialize restic repository now", true)
	if !consent {
		return fmt.Errorf("%w: initialization declined by user", ErrRepositoryNotInitialized)
	}

	logger.Info("terminal prompt:", zap.String("output", "Initializing restic repository..."))

	if c.repository.Backend == "local" && strings.HasPrefix(c.repository.URL, "/") {
		if err := os.MkdirAll(c.repository.URL, 0o750); err != nil {
			return fmt.Errorf("%w: failed to prepare repository directory %s: %v", ErrRepositoryNotInitialized, c.repository.URL, err)
		}
	}

	if err := c.InitRepository(); err != nil {
		return fmt.Errorf("%w: initialization failed: %v", ErrRepositoryNotInitialized, err)
	}

	logger.Info("terminal prompt:", zap.String("output", "✓ Restic repository initialized"))
	return nil
}

// getRepositoryPassword retrieves the repository password using local secret stores
func (c *Client) getRepositoryPassword() (string, error) {
	logger := otelzap.Ctx(c.rc.Ctx)

	// 1. Vault-managed secret (preferred when Vault is configured)
	if isVaultConfigured() {
		if password, err := c.readPasswordFromVault(); err == nil {
			recordPasswordSource("vault", true)
			return password, nil
		} else {
			recordPasswordSource("vault", false)
			logger.Warn("Failed to read repository password from Vault",
				zap.String("repository", c.repository.Name),
				zap.Error(err))
		}
	}

	// 2. Repository-local password file (created by quick backup generator)
	localPasswordPath := filepath.Join(c.repository.URL, ".password")
	if password, err := readPasswordFile(localPasswordPath); err == nil {
		recordPasswordSource("repo_password_file", true)
		logger.Debug("Using repository-local password file",
			zap.String("path", localPasswordPath))
		return password, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		recordPasswordSource("repo_password_file", false)
		logger.Warn("Failed to read repository-local password file",
			zap.String("path", localPasswordPath),
			zap.Error(err))
	}

	// 3. Global secrets directory fallback (used by managed repositories)
	secretsPasswordPath := filepath.Join(secretsDirPath, fmt.Sprintf("%s.password", c.repository.Name))
	if password, err := readPasswordFile(secretsPasswordPath); err == nil {
		recordPasswordSource("secrets_password_file", true)
		logger.Debug("Using secrets directory password file",
			zap.String("path", secretsPasswordPath))
		return password, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		recordPasswordSource("secrets_password_file", false)
		logger.Warn("Failed to read secrets directory password file",
			zap.String("path", secretsPasswordPath),
			zap.Error(err))
	}

	// 4. Repository `.env` file (compatibility fallback)
	envPath := filepath.Join(c.repository.URL, ".env")
	if password, err := readPasswordFromEnvFile(envPath); err == nil {
		recordPasswordSource("repo_env", true)
		logger.Debug("Using repository .env file for restic password",
			zap.String("path", envPath))
		return password, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		recordPasswordSource("repo_env", false)
		logger.Warn("Failed to read repository .env file",
			zap.String("path", envPath),
			zap.Error(err))
	}

	// 5. Secrets directory .env file (fallback for non-local repositories)
	secretsEnvPath := filepath.Join(secretsDirPath, fmt.Sprintf("%s.env", c.repository.Name))
	if password, err := readPasswordFromEnvFile(secretsEnvPath); err == nil {
		recordPasswordSource("secrets_env", true)
		logger.Debug("Using secrets .env file for restic password",
			zap.String("path", secretsEnvPath))
		return password, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		recordPasswordSource("secrets_env", false)
		logger.Warn("Failed to read secrets .env file",
			zap.String("path", secretsEnvPath),
			zap.Error(err))
	}

	// 6. Environment variable overrides (least preferred)
	if passwordFile := strings.TrimSpace(os.Getenv("RESTIC_PASSWORD_FILE")); passwordFile != "" {
		if password, err := readPasswordFile(passwordFile); err == nil {
			recordPasswordSource("env_var", true)
			logger.Warn("Using RESTIC_PASSWORD_FILE override; prefer managed password files",
				zap.String("path", passwordFile))
			return password, nil
		}
		recordPasswordSource("env_var", false)
	}

	// 7. Raw environment variable override
	if password := strings.TrimSpace(os.Getenv("RESTIC_PASSWORD")); password != "" {
		recordPasswordSource("env_var", true)
		logger.Warn("Using RESTIC_PASSWORD environment variable; prefer password files for security")
		return password, nil
	}

	missingErr := fmt.Errorf("restic repository password not found; expected password file at %s, secrets fallback at %s, or RESTIC_PASSWORD in %s",
		localPasswordPath, secretsPasswordPath, envPath)

	// 8. Interactive wizard fallback
	password, wizardErr := c.runPasswordWizard(localPasswordPath, secretsPasswordPath, []string{envPath, secretsEnvPath})
	if wizardErr == nil {
		recordPasswordSource("wizard", true)
		return password, nil
	}
	if wizardErr != nil && !errors.Is(wizardErr, errPasswordWizardSkipped) {
		recordPasswordSource("wizard", false)
		logger.Warn("Password setup wizard failed",
			zap.Error(wizardErr))
	}

	return "", missingErr
}

func (c *Client) readPasswordFromVault() (string, error) {
	var secret map[string]interface{}
	vaultPath := fmt.Sprintf("%s/%s", VaultPasswordPathPrefix, c.repository.Name)
	if err := vault.ReadFromVault(c.rc, vaultPath, &secret); err != nil {
		return "", err
	}

	raw, ok := secret[VaultPasswordKey]
	if !ok {
		return "", fmt.Errorf("vault secret %q missing key %q", vaultPath, VaultPasswordKey)
	}
	password, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("vault secret %q contains non-string password", vaultPath)
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return "", fmt.Errorf("vault secret %q contains empty password", vaultPath)
	}
	return password, nil
}

func isVaultConfigured() bool {
	return strings.TrimSpace(os.Getenv("VAULT_ADDR")) != ""
}

// InitRepository initializes a new restic repository
func (c *Client) InitRepository() error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Initializing restic repository",
		zap.String("name", c.repository.Name),
		zap.String("url", c.repository.URL))

	_, err := c.RunRestic("init", "--repository-version", ResticRepositoryVersion)
	if err != nil {
		// Check if already initialized
		if strings.Contains(err.Error(), "already initialized") {
			logger.Info("Repository already initialized")
			return nil
		}
		return fmt.Errorf("initializing repository: %w", err)
	}

	logger.Info("Repository initialized successfully")
	return nil
}

// Backup performs a backup using the specified profile
func (c *Client) Backup(profileName string) error {
	logger := otelzap.Ctx(c.rc.Ctx)

	profile, exists := c.config.Profiles[profileName]
	if !exists {
		return fmt.Errorf("profile %q not found", profileName)
	}

	logger.Info("Starting backup",
		zap.String("profile", profileName),
		zap.String("repository", c.repository.Name),
		zap.Strings("paths", profile.Paths))

	// Execute pre-backup hooks
	if profile.Hooks != nil && len(profile.Hooks.PreBackup) > 0 {
		logger.Info("Executing pre-backup hooks",
			zap.Int("count", len(profile.Hooks.PreBackup)))
		if err := c.executeHooks(profile.Hooks.PreBackup, "pre-backup"); err != nil {
			// Execute error hooks if pre-backup fails
			if len(profile.Hooks.OnError) > 0 {
				c.executeHooks(profile.Hooks.OnError, "error")
			}
			return fmt.Errorf("pre-backup hook failed: %w", err)
		}
	}

	// Build backup command
	args := []string{"backup"}

	// Add paths
	args = append(args, profile.Paths...)

	// Add excludes
	for _, exclude := range profile.Excludes {
		args = append(args, "--exclude", exclude)
	}

	// Add tags
	for _, tag := range profile.Tags {
		args = append(args, "--tag", tag)
	}

	// Add host if specified
	if profile.Host != "" {
		args = append(args, "--host", profile.Host)
	}

	// Progress reporting
	args = append(args, "--json")

	// Run backup with progress monitoring
	if err := c.runBackupWithProgress(args); err != nil {
		// Execute error hooks on backup failure
		if profile.Hooks != nil && len(profile.Hooks.OnError) > 0 {
			logger.Info("Executing error hooks",
				zap.Int("count", len(profile.Hooks.OnError)))
			if hookErr := c.executeHooks(profile.Hooks.OnError, "error"); hookErr != nil {
				logger.Error("Error hook failed", zap.Error(hookErr))
			}
		}
		return fmt.Errorf("backup failed: %w", err)
	}

	// Run retention policy if configured
	if profile.Retention != nil {
		logger.Info("Applying retention policy")
		if err := c.applyRetention(&profile); err != nil {
			logger.Error("Failed to apply retention policy", zap.Error(err))
		}
	}

	// Execute post-backup hooks
	if profile.Hooks != nil && len(profile.Hooks.PostBackup) > 0 {
		logger.Info("Executing post-backup hooks",
			zap.Int("count", len(profile.Hooks.PostBackup)))
		if err := c.executeHooks(profile.Hooks.PostBackup, "post-backup"); err != nil {
			logger.Error("Post-backup hook failed", zap.Error(err))
			// Don't fail the backup if post-backup hooks fail
		}
	}

	return nil
}

// readPasswordFile reads and trims a password from the provided file path.
func readPasswordFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	password := strings.TrimSpace(string(data))
	if password == "" {
		return "", fmt.Errorf("password file %s is empty", path)
	}

	return password, nil
}

// readPasswordFromEnvFile retrieves a restic password from a .env file if present.
// The file may contain either RESTIC_PASSWORD or RESTIC_PASSWORD_FILE pointing to a
// secondary password file.
func readPasswordFromEnvFile(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}

	vars, err := shared.ParseEnvFile(path)
	if err != nil {
		return "", err
	}

	if passwordFile, ok := vars["RESTIC_PASSWORD_FILE"]; ok && strings.TrimSpace(passwordFile) != "" {
		return readPasswordFile(strings.TrimSpace(passwordFile))
	}

	if password, ok := vars["RESTIC_PASSWORD"]; ok && strings.TrimSpace(password) != "" {
		return strings.TrimSpace(password), nil
	}

	return "", fmt.Errorf("restic password not found in %s", path)
}

// runBackupWithProgress executes backup with JSON progress parsing
// SECURITY: Uses password file instead of environment variable to prevent
// password exposure via 'ps auxe' (CVSS 7.5 vulnerability mitigation)
func (c *Client) runBackupWithProgress(args []string) error {
	logger := otelzap.Ctx(c.rc.Ctx)

	cmd := exec.CommandContext(c.rc.Ctx, "restic", args...)

	// Get repository password
	password, err := c.getRepositoryPassword()
	if err != nil {
		return err
	}

	// SECURITY FIX: Create temporary password file with restrictive permissions
	// This prevents password exposure in process environment variables
	passwordFile, err := os.CreateTemp("", "restic-password-*")
	if err != nil {
		return fmt.Errorf("creating temporary password file: %w", err)
	}
	defer os.Remove(passwordFile.Name()) // Clean up immediately after use
	defer passwordFile.Close()

	// Set restrictive permissions (owner read-only)
	if err := os.Chmod(passwordFile.Name(), TempPasswordFilePerm); err != nil {
		return fmt.Errorf("setting password file permissions: %w", err)
	}

	// Write password to file
	if _, err := passwordFile.WriteString(password); err != nil {
		return fmt.Errorf("writing password to temporary file: %w", err)
	}
	if err := passwordFile.Sync(); err != nil {
		return fmt.Errorf("syncing password file: %w", err)
	}

	// Set environment (WITHOUT password)
	env := os.Environ()
	env = append(env, fmt.Sprintf("RESTIC_REPOSITORY=%s", c.repository.URL))
	env = append(env, fmt.Sprintf("RESTIC_PASSWORD_FILE=%s", passwordFile.Name()))
	for k, v := range c.repository.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	// Get pipes for stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return err
	}

	// Read stderr for errors with panic recovery
	var stderrBuf bytes.Buffer
	go func() {
		// SECURITY: Panic recovery for stderr reader
		defer func() {
			if r := recover(); r != nil {
				logger := otelzap.Ctx(c.rc.Ctx)
				logger.Error("Stderr reader panic recovered",
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())))
			}
		}()

		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if err != nil {
				break
			}
			stderrBuf.Write(buf[:n])
		}
	}()

	// Parse JSON progress
	decoder := json.NewDecoder(stdout)
	var lastProgress time.Time

	for {
		var msg map[string]interface{}
		if err := decoder.Decode(&msg); err != nil {
			break
		}

		msgType, _ := msg["message_type"].(string)

		switch msgType {
		case "status":
			// Throttle progress updates to once per second
			if time.Since(lastProgress) > time.Second {
				percentDone, _ := msg["percent_done"].(float64)
				totalFiles, _ := msg["total_files"].(float64)
				totalBytes, _ := msg["total_bytes"].(float64)

				logger.Info("Backup progress",
					zap.Float64("percent", percentDone*100),
					zap.Int("total_files", int(totalFiles)),
					zap.String("total_size", humanizeBytes(int64(totalBytes))))

				lastProgress = time.Now()
			}

		case "summary":
			filesNew, _ := msg["files_new"].(float64)
			filesChanged, _ := msg["files_changed"].(float64)
			filesUnmodified, _ := msg["files_unmodified"].(float64)
			dataSizeInRepo, _ := msg["data_size_in_repo"].(float64)
			totalDuration, _ := msg["total_duration"].(float64)
			snapshotID, _ := msg["snapshot_id"].(string)

			logger.Info("Backup completed",
				zap.String("snapshot_id", snapshotID),
				zap.Int("files_new", int(filesNew)),
				zap.Int("files_changed", int(filesChanged)),
				zap.Int("files_unmodified", int(filesUnmodified)),
				zap.String("repo_size", humanizeBytes(int64(dataSizeInRepo))),
				zap.Duration("duration", time.Duration(totalDuration)*time.Second))

		case "error":
			item, _ := msg["item"].(string)
			during, _ := msg["during"].(string)
			errMsg, _ := msg["error"].(string)

			logger.Error("Backup error",
				zap.String("item", item),
				zap.String("during", during),
				zap.String("error", errMsg))
		}
	}

	// Wait for completion
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("backup failed: %w\nstderr: %s", err, stderrBuf.String())
	}

	return nil
}

// ListSnapshots returns all snapshots in the repository
func (c *Client) ListSnapshots() ([]Snapshot, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Listing snapshots")

	output, err := c.RunRestic("snapshots", "--json")
	if err != nil {
		return nil, err
	}

	var snapshots []Snapshot
	if err := json.Unmarshal(output, &snapshots); err != nil {
		return nil, fmt.Errorf("parsing snapshots: %w", err)
	}

	logger.Info("Found snapshots",
		zap.Int("count", len(snapshots)))

	return snapshots, nil
}

// Restore restores a snapshot to the specified target
func (c *Client) Restore(snapshotID, target string) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Starting restore",
		zap.String("snapshot", snapshotID),
		zap.String("target", target))

	// Ensure target directory exists
	if err := os.MkdirAll(target, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("creating target directory: %w", err)
	}

	_, err := c.RunRestic("restore", snapshotID, "--target", target)
	if err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}

	logger.Info("Restore completed successfully")
	return nil
}

// Verify checks the integrity of a snapshot
func (c *Client) Verify(snapshotID string) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Verifying snapshot integrity",
		zap.String("snapshot", snapshotID))

	_, err := c.RunRestic("check", "--read-data-subset=1/10", snapshotID)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	logger.Info("Snapshot verified successfully")
	return nil
}

// applyRetention applies retention policy to the repository
func (c *Client) applyRetention(profile *Profile) error {
	logger := otelzap.Ctx(c.rc.Ctx)

	args := []string{"forget", "--prune"}

	if profile.Retention.KeepLast > 0 {
		args = append(args, "--keep-last", fmt.Sprintf("%d", profile.Retention.KeepLast))
	}
	if profile.Retention.KeepDaily > 0 {
		args = append(args, "--keep-daily", fmt.Sprintf("%d", profile.Retention.KeepDaily))
	}
	if profile.Retention.KeepWeekly > 0 {
		args = append(args, "--keep-weekly", fmt.Sprintf("%d", profile.Retention.KeepWeekly))
	}
	if profile.Retention.KeepMonthly > 0 {
		args = append(args, "--keep-monthly", fmt.Sprintf("%d", profile.Retention.KeepMonthly))
	}
	if profile.Retention.KeepYearly > 0 {
		args = append(args, "--keep-yearly", fmt.Sprintf("%d", profile.Retention.KeepYearly))
	}

	// Add tags from profile
	for _, tag := range profile.Tags {
		args = append(args, "--tag", tag)
	}

	logger.Info("Applying retention policy",
		zap.String("profile", profile.Name),
		zap.Any("retention", profile.Retention))

	_, err := c.RunRestic(args...)
	return err
}

// RepositoryStats contains repository statistics
type RepositoryStats struct {
	RepositoryID     string
	TotalSize        int64
	TotalFileCount   int64
	SnapshotCount    int
	CompressionRatio float64
	LastCheck        time.Time
	HostStats        map[string]HostStats
}

// HostStats contains per-host statistics
type HostStats struct {
	SnapshotCount int
	Size          int64
}

// GetStats retrieves repository statistics
func (c *Client) GetStats() (*RepositoryStats, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Retrieving repository statistics")

	// Get stats JSON output from restic
	output, err := c.RunRestic("stats", "--json", "--mode", "raw-data")
	if err != nil {
		return nil, fmt.Errorf("getting repository stats: %w", err)
	}

	// Parse stats output
	var statsData struct {
		TotalSize      int64 `json:"total_size"`
		TotalFileCount int64 `json:"total_file_count"`
	}
	if err := json.Unmarshal(output, &statsData); err != nil {
		return nil, fmt.Errorf("parsing stats output: %w", err)
	}

	// Get snapshots for additional metadata
	snapshots, err := c.ListSnapshots()
	if err != nil {
		return nil, fmt.Errorf("listing snapshots: %w", err)
	}

	// Build per-host statistics
	hostStats := make(map[string]HostStats)
	for _, snap := range snapshots {
		stats := hostStats[snap.Hostname]
		stats.SnapshotCount++
		hostStats[snap.Hostname] = stats
	}

	// Try to get repository ID from snapshots command
	repoID := c.repository.Name
	snapshotOutput, err := c.RunRestic("snapshots", "--json", "--last")
	if err == nil {
		var lastSnapshot []Snapshot
		if err := json.Unmarshal(snapshotOutput, &lastSnapshot); err == nil && len(lastSnapshot) > 0 {
			// Use tree field as a proxy for repo uniqueness
			if lastSnapshot[0].Tree != "" {
				repoID = lastSnapshot[0].Tree[:8]
			}
		}
	}

	// Calculate compression ratio (estimate)
	compressionRatio := 1.0
	if statsData.TotalSize > 0 {
		// This is a rough estimate - actual compression ratio would need more detailed stats
		compressionRatio = 0.7 // Typical restic compression
	}

	stats := &RepositoryStats{
		RepositoryID:     repoID,
		TotalSize:        statsData.TotalSize,
		TotalFileCount:   statsData.TotalFileCount,
		SnapshotCount:    len(snapshots),
		CompressionRatio: compressionRatio,
		HostStats:        hostStats,
	}

	// Try to get last check time from check output (this might fail if never checked)
	// Note: restic doesn't directly expose last check time, so we skip this for now
	stats.LastCheck = time.Time{}

	logger.Info("Repository statistics retrieved",
		zap.Int("snapshots", stats.SnapshotCount),
		zap.Int64("total_size", stats.TotalSize),
		zap.Int("hosts", len(hostStats)))

	return stats, nil
}

// executeHooks executes a list of hook commands with timeout
// SECURITY: Hooks run with configured timeout (HookTimeout) to prevent hung backups
func (c *Client) executeHooks(hooks []string, hookType string) error {
	logger := otelzap.Ctx(c.rc.Ctx)

	for i, hookCmd := range hooks {
		logger.Info("Executing hook",
			zap.String("type", hookType),
			zap.Int("index", i+1),
			zap.Int("total", len(hooks)),
			zap.String("command", hookCmd))

		// Create command with timeout context
		ctx, cancel := context.WithTimeout(c.rc.Ctx, HookTimeout)
		defer cancel()

		// Execute hook
		start := time.Now()
		err := RunHookWithSettings(ctx, logger, hookCmd, c.config.Settings)
		duration := time.Since(start)

		// Check for timeout
		if ctx.Err() == context.DeadlineExceeded {
			logger.Error("Hook timed out",
				zap.String("type", hookType),
				zap.String("command", hookCmd),
				zap.Duration("timeout", HookTimeout))
			return fmt.Errorf("hook timed out after %s: %s", HookTimeout, hookCmd)
		}

		// Log output
		if err != nil {
			logger.Error("Hook failed",
				zap.String("type", hookType),
				zap.String("command", hookCmd),
				zap.Duration("duration", duration),
				zap.Error(err))
			return fmt.Errorf("hook failed: %w", err)
		}

		logger.Info("Hook completed successfully",
			zap.String("type", hookType),
			zap.String("command", hookCmd),
			zap.Duration("duration", duration))
	}

	logger.Info("All hooks completed successfully",
		zap.String("type", hookType),
		zap.Int("count", len(hooks)))

	return nil
}

// humanizeBytes converts bytes to human-readable format
func humanizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
