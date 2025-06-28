// pkg/backup/client.go

package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
func (c *Client) RunRestic(args ...string) ([]byte, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	// Get password from Vault
	password, err := c.getRepositoryPassword()
	if err != nil {
		return nil, fmt.Errorf("getting repository password: %w", err)
	}

	// Build command
	cmd := exec.CommandContext(c.rc.Ctx, "restic", args...)
	
	// Set environment
	env := os.Environ()
	env = append(env, fmt.Sprintf("RESTIC_REPOSITORY=%s", c.repository.URL))
	env = append(env, fmt.Sprintf("RESTIC_PASSWORD=%s", password))
	
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
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	if err != nil {
		logger.Error("Restic command failed",
			zap.Error(err),
			zap.String("output", string(output)),
			zap.Duration("duration", duration))
		return output, fmt.Errorf("restic %s: %w\n%s", args[0], err, output)
	}

	logger.Info("Restic command completed",
		zap.String("command", args[0]),
		zap.Duration("duration", duration),
		zap.Int("output_bytes", len(output)))

	return output, nil
}

// getRepositoryPassword retrieves password from Vault
func (c *Client) getRepositoryPassword() (string, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	vaultPath := fmt.Sprintf("eos/backup/repositories/%s", c.repository.Name)
	logger.Info("Retrieving repository password from Vault",
		zap.String("path", vaultPath))

	vClient, err := vault.NewClient(c.rc)
	if err != nil {
		// Fall back to local password file if Vault unavailable
		logger.Warn("Vault unavailable, checking local password file",
			zap.Error(err))
		
		passwordFile := fmt.Sprintf("/var/lib/eos/secrets/backup/%s.password", c.repository.Name)
		if data, err := os.ReadFile(passwordFile); err == nil {
			return strings.TrimSpace(string(data)), nil
		}
		
		return "", fmt.Errorf("vault unavailable and no local password found")
	}

	secret, err := vClient.Logical().Read(vaultPath)
	if err != nil {
		return "", fmt.Errorf("reading from vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no secret found at %s", vaultPath)
	}
	
	password, ok := secret.Data["password"].(string)
	if !ok {
		return "", fmt.Errorf("invalid password format in vault")
	}

	return password, nil
}

// InitRepository initializes a new restic repository
func (c *Client) InitRepository() error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Initializing restic repository",
		zap.String("name", c.repository.Name),
		zap.String("url", c.repository.URL))

	_, err := c.RunRestic("init", "--repository-version", "2")
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
		return fmt.Errorf("backup failed: %w", err)
	}

	// Run retention policy if configured
	if profile.Retention != nil {
		logger.Info("Applying retention policy")
		if err := c.applyRetention(&profile); err != nil {
			logger.Error("Failed to apply retention policy", zap.Error(err))
		}
	}

	return nil
}

// runBackupWithProgress executes backup with JSON progress parsing
func (c *Client) runBackupWithProgress(args []string) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	cmd := exec.CommandContext(c.rc.Ctx, "restic", args...)
	
	// Set environment
	password, err := c.getRepositoryPassword()
	if err != nil {
		return err
	}
	
	env := os.Environ()
	env = append(env, fmt.Sprintf("RESTIC_REPOSITORY=%s", c.repository.URL))
	env = append(env, fmt.Sprintf("RESTIC_PASSWORD=%s", password))
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

	// Read stderr for errors
	var stderrBuf bytes.Buffer
	go func() {
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
	if err := os.MkdirAll(target, 0755); err != nil {
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