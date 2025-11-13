package openwebui

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateConfig holds configuration for updating Open WebUI
type UpdateConfig struct {
	InstallDir      string
	ComposeFile     string
	BackupDir       string
	TargetVersion   string // e.g., "v0.6.32" or "latest"
	SkipBackup      bool
	SkipHealthCheck bool
	AutoRollback    bool
}

// OpenWebUIUpdater handles updating Open WebUI installations
type OpenWebUIUpdater struct {
	rc     *eos_io.RuntimeContext
	config *UpdateConfig
}

// UpdateState tracks the state of an update
type UpdateState struct {
	CurrentVersion string
	TargetVersion  string
	BackupPath     string
	UpdateSuccess  bool
	HealthyAfter   bool
}

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Prerelease bool   `json:"prerelease"`
	Draft      bool   `json:"draft"`
	CreatedAt  string `json:"created_at"`
}

// Lock file path for preventing concurrent updates
const updateLockFile = "/var/lock/eos-openwebui-update.lock"

// NewOpenWebUIUpdater creates a new updater instance
func NewOpenWebUIUpdater(rc *eos_io.RuntimeContext, config *UpdateConfig) *OpenWebUIUpdater {
	if config.InstallDir == "" {
		config.InstallDir = "/opt/openwebui"
	}
	if config.ComposeFile == "" {
		config.ComposeFile = filepath.Join(config.InstallDir, "docker-compose.yml")
	}
	if config.BackupDir == "" {
		config.BackupDir = filepath.Join(config.InstallDir, "backups")
	}

	return &OpenWebUIUpdater{
		rc:     rc,
		config: config,
	}
}

// validateVersionTag validates version tag format and prevents injection attacks (P0 Security Fix)
func validateVersionTag(version string) error {
	// MUST be semantic version format: vX.Y.Z or vX.Y.Z-suffix
	validVersionRegex := regexp.MustCompile(`^v\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$`)
	if !validVersionRegex.MatchString(version) {
		return fmt.Errorf("invalid version tag format: %s (must match vX.Y.Z or vX.Y.Z-suffix)", version)
	}

	// Additional safety: Check for shell metacharacters that could enable RCE
	dangerousChars := []string{";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r", "\\", "\"", "'"}
	for _, char := range dangerousChars {
		if strings.Contains(version, char) {
			return fmt.Errorf("version tag contains dangerous character: %s", char)
		}
	}

	return nil
}

// validateBackupPath validates backup file path to prevent path traversal (P0 Security Fix)
func validateBackupPath(backupPath string) error {
	// Get absolute path to resolve symlinks and .. references
	absPath, err := filepath.Abs(backupPath)
	if err != nil {
		return fmt.Errorf("failed to resolve backup path: %w", err)
	}

	// Path must end with .tar.gz
	if !strings.HasSuffix(absPath, ".tar.gz") {
		return fmt.Errorf("backup file must have .tar.gz extension")
	}

	// Check for path traversal attempts
	if strings.Contains(backupPath, "..") {
		return fmt.Errorf("backup path contains path traversal attempt")
	}

	// Path must not contain null bytes or other dangerous characters
	dangerousChars := []string{"\x00", ";", "|", "&", "$", "`"}
	for _, char := range dangerousChars {
		if strings.Contains(backupPath, char) {
			return fmt.Errorf("backup path contains dangerous character")
		}
	}

	// Verify file exists
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("backup file not found: %w", err)
	}

	// Must be a regular file, not a symlink or device
	if !info.Mode().IsRegular() {
		return fmt.Errorf("backup path must be a regular file, not a symlink or special file")
	}

	return nil
}

// checkDiskSpace verifies sufficient disk space before backup (P1 Security Fix)
func checkDiskSpace(ctx context.Context, path string, requiredBytes uint64) error {
	logger := otelzap.Ctx(ctx)

	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	// Available space in bytes
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	availableGB := float64(availableBytes) / (1024 * 1024 * 1024)

	logger.Debug("Disk space check",
		zap.Uint64("available_bytes", availableBytes),
		zap.Float64("available_gb", availableGB),
		zap.Uint64("required_bytes", requiredBytes))

	if availableBytes < requiredBytes {
		requiredGB := float64(requiredBytes) / (1024 * 1024 * 1024)
		return fmt.Errorf("insufficient disk space: %.2f GB available, %.2f GB required", availableGB, requiredGB)
	}

	return nil
}

// acquireUpdateLock creates a lock file to prevent concurrent updates (P0 Security Fix)
func acquireUpdateLock(ctx context.Context) (*os.File, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Acquiring update lock", zap.String("lock_file", updateLockFile))

	// Ensure /var/lock exists
	if err := os.MkdirAll("/var/lock", shared.ServiceDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create lock directory: %w", err)
	}

	// Try to create lock file with exclusive access
	lockFile, err := os.OpenFile(updateLockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			// Check if lock is stale (older than 2 hours)
			info, statErr := os.Stat(updateLockFile)
			if statErr == nil && time.Since(info.ModTime()) > 2*time.Hour {
				logger.Warn("Removing stale lock file", zap.Duration("age", time.Since(info.ModTime())))
				if removeErr := os.Remove(updateLockFile); removeErr != nil {
					return nil, fmt.Errorf("failed to remove stale lock: %w", removeErr)
				}
				// Try again after removing stale lock
				return acquireUpdateLock(ctx)
			}
			return nil, fmt.Errorf("another update is already in progress (lock file exists: %s)", updateLockFile)
		}
		return nil, fmt.Errorf("failed to create lock file: %w", err)
	}

	// Write PID to lock file for debugging
	if _, err := fmt.Fprintf(lockFile, "%d\n", os.Getpid()); err != nil {
		_ = lockFile.Close()
		_ = os.Remove(updateLockFile)
		return nil, fmt.Errorf("failed to write to lock file: %w", err)
	}

	logger.Info("Update lock acquired", zap.String("lock_file", updateLockFile))
	return lockFile, nil
}

// releaseUpdateLock removes the lock file
func releaseUpdateLock(ctx context.Context, lockFile *os.File) {
	logger := otelzap.Ctx(ctx)
	if lockFile != nil {
		if err := lockFile.Close(); err != nil {
			logger.Warn("Failed to close lock file", zap.Error(err))
		}
		if err := os.Remove(updateLockFile); err != nil {
			logger.Warn("Failed to remove lock file", zap.Error(err))
		} else {
			logger.Debug("Update lock released")
		}
	}
}

// Update performs the update following AIE pattern
func (owu *OpenWebUIUpdater) Update() error {
	logger := otelzap.Ctx(owu.rc.Ctx)
	logger.Info("Starting Open WebUI update with safety features")

	// P0 Security Fix: Acquire update lock to prevent concurrent updates
	lockFile, err := acquireUpdateLock(owu.rc.Ctx)
	if err != nil {
		return eos_err.NewUserError("cannot start update: %v", err)
	}
	defer releaseUpdateLock(owu.rc.Ctx, lockFile)

	// ASSESS: Check current state
	state, err := owu.assessCurrentState(owu.rc.Ctx)
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	logger.Info("Assessment complete",
		zap.String("current_version", state.CurrentVersion),
		zap.String("target_version", state.TargetVersion))

	// Check if already at target version
	if state.CurrentVersion == state.TargetVersion {
		logger.Info("Already at target version, no update needed")
		return nil
	}

	// INTERVENE: Perform update
	if err := owu.performUpdate(owu.rc.Ctx, state); err != nil {
		logger.Error("Update failed", zap.Error(err))

		// Attempt rollback if enabled
		if owu.config.AutoRollback && state.BackupPath != "" {
			logger.Warn("Attempting automatic rollback")
			if rollbackErr := owu.rollback(owu.rc.Ctx, state); rollbackErr != nil {
				logger.Error("Rollback failed", zap.Error(rollbackErr))
				return fmt.Errorf("update failed and rollback failed: %w (original error: %v)", rollbackErr, err)
			}
			logger.Info("Rollback successful")
			return fmt.Errorf("update failed, rolled back to previous version: %w", err)
		}

		return err
	}

	// EVALUATE: Verify update success
	if err := owu.evaluateUpdate(owu.rc.Ctx, state); err != nil {
		logger.Error("Post-update evaluation failed", zap.Error(err))

		// Attempt rollback if health check fails
		if owu.config.AutoRollback && state.BackupPath != "" {
			logger.Warn("Health check failed, attempting automatic rollback")
			if rollbackErr := owu.rollback(owu.rc.Ctx, state); rollbackErr != nil {
				logger.Error("Rollback failed", zap.Error(rollbackErr))
				return fmt.Errorf("health check failed and rollback failed: %w (health check error: %v)", rollbackErr, err)
			}
			logger.Info("Rollback successful")
			return fmt.Errorf("health check failed, rolled back to previous version: %w", err)
		}

		return err
	}

	logger.Info("Open WebUI update completed successfully",
		zap.String("from_version", state.CurrentVersion),
		zap.String("to_version", state.TargetVersion))

	return nil
}

// assessCurrentState checks current installation state
func (owu *OpenWebUIUpdater) assessCurrentState(ctx context.Context) (*UpdateState, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Assessing current Open WebUI installation")

	state := &UpdateState{}

	// Check if installation exists
	if _, err := os.Stat(owu.config.ComposeFile); os.IsNotExist(err) {
		return nil, eos_err.NewUserError(
			"Open WebUI is not installed at %s\n"+
				"Please install it first with: eos create openwebui",
			owu.config.InstallDir)
	}

	// Get current version from docker-compose.yml
	currentVersion, err := owu.getCurrentVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current version: %w", err)
	}
	state.CurrentVersion = currentVersion

	logger.Debug("Current version detected", zap.String("version", currentVersion))

	// Determine target version
	targetVersion, err := owu.getTargetVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to determine target version: %w", err)
	}
	state.TargetVersion = targetVersion

	logger.Debug("Target version determined", zap.String("version", targetVersion))

	// Check if container is running
	isRunning, err := owu.isContainerRunning(ctx)
	if err != nil {
		logger.Warn("Failed to check if container is running", zap.Error(err))
	} else if !isRunning {
		logger.Warn("Open WebUI container is not currently running")
	}

	return state, nil
}

// getCurrentVersion extracts current version from docker-compose.yml
func (owu *OpenWebUIUpdater) getCurrentVersion(ctx context.Context) (string, error) {
	content, err := os.ReadFile(owu.config.ComposeFile)
	if err != nil {
		return "", fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}

	// Parse version from image line: ghcr.io/open-webui/open-webui:v0.3.32
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, "image:") && strings.Contains(line, "open-webui") {
			parts := strings.Split(strings.TrimSpace(line), ":")
			if len(parts) >= 3 {
				// Return the version tag (last part after last colon)
				version := strings.TrimSpace(parts[len(parts)-1])
				return version, nil
			}
		}
	}

	return "unknown", fmt.Errorf("could not parse version from docker-compose.yml")
}

// getTargetVersion determines the version to update to
func (owu *OpenWebUIUpdater) getTargetVersion(ctx context.Context) (string, error) {
	logger := otelzap.Ctx(ctx)

	// If version explicitly specified, validate and use it
	if owu.config.TargetVersion != "" && owu.config.TargetVersion != "latest" {
		// P0 Security Fix: Validate version tag to prevent RCE
		if err := validateVersionTag(owu.config.TargetVersion); err != nil {
			return "", fmt.Errorf("invalid target version: %w", err)
		}
		logger.Debug("Using explicitly specified version",
			zap.String("version", owu.config.TargetVersion))
		return owu.config.TargetVersion, nil
	}

	// Otherwise, fetch latest stable release from GitHub
	logger.Info("Fetching latest stable release from GitHub")

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.github.com/repos/open-webui/open-webui/releases", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("failed to parse releases: %w", err)
	}

	// Find the latest stable (non-prerelease, non-draft) release
	for _, release := range releases {
		if !release.Prerelease && !release.Draft {
			// P0 Security Fix: Validate version tag from GitHub API to prevent poisoning
			if err := validateVersionTag(release.TagName); err != nil {
				logger.Warn("Skipping invalid release tag from GitHub",
					zap.String("tag", release.TagName),
					zap.Error(err))
				continue
			}

			logger.Info("Latest stable release found",
				zap.String("version", release.TagName),
				zap.String("name", release.Name))
			return release.TagName, nil
		}
	}

	return "", fmt.Errorf("no stable releases found")
}

// isContainerRunning checks if the Open WebUI container is running
func (owu *OpenWebUIUpdater) isContainerRunning(ctx context.Context) (bool, error) {
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--filter", "name=open-webui", "--format", "{{.Names}}"},
		Capture: true,
	})

	if err != nil {
		return false, err
	}

	return strings.Contains(output, "open-webui"), nil
}

// performUpdate executes the update process
func (owu *OpenWebUIUpdater) performUpdate(ctx context.Context, state *UpdateState) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Performing update",
		zap.String("from", state.CurrentVersion),
		zap.String("to", state.TargetVersion))

	// Step 1: Stop container BEFORE backup (P0 Security Fix - prevents TOCTOU race condition)
	logger.Info("Stopping Open WebUI container before backup to ensure data consistency")
	if err := owu.stopContainer(ctx); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	// Step 2: Ensure backup directory exists before checking disk space
	if !owu.config.SkipBackup {
		logger.Debug("Ensuring backup directory exists", zap.String("backup_dir", owu.config.BackupDir))
		if err := os.MkdirAll(owu.config.BackupDir, shared.ServiceDirPerm); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}

		// Check disk space after creating directory (P1 Security Fix)
		// Estimate backup size: typically 1-5GB for Open WebUI data
		// Require at least 5GB available to be safe
		requiredSpace := uint64(5 * 1024 * 1024 * 1024) // 5GB in bytes
		if err := checkDiskSpace(ctx, owu.config.BackupDir, requiredSpace); err != nil {
			return fmt.Errorf("pre-backup disk space check failed: %w\n"+
				"Free up disk space before attempting update", err)
		}
		logger.Debug("Disk space check passed")
	}

	// Step 3: Backup data (unless skipped)
	if !owu.config.SkipBackup {
		backupPath, err := owu.backupData(ctx)
		if err != nil {
			// Try to restart container before returning error
			logger.Error("Backup failed, attempting to restart container", zap.Error(err))
			if startErr := owu.startContainer(ctx); startErr != nil {
				logger.Error("Failed to restart container after backup failure", zap.Error(startErr))
			}
			return fmt.Errorf("backup failed: %w", err)
		}
		state.BackupPath = backupPath
		logger.Info("Backup created successfully", zap.String("path", backupPath))
	} else {
		logger.Warn("Backup skipped (not recommended)")
	}

	// Step 4: Update docker-compose.yml with new version
	logger.Info("Updating docker-compose.yml", zap.String("new_version", state.TargetVersion))
	if err := owu.updateComposeFile(ctx, state.TargetVersion); err != nil {
		return fmt.Errorf("failed to update compose file: %w", err)
	}

	// Step 5: Pull new image
	logger.Info("Pulling new Docker image", zap.String("version", state.TargetVersion))
	if err := owu.pullImage(ctx); err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	// Step 6: Start container with new version
	logger.Info("Starting Open WebUI with new version")
	if err := owu.startContainer(ctx); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	state.UpdateSuccess = true
	return nil
}

// backupData creates a backup of Open WebUI data
func (owu *OpenWebUIUpdater) backupData(ctx context.Context) (string, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Creating backup of Open WebUI data")

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("openwebui-backup-%s.tar.gz", timestamp)
	backupPath := filepath.Join(owu.config.BackupDir, backupName)

	logger.Debug("Backup configuration",
		zap.String("backup_dir", owu.config.BackupDir),
		zap.String("backup_name", backupName),
		zap.String("backup_path", backupPath))

	// Pre-flight checks with detailed logging
	logger.Debug("Pre-flight checks starting")

	// Check backup directory exists and is writable
	if info, err := os.Stat(owu.config.BackupDir); err != nil {
		logger.Error("Backup directory does not exist", zap.Error(err))
		return "", fmt.Errorf("backup directory missing: %w", err)
	} else {
		logger.Debug("Backup directory status",
			zap.Bool("is_dir", info.IsDir()),
			zap.String("permissions", info.Mode().String()))
	}

	// Check if Docker volume exists
	volumeCheck, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"volume", "inspect", "open-webui-data"},
		Capture: true,
	})
	if err != nil {
		logger.Error("Docker volume check failed",
			zap.Error(err),
			zap.String("output", volumeCheck))
		return "", fmt.Errorf("open-webui-data volume not found: %s", volumeCheck)
	}
	logger.Debug("Docker volume exists", zap.String("volume", "open-webui-data"))

	// Check if alpine image is available
	imageCheck, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"image", "inspect", "alpine"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Alpine image not found locally, will be pulled automatically",
			zap.String("output", imageCheck))
	} else {
		logger.Debug("Alpine image available locally")
	}

	// Use docker to create tarball of the volume
	// This is safer than accessing /var/lib/docker/volumes directly
	logger.Info("Executing Docker backup command")

	dockerArgs := []string{
		"run", "--rm",
		"--security-opt", "no-new-privileges:true", // Prevent privilege escalation
		"--cap-drop", "ALL", // Drop all capabilities
		"--cap-add", "DAC_OVERRIDE", // Only add minimal capability needed for tar
		"--read-only",       // Read-only root filesystem
		"--network", "none", // No network access needed
		"-v", "open-webui-data:/data:ro", // Mount data volume read-only during backup
		"-v", fmt.Sprintf("%s:/backup", owu.config.BackupDir),
		"alpine",
		"tar", "czf", fmt.Sprintf("/backup/%s", backupName),
		"-C", "/data", ".",
	}

	logger.Debug("Docker command details",
		zap.String("command", "docker"),
		zap.Strings("args", dockerArgs),
		zap.Int("timeout_ms", 5*60*1000))

	// P1 Security Fix: Add container security restrictions
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    dockerArgs,
		Capture: true,
		Timeout: 5 * 60 * 1000, // 5 minutes in milliseconds
	})

	// Log the raw output and error details
	logger.Debug("Docker command completed",
		zap.Bool("success", err == nil),
		zap.String("output", output),
		zap.Int("output_length", len(output)))

	if err != nil {
		logger.Error("Backup command failed",
			zap.Error(err),
			zap.String("docker_output", output),
			zap.Int("output_length", len(output)),
			zap.String("error_type", fmt.Sprintf("%T", err)))

		// Provide detailed error message
		if len(output) == 0 {
			return "", fmt.Errorf("backup command failed with no output (likely container startup failure)\n"+
				"Error: %v\n"+
				"This usually indicates:\n"+
				"  - Docker security restrictions preventing container start\n"+
				"  - Missing alpine image\n"+
				"  - Volume mount permissions issue\n"+
				"Run 'sudo eos debug openwebui' for detailed diagnostics", err)
		}
		return "", fmt.Errorf("backup command failed: %s\nError: %v", output, err)
	}

	logger.Debug("Docker command output captured", zap.String("output", output))

	// Verify backup was created
	info, err := os.Stat(backupPath)
	if err != nil {
		return "", fmt.Errorf("backup file not found after creation: %w", err)
	}

	logger.Info("Backup created successfully",
		zap.String("path", backupPath),
		zap.Int64("size_bytes", info.Size()))

	return backupPath, nil
}

// stopContainer stops the Open WebUI container
func (owu *OpenWebUIUpdater) stopContainer(ctx context.Context) error {
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", owu.config.ComposeFile, "down"},
		Dir:     owu.config.InstallDir,
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to stop container: %s", output)
	}

	return nil
}

// updateComposeFile updates the docker-compose.yml with new version
func (owu *OpenWebUIUpdater) updateComposeFile(ctx context.Context, newVersion string) error {
	logger := otelzap.Ctx(ctx)

	// P1 Security Fix: Validate version tag before using in compose file
	if err := validateVersionTag(newVersion); err != nil {
		return fmt.Errorf("cannot update compose file with invalid version: %w", err)
	}

	// P1 Security Fix: Create backup of compose file before modification
	backupComposePath := owu.config.ComposeFile + ".backup"
	content, err := os.ReadFile(owu.config.ComposeFile)
	if err != nil {
		return fmt.Errorf("failed to read compose file: %w", err)
	}

	// Write backup
	if err := os.WriteFile(backupComposePath, content, shared.ConfigFilePerm); err != nil {
		logger.Warn("Failed to create compose file backup", zap.Error(err))
	} else {
		logger.Debug("Created compose file backup", zap.String("path", backupComposePath))
	}

	// Replace the image version
	oldContent := string(content)
	lines := strings.Split(oldContent, "\n")
	updated := false

	for i, line := range lines {
		if strings.Contains(line, "image:") && strings.Contains(line, "open-webui") {
			// Find the last colon (which is before the version tag)
			// This handles cases like "    image: ghcr.io/open-webui/open-webui:v0.3.32"
			lastColon := strings.LastIndex(line, ":")
			if lastColon != -1 {
				// Replace everything after the last colon
				prefix := line[:lastColon+1]
				lines[i] = prefix + newVersion
				updated = true
				break // Only update the first matching line
			}
		}
	}

	if !updated {
		return fmt.Errorf("could not find open-webui image line to update in docker-compose.yml")
	}

	newContent := strings.Join(lines, "\n")

	// P1 Security Fix: Atomic write using temp file + rename
	tempFile := owu.config.ComposeFile + ".tmp"

	// Write to temp file
	if err := os.WriteFile(tempFile, []byte(newContent), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write temp compose file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempFile, owu.config.ComposeFile); err != nil {
		// Clean up temp file on failure
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to atomically update compose file: %w", err)
	}

	logger.Debug("Compose file updated atomically", zap.String("version", newVersion))
	return nil
}

// pullImage pulls the new Docker image
func (owu *OpenWebUIUpdater) pullImage(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", owu.config.ComposeFile, "pull"},
		Dir:     owu.config.InstallDir,
		Capture: true,
		Timeout: 10 * 60 * 1000, // 10 minutes in milliseconds
	})

	if err != nil {
		// Check if image exists despite error (as in install.go)
		logger.Warn("Docker pull reported an error, checking if image exists", zap.Error(err))

		checkOutput, checkErr := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"images", "ghcr.io/open-webui/open-webui", "--format", "{{.Repository}}:{{.Tag}}"},
			Capture: true,
		})

		if checkErr != nil || !strings.Contains(checkOutput, "open-webui") {
			return fmt.Errorf("failed to pull image: %s\nImage verification failed: %v", output, checkErr)
		}

		logger.Info("Image verified present despite pull warnings")
	}

	return nil
}

// startContainer starts the Open WebUI container
func (owu *OpenWebUIUpdater) startContainer(ctx context.Context) error {
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", owu.config.ComposeFile, "up", "-d"},
		Dir:     owu.config.InstallDir,
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to start container: %s", output)
	}

	return nil
}

// evaluateUpdate verifies the update was successful
func (owu *OpenWebUIUpdater) evaluateUpdate(ctx context.Context, state *UpdateState) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Evaluating update success")

	// Wait a moment for container to start
	time.Sleep(3 * time.Second)

	// Check if container is running
	isRunning, err := owu.isContainerRunning(ctx)
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	if !isRunning {
		return fmt.Errorf("container is not running after update")
	}

	logger.Info("Container is running")

	// Skip health check if requested
	if owu.config.SkipHealthCheck {
		logger.Warn("Health check skipped")
		state.HealthyAfter = true
		return nil
	}

	// Wait for application to be ready (can take 30+ seconds)
	logger.Info("Waiting for application to be ready (this may take up to 1 minute)")
	time.Sleep(10 * time.Second)

	// Check container health
	healthy, err := owu.checkHealth(ctx)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if !healthy {
		return fmt.Errorf("application is not healthy after update")
	}

	state.HealthyAfter = true
	logger.Info("Application is healthy")

	return nil
}

// checkHealth verifies the application is responding
func (owu *OpenWebUIUpdater) checkHealth(ctx context.Context) (bool, error) {
	logger := otelzap.Ctx(ctx)

	// First, verify container is running
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"inspect", "--format", "{{.State.Status}}", "open-webui"},
		Capture: true,
	})

	if err != nil {
		return false, fmt.Errorf("failed to inspect container: %w", err)
	}

	status := strings.TrimSpace(output)
	if status != "running" {
		return false, fmt.Errorf("container status is %s, expected running", status)
	}

	logger.Debug("Container is running, checking application health")

	// Try multiple times with backoff (application might still be starting)
	maxAttempts := 6
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Check health endpoint - Open WebUI exposes /health on internal port 8080
		healthURL := "http://localhost:8080/health"

		// Execute health check inside the container network using docker exec
		healthCheckCmd := fmt.Sprintf("docker exec open-webui wget -q -O- %s", healthURL)
		checkOutput, checkErr := execute.Run(ctx, execute.Options{
			Command: "sh",
			Args:    []string{"-c", healthCheckCmd},
			Capture: true,
		})

		if checkErr == nil && checkOutput != "" {
			logger.Info("Application health check passed", zap.Int("attempt", attempt))
			return true, nil
		}

		logger.Debug("Health check attempt failed",
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", maxAttempts),
			zap.Error(checkErr))

		if attempt < maxAttempts {
			logger.Debug("Waiting before retry", zap.Duration("wait", 10*time.Second))
			time.Sleep(10 * time.Second)
		}
	}

	return false, fmt.Errorf("application failed to respond to health checks after %d attempts", maxAttempts)
}

// rollback restores from backup
func (owu *OpenWebUIUpdater) rollback(ctx context.Context, state *UpdateState) error {
	logger := otelzap.Ctx(ctx)
	logger.Warn("Rolling back to previous version",
		zap.String("backup", state.BackupPath),
		zap.String("previous_version", state.CurrentVersion))

	// Stop current container
	if err := owu.stopContainer(ctx); err != nil {
		logger.Error("Failed to stop container during rollback", zap.Error(err))
	}

	// Restore data from backup
	if state.BackupPath != "" {
		logger.Info("Restoring data from backup")
		if err := owu.RestoreBackup(ctx, state.BackupPath); err != nil {
			return fmt.Errorf("failed to restore backup: %w", err)
		}
	}

	// Revert docker-compose.yml to previous version
	logger.Info("Reverting to previous version", zap.String("version", state.CurrentVersion))
	if err := owu.updateComposeFile(ctx, state.CurrentVersion); err != nil {
		return fmt.Errorf("failed to revert compose file: %w", err)
	}

	// Start container with old version
	logger.Info("Starting container with previous version")
	if err := owu.startContainer(ctx); err != nil {
		return fmt.Errorf("failed to start container after rollback: %w", err)
	}

	// Verify the rollback worked
	logger.Info("Verifying rollback succeeded")
	time.Sleep(10 * time.Second) // Give application time to start

	healthy, err := owu.checkHealth(ctx)
	if err != nil || !healthy {
		return fmt.Errorf("rollback completed but application is not healthy: %v", err)
	}

	logger.Info("Rollback completed successfully and application is healthy")
	return nil
}

// RestoreBackup restores data from a backup tarball (public for use by restore command)
func (owu *OpenWebUIUpdater) RestoreBackup(ctx context.Context, backupPath string) error {
	logger := otelzap.Ctx(ctx)

	// P0 Security Fix: Validate backup path to prevent path traversal attacks
	if err := validateBackupPath(backupPath); err != nil {
		return fmt.Errorf("backup path validation failed: %w", err)
	}

	// Extract directory and filename from the backup path
	// This ensures we mount the correct directory, not just the default BackupDir
	backupDir := filepath.Dir(backupPath)
	backupName := filepath.Base(backupPath)

	logger.Debug("Restoring backup",
		zap.String("backup_dir", backupDir),
		zap.String("backup_name", backupName))

	// P1 Security Fix: Add container security restrictions
	// Extract backup tarball to volume
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args: []string{
			"run", "--rm",
			"--security-opt", "no-new-privileges:true", // Prevent privilege escalation
			"--cap-drop", "ALL", // Drop all capabilities
			"--cap-add", "DAC_OVERRIDE", // Only add minimal capability needed
			"--cap-add", "CHOWN", // Need chown for tar extract
			"--cap-add", "FOWNER", // Need fowner for tar extract
			"--network", "none", // No network access needed
			"-v", "open-webui-data:/data",
			"-v", fmt.Sprintf("%s:/backup:ro", backupDir), // Mount backup directory read-only
			"alpine",
			"sh", "-c",
			fmt.Sprintf("rm -rf /data/* && tar xzf /backup/%s -C /data", backupName),
		},
		Capture: true,
		Timeout: 5 * 60 * 1000, // 5 minutes in milliseconds
	})

	if err != nil {
		return fmt.Errorf("restore command failed: %s", output)
	}

	logger.Info("Data restored from backup successfully")
	return nil
}
