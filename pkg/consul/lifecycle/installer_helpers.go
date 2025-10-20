package lifecycle

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// CommandRunner provides a consistent interface for running commands with retry logic
type CommandRunner struct {
	rc      *eos_io.RuntimeContext
	logger  otelzap.LoggerWithCtx
	dryRun  bool
	retries int
}

// NewCommandRunner creates a new command runner with default retry settings
func NewCommandRunner(rc *eos_io.RuntimeContext) *CommandRunner {
	return &CommandRunner{
		rc:      rc,
		logger:  otelzap.Ctx(rc.Ctx),
		retries: 3,
	}
}

// Run executes a command with retry logic and proper error handling
func (r *CommandRunner) Run(name string, args ...string) error {
	return r.RunWithRetries(name, args, r.retries)
}

// RunWithRetries executes a command with custom retry count
func (r *CommandRunner) RunWithRetries(name string, args []string, maxRetries int) error {
	r.logger.Debug("Executing command",
		zap.String("command", name),
		zap.Strings("args", args))

	if r.dryRun {
		r.logger.Info("DRY RUN: Would execute",
			zap.String("command", name),
			zap.Strings("args", args))
		return nil
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		output, err := execute.Run(r.rc.Ctx, execute.Options{
			Command: name,
			Args:    args,
			Capture: true,
		})

		if err == nil {
			r.logger.Debug("Command succeeded",
				zap.String("command", name),
				zap.Int("attempt", attempt))
			return nil
		}

		lastErr = err
		r.logger.Warn("Command failed, retrying",
			zap.String("command", name),
			zap.Int("attempt", attempt),
			zap.Int("max_retries", maxRetries),
			zap.Error(err),
			zap.String("output", output))

		if attempt < maxRetries {
			backoff := time.Duration(attempt) * time.Second
			time.Sleep(backoff)
		}
	}

	return fmt.Errorf("command failed after %d attempts: %w", maxRetries, lastErr)
}

// RunOutput executes a command and returns its output
func (r *CommandRunner) RunOutput(name string, args ...string) (string, error) {
	r.logger.Debug("Executing command for output",
		zap.String("command", name),
		zap.Strings("args", args))

	if r.dryRun {
		r.logger.Info("DRY RUN: Would execute for output",
			zap.String("command", name),
			zap.Strings("args", args))
		return "", nil
	}

	output, err := execute.Run(r.rc.Ctx, execute.Options{
		Command: name,
		Args:    args,
		Capture: true,
	})

	if err != nil {
		return "", fmt.Errorf("command failed: %w", err)
	}

	return strings.TrimSpace(output), nil
}

// RunQuiet executes a command without logging output (for checks)
func (r *CommandRunner) RunQuiet(name string, args ...string) error {
	if r.dryRun {
		return nil
	}

	_, err := execute.Run(r.rc.Ctx, execute.Options{
		Command: name,
		Args:    args,
		Capture: true,
	})
	return err
}

// SystemdService provides consistent systemd operations
type SystemdService struct {
	runner *CommandRunner
	name   string
}

// NewSystemdService creates a systemd service manager
func NewSystemdService(runner *CommandRunner, serviceName string) *SystemdService {
	return &SystemdService{
		runner: runner,
		name:   serviceName,
	}
}

// Stop stops the service
func (s *SystemdService) Stop() error {
	return s.runner.RunQuiet("systemctl", "stop", s.name)
}

// Disable disables the service
func (s *SystemdService) Disable() error {
	return s.runner.RunQuiet("systemctl", "disable", s.name)
}

// Enable enables the service
func (s *SystemdService) Enable() error {
	return s.runner.Run("systemctl", "enable", s.name)
}

// Start starts the service with retries
func (s *SystemdService) Start() error {
	return s.runner.RunWithRetries("systemctl", []string{"start", s.name}, 3)
}

// Restart restarts the service
func (s *SystemdService) Restart() error {
	return s.runner.Run("systemctl", "restart", s.name)
}

// IsActive checks if the service is active
func (s *SystemdService) IsActive() bool {
	output, err := s.runner.RunOutput("systemctl", "is-active", s.name)
	return err == nil && output == "active"
}

// IsFailed checks if the service is failed
func (s *SystemdService) IsFailed() bool {
	output, err := s.runner.RunOutput("systemctl", "is-failed", s.name)
	return err == nil && output == "failed"
}

// GetStatus returns the service status
func (s *SystemdService) GetStatus() (string, error) {
	return s.runner.RunOutput("systemctl", "status", s.name, "--no-pager")
}

// ReloadDaemon reloads systemd daemon
func (s *SystemdService) ReloadDaemon() error {
	return s.runner.Run("systemctl", "daemon-reload")
}

// DirectoryManager handles directory operations consistently
type DirectoryManager struct {
	runner *CommandRunner
	logger otelzap.LoggerWithCtx
}

// NewDirectoryManager creates a directory manager
func NewDirectoryManager(runner *CommandRunner) *DirectoryManager {
	return &DirectoryManager{
		runner: runner,
		logger: runner.logger,
	}
}

// CreateWithOwnership creates a directory with specified ownership
func (d *DirectoryManager) CreateWithOwnership(path string, user string, group string, mode os.FileMode) error {
	d.logger.Debug("Creating directory",
		zap.String("path", path),
		zap.String("user", user),
		zap.String("group", group),
		zap.Uint32("mode", uint32(mode)))

	// Create directory
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	// Set ownership
	if user != "" && group != "" {
		if err := d.runner.Run("chown", fmt.Sprintf("%s:%s", user, group), path); err != nil {
			return fmt.Errorf("failed to set ownership for %s: %w", path, err)
		}
	}

	return nil
}

// RemoveIfExists removes a directory if it exists
func (d *DirectoryManager) RemoveIfExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		d.logger.Debug("Removing directory", zap.String("path", path))
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
	}
	return nil
}

// FileManager handles file operations consistently
type FileManager struct {
	logger otelzap.LoggerWithCtx
	runner *CommandRunner
}

// NewFileManager creates a file manager
func NewFileManager(runner *CommandRunner) *FileManager {
	return &FileManager{
		logger: runner.logger,
		runner: runner,
	}
}

// WriteWithOwnership writes a file with specified ownership
func (f *FileManager) WriteWithOwnership(path string, content []byte, mode os.FileMode, user string, group string) error {
	f.logger.Debug("Writing file",
		zap.String("path", path),
		zap.Int("size", len(content)),
		zap.Uint32("mode", uint32(mode)))

	// Write file
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	// Set ownership
	if user != "" && group != "" {
		if err := f.runner.Run("chown", fmt.Sprintf("%s:%s", user, group), path); err != nil {
			return fmt.Errorf("failed to set ownership for %s: %w", path, err)
		}
	}

	return nil
}

// BackupFile creates a timestamped backup of a file with rotation (keeps max 5 backups)
func (f *FileManager) BackupFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		return nil // File doesn't exist, nothing to backup
	}

	// Clean old backups first (keep max 5)
	if err := f.cleanOldBackups(path, 5); err != nil {
		f.logger.Warn("Failed to clean old backups", zap.Error(err))
	}

	backupPath := fmt.Sprintf("%s.backup.%s", path, time.Now().Format("20060102_150405"))
	f.logger.Info("Creating backup",
		zap.String("original", path),
		zap.String("backup", backupPath))

	input, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s for backup: %w", path, err)
	}

	if err := os.WriteFile(backupPath, input, 0644); err != nil {
		return fmt.Errorf("failed to write backup %s: %w", backupPath, err)
	}

	return nil
}

// cleanOldBackups removes old backup files, keeping only the most recent maxBackups
func (f *FileManager) cleanOldBackups(originalPath string, maxBackups int) error {
	dir := filepath.Dir(originalPath)
	baseName := filepath.Base(originalPath)
	backupPattern := baseName + ".backup.*"

	// Find all backup files
	pattern := filepath.Join(dir, backupPattern)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to find backup files: %w", err)
	}

	// If we have fewer backups than the max, nothing to clean
	if len(matches) < maxBackups {
		return nil
	}

	// Sort backups by modification time (oldest first)
	type backupInfo struct {
		path    string
		modTime time.Time
	}

	var backups []backupInfo
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		backups = append(backups, backupInfo{
			path:    match,
			modTime: info.ModTime(),
		})
	}

	// Sort by modification time (oldest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.Before(backups[j].modTime)
	})

	// Delete oldest backups, keeping only maxBackups-1 (to make room for new one)
	toDelete := len(backups) - (maxBackups - 1)
	if toDelete <= 0 {
		return nil
	}

	for i := 0; i < toDelete; i++ {
		if err := os.Remove(backups[i].path); err != nil {
			f.logger.Warn("Failed to remove old backup",
				zap.String("path", backups[i].path),
				zap.Error(err))
		} else {
			f.logger.Debug("Removed old backup",
				zap.String("path", backups[i].path))
		}
	}

	return nil
}

// ProgressReporter provides user feedback during long operations
type ProgressReporter struct {
	logger  otelzap.LoggerWithCtx
	current int
	total   int
	prefix  string
}

// NewProgressReporter creates a progress reporter
func NewProgressReporter(logger otelzap.LoggerWithCtx, prefix string, total int) *ProgressReporter {
	return &ProgressReporter{
		logger:  logger,
		prefix:  prefix,
		total:   total,
		current: 0,
	}
}

// Update updates and reports progress
func (p *ProgressReporter) Update(message string) {
	p.current++
	percentage := (p.current * 100) / p.total
	p.logger.Info(fmt.Sprintf("terminal prompt: [%d%%] %s: %s", percentage, p.prefix, message))
}

// Complete marks the operation as complete
func (p *ProgressReporter) Complete(message string) {
	p.logger.Info(fmt.Sprintf("terminal prompt: ✓ %s: %s", p.prefix, message))
}

// Failed marks the operation as failed
func (p *ProgressReporter) Failed(message string, err error) {
	p.logger.Error(fmt.Sprintf("terminal prompt: ✗ %s: %s", p.prefix, message),
		zap.Error(err))
}

// UserHelper provides consistent user management
type UserHelper struct {
	runner *CommandRunner
	logger otelzap.LoggerWithCtx
}

// NewUserHelper creates a user helper
func NewUserHelper(runner *CommandRunner) *UserHelper {
	return &UserHelper{
		runner: runner,
		logger: runner.logger,
	}
}

// CreateSystemUser creates a system user if it doesn't exist
// This delegates to the centralized hashicorp.UserManager implementation
func (u *UserHelper) CreateSystemUser(username string, home string) error {
	// Create a hashicorp.CommandRunner from our RuntimeContext
	hashicorpRunner := hashicorp.NewCommandRunner(u.runner.rc)
	userMgr := hashicorp.NewUserManager(hashicorpRunner)
	return userMgr.CreateSystemUser(username, home)
}

// ValidationHelper provides pre-installation validation
type ValidationHelper struct {
	logger otelzap.LoggerWithCtx
	errors []string
}

// NewValidationHelper creates a validation helper
func NewValidationHelper(logger otelzap.LoggerWithCtx) *ValidationHelper {
	return &ValidationHelper{
		logger: logger,
		errors: []string{},
	}
}

// ValidatePort checks if a port is available
func (v *ValidationHelper) ValidatePort(port int) {
	addr := fmt.Sprintf(":%d", port)
	conn, err := exec.Command("lsof", "-i", addr).Output()
	if err == nil && len(conn) > 0 {
		v.errors = append(v.errors, fmt.Sprintf("Port %d is already in use", port))
		v.logger.Warn("Port in use",
			zap.Int("port", port),
			zap.String("output", string(conn)))
	}
}

// ValidateDiskSpace checks available disk space
func (v *ValidationHelper) ValidateDiskSpace(path string, requiredMB int64) {
	// This would use actual disk space checking
	// For now, just a placeholder
	v.logger.Debug("Checking disk space",
		zap.String("path", path),
		zap.Int64("required_mb", requiredMB))
}

// ValidatePermissions checks if we have required permissions
func (v *ValidationHelper) ValidatePermissions() {
	if os.Geteuid() != 0 {
		v.errors = append(v.errors, "Root privileges required")
	}
}

// HasErrors returns true if validation errors exist
func (v *ValidationHelper) HasErrors() bool {
	return len(v.errors) > 0
}

// GetErrors returns all validation errors
func (v *ValidationHelper) GetErrors() []string {
	return v.errors
}

// GetError returns a combined error message
func (v *ValidationHelper) GetError() error {
	if !v.HasErrors() {
		return nil
	}
	return fmt.Errorf("validation failed:\n  - %s", strings.Join(v.errors, "\n  - "))
}

// NetworkHelper provides network operation helpers with retry logic
type NetworkHelper struct {
	client  *HTTPClient
	logger  otelzap.LoggerWithCtx
	timeout time.Duration
}

// HTTPClient wraps http.Client with retry logic
type HTTPClient struct {
	client    *http.Client
	maxRetry  int
	retryWait time.Duration
}

// NewHTTPClient creates a new HTTP client with retry logic
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
		maxRetry:  3,
		retryWait: 2 * time.Second,
	}
}

// GetWithRetry performs GET request with automatic retry
func (h *HTTPClient) GetWithRetry(ctx context.Context, url string) (*http.Response, error) {
	var lastErr error

	for attempt := 1; attempt <= h.maxRetry; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := h.client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if resp != nil {
			resp.Body.Close()
		}

		lastErr = err
		if err == nil {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		if attempt < h.maxRetry {
			time.Sleep(h.retryWait * time.Duration(attempt))
		}
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", h.maxRetry, lastErr)
}

// File operations helpers for ConsulInstaller

func (ci *ConsulInstaller) writeFile(path string, content []byte, mode os.FileMode) error {
	return os.WriteFile(path, content, mode)
}

func (ci *ConsulInstaller) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (ci *ConsulInstaller) createDirectory(path string, mode os.FileMode) error {
	// CRITICAL: Check if path is on network mount before creating
	// Network mounts can cause data loss during network outages
	isNetwork, err := isNetworkMount(path)
	if err != nil {
		ci.logger.Warn("Could not check if path is on network mount",
			zap.String("path", path),
			zap.Error(err))
	} else if isNetwork {
		return fmt.Errorf("refusing to create directory on network mount: %s\nNetwork mounts can cause data loss during outages. Use local storage for Consul data.", path)
	}

	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	ci.logger.Info("Created directory",
		zap.String("path", path),
		zap.String("mode", mode.String()))

	return nil
}

// HTTP operations

// httpGet performs HTTP GET request with proper error wrapping and context handling
func (ci *ConsulInstaller) httpGet(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return body, nil
}

// createLogrotateConfig creates a logrotate configuration for Consul logs
func (ci *ConsulInstaller) createLogrotateConfig() error {
	logrotateConfig := `/var/log/consul/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 consul consul
    sharedscripts
    postrotate
        systemctl reload consul > /dev/null 2>&1 || true
    endscript
}
`

	if err := ci.writeFile("/etc/logrotate.d/consul", []byte(logrotateConfig), 0644); err != nil {
		return fmt.Errorf("failed to create logrotate config: %w", err)
	}

	ci.logger.Info("Created logrotate configuration")
	return nil
}

// Network detection helpers

// getDefaultBindAddr detects the primary network interface IP
// Returns error if no valid interface found (fail-closed)
func getDefaultBindAddr() (string, error) {
	cmd := exec.Command("hostname", "-I")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to detect network interfaces: %w", err)
	}

	// Get first non-loopback IP
	ips := strings.Fields(string(output))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" && !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "::1") {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no valid network interface found (only loopback detected)")
}

// isNetworkMount checks if a path is on a network filesystem
func isNetworkMount(path string) (bool, error) {
	// Get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	// Get filesystem type
	var stat unix.Statfs_t
	if err := unix.Statfs(absPath, &stat); err != nil {
		return false, err
	}

	// Check for network filesystem types
	// NFS: 0x6969, CIFS: 0xFF534D42, etc.
	networkFsTypes := map[int64]string{
		0x6969:     "NFS",
		0xFF534D42: "CIFS/SMB",
		0x01021994: "TMPFS", // Not network but also problematic for persistent data
	}

	fsType := int64(stat.Type)
	if fsName, isNetwork := networkFsTypes[fsType]; isNetwork {
		return true, fmt.Errorf("filesystem type: %s", fsName)
	}

	return false, nil
}
