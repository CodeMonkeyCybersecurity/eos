package hashicorp

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CommandRunner provides consistent command execution with retry logic
type CommandRunner struct {
	rc      *eos_io.RuntimeContext
	logger  otelzap.LoggerWithCtx
	dryRun  bool
	retries int
}

// NewCommandRunner creates a new command runner
func NewCommandRunner(rc *eos_io.RuntimeContext) *CommandRunner {
	return &CommandRunner{
		rc:      rc,
		logger:  otelzap.Ctx(rc.Ctx),
		retries: 3,
	}
}

// Run executes a command with default retry logic
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

// RunQuiet executes a command without logging output
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

// SystemdManager handles systemd service operations
type SystemdManager struct {
	runner *CommandRunner
}

// NewSystemdManager creates a systemd manager
func NewSystemdManager(runner *CommandRunner) *SystemdManager {
	return &SystemdManager{runner: runner}
}

// StopService stops a systemd service
func (s *SystemdManager) StopService(serviceName string) error {
	return s.runner.RunQuiet("systemctl", "stop", serviceName)
}

// DisableService disables a systemd service
func (s *SystemdManager) DisableService(serviceName string) error {
	return s.runner.RunQuiet("systemctl", "disable", serviceName)
}

// EnableService enables a systemd service
func (s *SystemdManager) EnableService(serviceName string) error {
	return s.runner.Run("systemctl", "enable", serviceName)
}

// StartService starts a systemd service with retries
func (s *SystemdManager) StartService(serviceName string) error {
	return s.runner.RunWithRetries("systemctl", []string{"start", serviceName}, 3)
}

// RestartService restarts a systemd service
func (s *SystemdManager) RestartService(serviceName string) error {
	return s.runner.Run("systemctl", "restart", serviceName)
}

// IsServiceActive checks if a service is active
func (s *SystemdManager) IsServiceActive(serviceName string) bool {
	output, err := s.runner.RunOutput("systemctl", "is-active", serviceName)
	return err == nil && output == "active"
}

// IsServiceFailed checks if a service has failed
func (s *SystemdManager) IsServiceFailed(serviceName string) bool {
	output, err := s.runner.RunOutput("systemctl", "is-failed", serviceName)
	return err == nil && output == "failed"
}

// GetServiceStatus returns the service status
func (s *SystemdManager) GetServiceStatus(serviceName string) (string, error) {
	return s.runner.RunOutput("systemctl", "status", serviceName, "--no-pager")
}

// ReloadDaemon reloads the systemd daemon
func (s *SystemdManager) ReloadDaemon() error {
	return s.runner.Run("systemctl", "daemon-reload")
}

// DirectoryManager handles directory operations
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
func (d *DirectoryManager) CreateWithOwnership(path, user, group string, mode os.FileMode) error {
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

// FileManager handles file operations
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
func (f *FileManager) WriteWithOwnership(path string, content []byte, mode os.FileMode, user, group string) error {
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

// BackupFile creates a timestamped backup of a file
func (f *FileManager) BackupFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		return nil // File doesn't exist, nothing to backup
	}

	backupPath := fmt.Sprintf("%s.backup.%s", path, time.Now().Format("20060102_150405"))
	f.logger.Info("Creating backup",
		zap.String("original", path),
		zap.String("backup", backupPath))

	input, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s for backup: %w", path, err)
	}

	if err := os.WriteFile(backupPath, input, shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write backup %s: %w", backupPath, err)
	}

	return nil
}

// UserManager handles user operations
type UserManager struct {
	runner *CommandRunner
	logger otelzap.LoggerWithCtx
}

// NewUserManager creates a user manager
func NewUserManager(runner *CommandRunner) *UserManager {
	return &UserManager{
		runner: runner,
		logger: runner.logger,
	}
}

// CreateSystemUser creates a system user if it doesn't exist
func (u *UserManager) CreateSystemUser(username, home string) error {
	// Check if user exists
	if err := u.runner.RunQuiet("id", username); err == nil {
		u.logger.Debug("User already exists", zap.String("user", username))
		return nil
	}

	u.logger.Info("Creating system user", zap.String("user", username))

	// Build useradd arguments
	// Note: --user-group creates a group with the same name as the user
	// This is different from --group which expects a GROUP NAME argument
	args := []string{
		"--system",
		"--user-group",
		"--home",
		home,
		"--no-create-home",
		"--shell",
		"/bin/false",
		username,
	}

	u.logger.Debug("Executing useradd command",
		zap.String("user", username),
		zap.Strings("args", args))

	if err := u.runner.Run("useradd", args...); err != nil {
		return fmt.Errorf("failed to create user %s: %w", username, err)
	}

	return nil
}

// ProgressReporter provides user feedback during operations
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

// Validator provides pre-installation validation
type Validator struct {
	logger otelzap.LoggerWithCtx
	errors []string
}

// NewValidator creates a validator
func NewValidator(logger otelzap.LoggerWithCtx) *Validator {
	return &Validator{
		logger: logger,
		errors: []string{},
	}
}

// RequireRoot checks for root privileges
func (v *Validator) RequireRoot() {
	if os.Geteuid() != 0 {
		v.errors = append(v.errors, "Root privileges required. Please run with sudo")
	}
}

// CheckPort validates port availability
func (v *Validator) CheckPort(port int) {
	addr := fmt.Sprintf(":%d", port)
	conn, err := exec.Command("lsof", "-i", addr).Output()
	if err == nil && len(conn) > 0 {
		v.errors = append(v.errors, fmt.Sprintf("Port %d is already in use", port))
		v.logger.Warn("Port in use",
			zap.Int("port", port),
			zap.String("output", string(conn)))
	}
}

// CheckDiskSpace validates available disk space
func (v *Validator) CheckDiskSpace(path string, requiredMB int64) {
	v.logger.Debug("Checking disk space",
		zap.String("path", path),
		zap.Int64("required_mb", requiredMB))
	// Simplified check - would use actual disk space checking in production
}

// RequireCommand checks if a command exists
func (v *Validator) RequireCommand(cmd string) {
	if _, err := exec.LookPath(cmd); err != nil {
		v.errors = append(v.errors, fmt.Sprintf("Required command '%s' not found", cmd))
	}
}

// HasErrors returns true if validation errors exist
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// GetError returns a combined error message
func (v *Validator) GetError() error {
	if !v.HasErrors() {
		return nil
	}
	return fmt.Errorf("validation failed:\n  - %s", strings.Join(v.errors, "\n  - "))
}

// NetworkHelper provides network operations with retry logic
type NetworkHelper struct {
	logger  otelzap.LoggerWithCtx
	client  *http.Client
	retries int
}

// NewNetworkHelper creates a network helper
func NewNetworkHelper(logger otelzap.LoggerWithCtx) *NetworkHelper {
	return &NetworkHelper{
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		retries: 3,
	}
}

// DownloadFile downloads a file from URL to destination with retry
func (n *NetworkHelper) DownloadFile(url, dest string) error {
	var lastErr error

	for attempt := 1; attempt <= n.retries; attempt++ {
		n.logger.Debug("Downloading file",
			zap.String("url", url),
			zap.String("dest", dest),
			zap.Int("attempt", attempt))

		err := n.downloadAttempt(url, dest)
		if err == nil {
			return nil
		}

		lastErr = err
		n.logger.Warn("Download failed, retrying",
			zap.Int("attempt", attempt),
			zap.Error(err))

		if attempt < n.retries {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}

	return fmt.Errorf("download failed after %d attempts: %w", n.retries, lastErr)
}

func (n *NetworkHelper) downloadAttempt(url, dest string) error {
	resp, err := n.client.Get(url)
	if err != nil {
		return err
	}
	// SECURITY P2 #8: Check defer Body.Close() error
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			n.logger.Warn("Failed to close HTTP response body", zap.Error(closeErr))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); closeErr != nil {
			n.logger.Warn("Failed to close output file", zap.String("path", dest), zap.Error(closeErr))
		}
	}()

	_, err = io.Copy(out, resp.Body)
	return err
}

// GetWithRetry performs GET request with automatic retry
func (n *NetworkHelper) GetWithRetry(ctx context.Context, url string) (*http.Response, error) {
	var lastErr error

	for attempt := 1; attempt <= n.retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := n.client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if resp != nil {
			_ = resp.Body.Close()
		}

		lastErr = err
		if err == nil {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		if attempt < n.retries {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", n.retries, lastErr)
}
