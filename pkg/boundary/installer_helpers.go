package boundary

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
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
func (d *DirectoryManager) CreateWithOwnership(path, user, group string, mode os.FileMode) error {
	// Create directory
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	// Set ownership
	if err := d.runner.Run("chown", "-R", fmt.Sprintf("%s:%s", user, group), path); err != nil {
		return fmt.Errorf("failed to set ownership for %s: %w", path, err)
	}

	// Set permissions
	if err := d.runner.Run("chmod", fmt.Sprintf("%o", mode), path); err != nil {
		return fmt.Errorf("failed to set permissions for %s: %w", path, err)
	}

	return nil
}

// FileManager handles file operations
type FileManager struct {
	runner *CommandRunner
	logger otelzap.LoggerWithCtx
}

// NewFileManager creates a file manager
func NewFileManager(runner *CommandRunner) *FileManager {
	return &FileManager{
		runner: runner,
		logger: runner.logger,
	}
}

// WriteWithOwnership writes a file with specified ownership
func (f *FileManager) WriteWithOwnership(path string, content []byte, mode os.FileMode, user, group string) error {
	// Write file
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	// Set ownership
	if err := f.runner.Run("chown", fmt.Sprintf("%s:%s", user, group), path); err != nil {
		return fmt.Errorf("failed to set ownership for %s: %w", path, err)
	}

	return nil
}

// BackupFile creates a backup of an existing file
func (f *FileManager) BackupFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		return nil // File doesn't exist, no backup needed
	}

	backupPath := fmt.Sprintf("%s.backup.%d", path, time.Now().Unix())
	if err := f.runner.Run("cp", "-p", path, backupPath); err != nil {
		return fmt.Errorf("failed to backup file %s: %w", path, err)
	}

	f.logger.Info("Created backup", zap.String("original", path), zap.String("backup", backupPath))
	return nil
}

// ProgressReporter provides progress updates
type ProgressReporter struct {
	logger      otelzap.LoggerWithCtx
	taskName    string
	totalSteps  int
	currentStep int
}

// NewProgressReporter creates a progress reporter
func NewProgressReporter(logger otelzap.LoggerWithCtx, taskName string, totalSteps int) *ProgressReporter {
	return &ProgressReporter{
		logger:     logger,
		taskName:   taskName,
		totalSteps: totalSteps,
	}
}

// Update reports progress
func (p *ProgressReporter) Update(message string) {
	p.currentStep++
	percentage := (p.currentStep * 100) / p.totalSteps
	p.logger.Info(fmt.Sprintf("terminal prompt: %s", message),
		zap.Int("step", p.currentStep),
		zap.Int("total", p.totalSteps),
		zap.Int("percentage", percentage))
}

// Complete marks the task as complete
func (p *ProgressReporter) Complete(message string) {
	p.logger.Info(fmt.Sprintf("terminal prompt:  %s", message))
}

// Failed marks the task as failed
func (p *ProgressReporter) Failed(message string, err error) {
	p.logger.Error(fmt.Sprintf("terminal prompt: ❌ %s", message), zap.Error(err))
}

// UserHelper manages system users
type UserHelper struct {
	runner *CommandRunner
}

// NewUserHelper creates a user helper
func NewUserHelper(runner *CommandRunner) *UserHelper {
	return &UserHelper{runner: runner}
}

// CreateSystemUser creates a system user for a service
func (u *UserHelper) CreateSystemUser(username, homedir string) error {
	// Check if user exists
	if err := u.runner.RunQuiet("id", username); err == nil {
		// User already exists
		return nil
	}

	// Create system user
	args := []string{
		"--system",
		"--group",
		"--home", homedir,
		"--no-create-home",
		"--shell", "/bin/false",
		username,
	}

	if err := u.runner.Run("useradd", args...); err != nil {
		// Check if user was created by another process
		if err := u.runner.RunQuiet("id", username); err == nil {
			return nil
		}
		return fmt.Errorf("failed to create user %s: %w", username, err)
	}

	return nil
}

// ValidationHelper provides validation utilities
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

// RequireRoot checks if running as root
func (v *ValidationHelper) RequireRoot() {
	if os.Geteuid() != 0 {
		v.errors = append(v.errors, "must be run as root")
	}
}

// RequireCommand checks if a command exists
func (v *ValidationHelper) RequireCommand(command string) {
	if _, err := exec.LookPath(command); err != nil {
		v.errors = append(v.errors, fmt.Sprintf("required command not found: %s", command))
	}
}

// CheckPort validates port availability
func (v *ValidationHelper) CheckPort(port int) {
	// Simple check - actual implementation would use net.Listen
	if port < 1 || port > 65535 {
		v.errors = append(v.errors, fmt.Sprintf("invalid port: %d", port))
	}
}

// HasErrors returns true if validation errors exist
func (v *ValidationHelper) HasErrors() bool {
	return len(v.errors) > 0
}

// GetError returns combined validation errors
func (v *ValidationHelper) GetError() error {
	if !v.HasErrors() {
		return nil
	}
	return fmt.Errorf("validation failed: %s", strings.Join(v.errors, "; "))
}

// HTTPClient provides HTTP client functionality
type HTTPClient struct {
	client *http.Client
}

// NewHTTPClient creates an HTTP client with timeout
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  true,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}
}

// Get performs an HTTP GET request
func (h *HTTPClient) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return h.client.Do(req)
}
