// pkg/bootstrap/common.go
//
// Common utilities and patterns for bootstrap operations.
// This file consolidates shared functionality to reduce duplication.

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceStatus represents the status of a system service
type ServiceStatus string

const (
	ServiceStatusActive   ServiceStatus = "active"
	ServiceStatusInactive ServiceStatus = "inactive"
	ServiceStatusFailed   ServiceStatus = "failed"
	ServiceStatusUnknown  ServiceStatus = "unknown"
)

// ErrorClass categorizes errors for retry decision-making
type ErrorClass int

const (
	// ErrorTransient indicates a temporary failure that should be retried
	// Examples: network timeouts, temporary locks, resource temporarily unavailable
	ErrorTransient ErrorClass = iota

	// ErrorPermanent indicates a configuration or logic error that won't be fixed by retrying
	// Examples: validation failures, missing files, permission denied, bind address in use
	ErrorPermanent

	// ErrorAmbiguous indicates an unknown error that should be retried cautiously (max 2 attempts)
	// Examples: unfamiliar error messages, errors that don't match known patterns
	ErrorAmbiguous
)

// String returns the string representation of ErrorClass
func (ec ErrorClass) String() string {
	switch ec {
	case ErrorTransient:
		return "Transient"
	case ErrorPermanent:
		return "Permanent"
	case ErrorAmbiguous:
		return "Ambiguous"
	default:
		return "Unknown"
	}
}

// ClassifyError categorizes an error to determine if it should be retried
// It recursively unwraps errors and checks all levels for known patterns
//
// Pattern Matching Strategy:
// 1. Check PERMANENT patterns first (fail fast is safer than wasting time)
// 2. Check TRANSIENT patterns second (known retry-able errors)
// 3. Default to AMBIGUOUS (retry cautiously when uncertain)
//
// This function uses case-insensitive partial matching to handle:
// - Error message variations across versions
// - Wrapped errors with context
// - Non-exact wording changes
func ClassifyError(err error) ErrorClass {
	if err == nil {
		return ErrorTransient // No error = success = transient issue resolved
	}

	// Collect all error messages in the chain for pattern matching
	var messages []string
	currentErr := err
	for currentErr != nil {
		msg := strings.ToLower(currentErr.Error())
		if msg != "" {
			messages = append(messages, msg)
		}
		currentErr = errors.Unwrap(currentErr)
	}

	// If no messages found, can't classify reliably
	if len(messages) == 0 {
		return ErrorAmbiguous
	}

	// Check all messages in the error chain
	for _, msg := range messages {
		// PERMANENT patterns - configuration/logic errors that won't fix themselves
		// These should fail fast to give user actionable feedback
		permanentPatterns := []string{
			"validat",      // validation failed, config validation error
			"not found",    // file not found, service not found, device not found
			"no such",      // no such file, no such directory
			"does not exist",
			"permission denied",
			"access denied",
			"forbidden",
			"unauthorized",
			"address already in use", // Port conflicts
			"bind: address already in use",
			"cannot bind",
			"masked",               // systemd masked service
			"command not found",    // Missing executables
			"executable not found", // Missing binaries
			"invalid",              // invalid configuration, invalid argument
			"malformed",            // Malformed config files
			"syntax error",         // Config file syntax
			"parse error",          // Config parsing failures
			"multiple private",     // Consul multi-interface error
			"multiple.*address",    // Generic multi-address errors
			"incompatible",         // Version mismatches
			"unsupported",          // Feature not supported
		}

		for _, pattern := range permanentPatterns {
			if strings.Contains(msg, pattern) {
				return ErrorPermanent
			}
		}

		// TRANSIENT patterns - temporary failures that are safe to retry
		// These are environmental issues that may resolve on their own
		transientPatterns := []string{
			"timeout",       // Network timeouts, operation timeouts
			"timed out",     // Alternative timeout phrasing
			"connection refused",
			"connection reset",
			"connection closed",
			"network unreachable",
			"host unreachable",
			"no route to host",
			"temporary failure", // DNS and other temporary failures
			"try again",         // EAGAIN, EWOULDBLOCK
			"resource temporarily unavailable",
			"too many open files", // Might resolve if files close
			"service unavailable",
			"503",                     // HTTP 503 Service Unavailable
			"dial tcp",                // Network dial errors
			"i/o timeout",             // I/O operation timeout
			"deadline exceeded",       // Context deadline exceeded
			"lock",                    // Lock contention (might release)
			"busy",                    // Resource busy
			"connection pool exhausted", // Might free up
		}

		for _, pattern := range transientPatterns {
			if strings.Contains(msg, pattern) {
				return ErrorTransient
			}
		}
	}

	// If no patterns matched, classify as ambiguous
	// This is the safe default: retry cautiously rather than give up or retry aggressively
	return ErrorAmbiguous
}

// RetryConfig defines retry behavior for operations
type RetryConfig struct {
	MaxAttempts int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	BackoffMultiplier float64
}

// DefaultRetryConfig returns sensible defaults for retry operations
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      2 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// ServiceRetryConfig returns retry config optimized for service operations
func ServiceRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:       5,
		InitialDelay:      5 * time.Second,
		MaxDelay:          60 * time.Second,
		BackoffMultiplier: 1.5,
	}
}

// WithRetry executes an operation with exponential backoff retry logic
// It uses error classification to determine if retrying makes sense:
// - Permanent errors: Fail immediately (no retry)
// - Transient errors: Retry with full backoff (network issues, etc.)
// - Ambiguous errors: Retry cautiously (max 2 attempts)
func WithRetry(rc *eos_io.RuntimeContext, config RetryConfig, operation func() error) error {
	logger := otelzap.Ctx(rc.Ctx)

	delay := config.InitialDelay
	var lastErr error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		logger.Debug("Attempting operation",
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", config.MaxAttempts))

		// Execute the operation
		err := operation()
		if err == nil {
			if attempt > 1 {
				logger.Info("Operation succeeded after retry",
					zap.Int("attempts", attempt))
			}
			return nil
		}

		lastErr = err

		// Classify the error to determine retry strategy
		errorClass := ClassifyError(err)

		logger.Debug("Error classification",
			zap.String("class", errorClass.String()),
			zap.Error(err))

		// PERMANENT errors - fail fast, don't waste time retrying
		if errorClass == ErrorPermanent {
			logger.Error("Operation failed with permanent error (not retrying)",
				zap.Error(err),
				zap.String("error_class", errorClass.String()),
				zap.String("reason", "Configuration or logic error that won't fix itself"))
			return fmt.Errorf("permanent error (not retrying): %w", err)
		}

		// AMBIGUOUS errors - retry cautiously (max 2 attempts total)
		if errorClass == ErrorAmbiguous && attempt >= 2 {
			logger.Warn("Operation failed with ambiguous error (retry limit reached)",
				zap.Error(err),
				zap.String("error_class", errorClass.String()),
				zap.Int("attempt", attempt),
				zap.String("reason", "Unknown error type, limited to 2 retry attempts"))
			return fmt.Errorf("ambiguous error after %d attempts: %w", attempt, err)
		}

		// If we've reached max attempts, fail
		if attempt >= config.MaxAttempts {
			logger.Error("Operation failed after max attempts",
				zap.Error(err),
				zap.String("error_class", errorClass.String()),
				zap.Int("attempts", attempt))
			return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, err)
		}

		// TRANSIENT or AMBIGUOUS (attempt 1) - retry with backoff
		logger.Warn("Operation failed, will retry",
			zap.Error(err),
			zap.String("error_class", errorClass.String()),
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", config.MaxAttempts),
			zap.Duration("retry_delay", delay),
			zap.String("reason", getRetryReason(errorClass)))

		// Sleep with context cancellation support
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-rc.Ctx.Done():
			return fmt.Errorf("operation cancelled during retry: %w", rc.Ctx.Err())
		}

		// Calculate next delay with exponential backoff
		delay = time.Duration(float64(delay) * config.BackoffMultiplier)
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// getRetryReason returns a human-readable reason for why we're retrying
func getRetryReason(class ErrorClass) string {
	switch class {
	case ErrorTransient:
		return "Transient error (network/timing issue, likely to succeed on retry)"
	case ErrorAmbiguous:
		return "Ambiguous error (unknown cause, retrying cautiously)"
	case ErrorPermanent:
		return "Permanent error (should not retry)"
	default:
		return "Unknown error classification"
	}
}

// CheckService checks if a systemd service is active
func CheckService(rc *eos_io.RuntimeContext, serviceName string) (ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking service status", zap.String("service", serviceName))

	isActive, err := SystemctlIsActive(rc, serviceName)
	if err == nil && isActive {
		return ServiceStatusActive, nil
	}

	// Get more detailed status for non-active services
	status, _ := SystemctlGetStatus(rc, serviceName)

	if strings.Contains(status, "inactive") {
		return ServiceStatusInactive, nil
	}
	if strings.Contains(status, "failed") {
		return ServiceStatusFailed, nil
	}

	if err != nil {
		logger.Debug("Service check failed",
			zap.String("service", serviceName),
			zap.Error(err))
	}

	return ServiceStatusUnknown, err
}

// EnsureService ensures a systemd service is running, starting it if necessary
func EnsureService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Ensuring service is running", zap.String("service", serviceName))

	// ASSESS - Check if service unit file exists
	output, err := SystemctlListUnitFiles(rc, serviceName)
	if err != nil || !strings.Contains(output, serviceName) {
		return fmt.Errorf("service unit file not found for %s", serviceName)
	}

	// Check if service is masked
	if strings.Contains(output, "masked") {
		return fmt.Errorf("service %s is masked and cannot be started", serviceName)
	}

	// ASSESS - Check current status
	status, err := CheckService(rc, serviceName)
	if err == nil && status == ServiceStatusActive {
		logger.Debug("Service is already active", zap.String("service", serviceName))
		return nil
	}

	// INTERVENE - Enable and start the service
	logger.Info("Starting service", zap.String("service", serviceName))

	// Enable the service first
	if err := SystemctlEnable(rc, serviceName); err != nil {
		logger.Warn("Failed to enable service",
			zap.String("service", serviceName),
			zap.Error(err))
		// Continue anyway - service might still start
	}

	// Start the service
	if err := SystemctlStart(rc, serviceName); err != nil {
		return err // Error already includes context from SystemctlStart
	}

	// EVALUATE - Verify service is running with retry
	return WithRetry(rc, ServiceRetryConfig(), func() error {
		status, err := CheckService(rc, serviceName)
		if err != nil {
			return fmt.Errorf("failed to check service status: %w", err)
		}

		if status != ServiceStatusActive {
			return fmt.Errorf("service %s is not active (status: %s)", serviceName, status)
		}

		logger.Info("Service is now active", zap.String("service", serviceName))
		return nil
	})
}

// CheckCommand checks if a command exists in PATH
func CheckCommand(command string) error {
	if _, err := exec.LookPath(command); err != nil {
		return eos_err.NewUserError("%s not found in PATH", command)
	}
	return nil
}

// CheckMultipleCommands checks if multiple commands exist
func CheckMultipleCommands(commands []string) error {
	var missing []string
	
	for _, cmd := range commands {
		if err := CheckCommand(cmd); err != nil {
			missing = append(missing, cmd)
		}
	}
	
	if len(missing) > 0 {
		return eos_err.NewUserError("required commands not found: %s", strings.Join(missing, ", "))
	}
	
	return nil
}

// CheckRoot checks if running as root
func CheckRoot() error {
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this operation requires root privileges, please run with sudo")
	}
	return nil
}

// CheckDiskSpace checks if there's enough free disk space
func CheckDiskSpace(rc *eos_io.RuntimeContext, path string, requiredGB int) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking disk space",
		zap.String("path", path),
		zap.Int("required_gb", requiredGB))
	
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-BG", "--output=avail", path},
		Capture: true,
	})
	
	if err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}
	
	// Parse available space from df output
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return fmt.Errorf("unexpected df output format")
	}
	
	// Extract number from "123G" format
	availStr := strings.TrimSuffix(strings.TrimSpace(lines[1]), "G")
	var availGB int
	if _, err := fmt.Sscanf(availStr, "%d", &availGB); err != nil {
		return fmt.Errorf("failed to parse available space: %w", err)
	}
	
	if availGB < requiredGB {
		return eos_err.NewUserError("insufficient disk space: %dGB available, %dGB required", availGB, requiredGB)
	}
	
	logger.Debug("Disk space check passed",
		zap.Int("available_gb", availGB),
		zap.Int("required_gb", requiredGB))
	
	return nil
}

// CheckPackageInstalled checks if a package is installed (Ubuntu/Debian)
func CheckPackageInstalled(rc *eos_io.RuntimeContext, packageName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking if package is installed", zap.String("package", packageName))
	
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-l", packageName},
		Capture: true,
	})
	
	if err != nil {
		// dpkg returns non-zero if package not found
		return false, nil
	}
	
	// Check if package is in installed state (ii)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, packageName) && strings.HasPrefix(line, "ii") {
			logger.Debug("Package is installed", zap.String("package", packageName))
			return true, nil
		}
	}
	
	return false, nil
}

// InstallPackageIfMissing installs a package if it's not already installed
func InstallPackageIfMissing(rc *eos_io.RuntimeContext, packageName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if already installed
	installed, err := CheckPackageInstalled(rc, packageName)
	if err != nil {
		return fmt.Errorf("failed to check package status: %w", err)
	}
	
	if installed {
		logger.Debug("Package already installed", zap.String("package", packageName))
		return nil
	}
	
	// INTERVENE - Install the package
	logger.Info("Installing package", zap.String("package", packageName))
	
	// Update package lists first
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"update"},
		Capture: false,
		Timeout: 300 * time.Second,
	}); err != nil {
		logger.Warn("Failed to update package lists", zap.Error(err))
		// Continue anyway - the package might still install
	}
	
	// Install the package
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"install", "-y", packageName},
		Capture: false,
		Timeout: 300 * time.Second,
	}); err != nil {
		return fmt.Errorf("failed to install package %s: %w", packageName, err)
	}
	
	// EVALUATE - Verify installation
	installed, err = CheckPackageInstalled(rc, packageName)
	if err != nil {
		return fmt.Errorf("failed to verify package installation: %w", err)
	}
	
	if !installed {
		return fmt.Errorf("package %s installation verification failed", packageName)
	}
	
	logger.Info("Package installed successfully", zap.String("package", packageName))
	return nil
}

// CreateDirectoryIfMissing creates a directory with proper permissions if it doesn't exist
func CreateDirectoryIfMissing(path string, perm os.FileMode) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, perm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}
	return nil
}

// ProgressReporter provides consistent progress reporting
type ProgressReporter struct {
	logger       otelzap.LoggerWithCtx
	totalPhases  int
	currentPhase int
	phaseName    string
}

// NewProgressReporter creates a new progress reporter
func NewProgressReporter(rc *eos_io.RuntimeContext, totalPhases int) *ProgressReporter {
	return &ProgressReporter{
		logger:      otelzap.Ctx(rc.Ctx),
		totalPhases: totalPhases,
	}
}

// StartPhase logs the start of a new phase
func (pr *ProgressReporter) StartPhase(phaseName string) {
	pr.currentPhase++
	pr.phaseName = phaseName
	
	pr.logger.Info(fmt.Sprintf("Phase %d/%d: %s", pr.currentPhase, pr.totalPhases, phaseName),
		zap.Int("phase", pr.currentPhase),
		zap.Int("total_phases", pr.totalPhases),
		zap.String("phase_name", phaseName))
}

// CompletePhase logs the completion of the current phase
func (pr *ProgressReporter) CompletePhase() {
	pr.logger.Info(fmt.Sprintf("✓ Completed: %s", pr.phaseName),
		zap.Int("phase", pr.currentPhase),
		zap.String("phase_name", pr.phaseName))
}

// FailPhase logs the failure of the current phase with error context
func (pr *ProgressReporter) FailPhase(err error) {
	pr.logger.Error(fmt.Sprintf("✗ Failed: %s", pr.phaseName),
		zap.Int("phase", pr.currentPhase),
		zap.Int("total_phases", pr.totalPhases),
		zap.String("phase_name", pr.phaseName),
		zap.Error(err))
}

// ReportProgress logs progress within a phase
func (pr *ProgressReporter) ReportProgress(message string, fields ...zap.Field) {
	allFields := append([]zap.Field{
		zap.Int("phase", pr.currentPhase),
		zap.String("phase_name", pr.phaseName),
	}, fields...)

	pr.logger.Info(message, allFields...)
}

// WaitForPort waits for a service to be available on a specific port
func WaitForPort(ctx context.Context, host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			// Continue trying
		}
	}
	
	return fmt.Errorf("timeout waiting for %s:%d", host, port)
}

// Systemctl wrapper functions
// These provide a consistent, safe interface to systemctl commands
// All service names are protected with "--" separator to handle names starting with hyphens

// SystemctlIsActive checks if a service is active
func SystemctlIsActive(rc *eos_io.RuntimeContext, serviceName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking if service is active",
		zap.String("service", serviceName))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "--", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	status := strings.TrimSpace(output)
	isActive := status == "active"

	logger.Debug("Service active check result",
		zap.String("service", serviceName),
		zap.Bool("is_active", isActive),
		zap.String("status", status))

	return isActive, err
}

// SystemctlIsEnabled checks if a service is enabled
func SystemctlIsEnabled(rc *eos_io.RuntimeContext, serviceName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking if service is enabled",
		zap.String("service", serviceName))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-enabled", "--", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	status := strings.TrimSpace(output)
	isEnabled := status == "enabled"

	logger.Debug("Service enabled check result",
		zap.String("service", serviceName),
		zap.Bool("is_enabled", isEnabled),
		zap.String("status", status))

	return isEnabled, err
}

// SystemctlStart starts a service
func SystemctlStart(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting service via systemctl",
		zap.String("service", serviceName))

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", "--", serviceName},
		Capture: false,
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to start service %s: %w", serviceName, err)
	}

	logger.Info("Service started successfully",
		zap.String("service", serviceName))
	return nil
}

// SystemctlStop stops a service
func SystemctlStop(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping service via systemctl",
		zap.String("service", serviceName))

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", "--", serviceName},
		Capture: false,
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to stop service %s: %w", serviceName, err)
	}

	// CRITICAL: systemctl stop is ASYNCHRONOUS - poll until service actually stops
	// Without this, we return immediately but service is still shutting down
	// This causes race conditions when we modify config files the service is still using
	deadline := time.Now().Add(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		active, err := SystemctlIsActive(rc, serviceName)
		if err != nil || !active {
			logger.Info("Service stopped successfully",
				zap.String("service", serviceName))
			return nil
		}
		<-ticker.C
	}

	return fmt.Errorf("service %s did not stop within 10 seconds (still active)", serviceName)
}

// SystemctlRestart restarts a service
func SystemctlRestart(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restarting service via systemctl",
		zap.String("service", serviceName))

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "--", serviceName},
		Capture: false,
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to restart service %s: %w", serviceName, err)
	}

	logger.Info("Service restarted successfully",
		zap.String("service", serviceName))
	return nil
}

// SystemctlEnable enables a service
func SystemctlEnable(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Enabling service via systemctl",
		zap.String("service", serviceName))

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "--", serviceName},
		Capture: false,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to enable service %s: %w", serviceName, err)
	}

	logger.Info("Service enabled successfully",
		zap.String("service", serviceName))
	return nil
}

// SystemctlDisable disables a service
func SystemctlDisable(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Disabling service via systemctl",
		zap.String("service", serviceName))

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"disable", "--", serviceName},
		Capture: false,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to disable service %s: %w", serviceName, err)
	}

	logger.Info("Service disabled successfully",
		zap.String("service", serviceName))
	return nil
}

// SystemctlEnableNow enables and starts a service in one command
func SystemctlEnableNow(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Enabling and starting service via systemctl",
		zap.String("service", serviceName))

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "--now", "--", serviceName},
		Capture: false,
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to enable and start service %s: %w", serviceName, err)
	}

	logger.Info("Service enabled and started successfully",
		zap.String("service", serviceName))
	return nil
}

// SystemctlDaemonReload reloads systemd manager configuration
func SystemctlDaemonReload(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Reloading systemd daemon configuration")

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: false,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	logger.Info("Systemd daemon reloaded successfully")
	return nil
}

// SystemctlGetMainPID gets the main PID of a service
func SystemctlGetMainPID(rc *eos_io.RuntimeContext, serviceName string) (int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Getting main PID for service",
		zap.String("service", serviceName))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"show", "--property=MainPID", "--", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil {
		return 0, fmt.Errorf("failed to get PID for %s: %w", serviceName, err)
	}

	parts := strings.Split(strings.TrimSpace(output), "=")
	if len(parts) != 2 {
		return 0, fmt.Errorf("unexpected format from systemctl show: %s", output)
	}

	pid, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("failed to parse PID %s: %w", parts[1], err)
	}

	logger.Debug("Got main PID for service",
		zap.String("service", serviceName),
		zap.Int("pid", pid))

	return pid, nil
}

// SystemctlGetStatus gets detailed status information for a service
func SystemctlGetStatus(rc *eos_io.RuntimeContext, serviceName string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Getting status for service",
		zap.String("service", serviceName))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "--", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	// Note: systemctl status returns non-zero for inactive services, but output is still useful
	logger.Debug("Got status for service",
		zap.String("service", serviceName),
		zap.Int("output_length", len(output)))

	return output, err
}

// SystemctlListUnitFiles lists unit files matching a pattern
func SystemctlListUnitFiles(rc *eos_io.RuntimeContext, pattern string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Listing unit files",
		zap.String("pattern", pattern))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "--", pattern},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return "", fmt.Errorf("failed to list unit files for %s: %w", pattern, err)
	}

	return output, nil
}