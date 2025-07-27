// pkg/bootstrap/common.go
//
// Common utilities and patterns for bootstrap operations.
// This file consolidates shared functionality to reduce duplication.

package bootstrap

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
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
func WithRetry(rc *eos_io.RuntimeContext, config RetryConfig, operation func() error) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	delay := config.InitialDelay
	var lastErr error
	
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		logger.Debug("Attempting operation",
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", config.MaxAttempts))
		
		if err := operation(); err == nil {
			if attempt > 1 {
				logger.Info("Operation succeeded after retry",
					zap.Int("attempts", attempt))
			}
			return nil
		} else {
			lastErr = err
			
			if attempt < config.MaxAttempts {
				logger.Warn("Operation failed, will retry",
					zap.Error(err),
					zap.Int("attempt", attempt),
					zap.Duration("retry_delay", delay))
				
				// Sleep with context cancellation support
				select {
				case <-time.After(delay):
					// Continue to next attempt
				case <-rc.Ctx.Done():
					return fmt.Errorf("operation cancelled: %w", rc.Ctx.Err())
				}
				
				// Calculate next delay with exponential backoff
				delay = time.Duration(float64(delay) * config.BackoffMultiplier)
				if delay > config.MaxDelay {
					delay = config.MaxDelay
				}
			}
		}
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// CheckService checks if a systemd service is active
func CheckService(rc *eos_io.RuntimeContext, serviceName string) (ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking service status", zap.String("service", serviceName))
	
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	
	status := strings.TrimSpace(output)
	
	switch status {
	case "active":
		return ServiceStatusActive, nil
	case "inactive":
		return ServiceStatusInactive, nil
	case "failed":
		return ServiceStatusFailed, nil
	default:
		if err != nil {
			logger.Debug("Service check failed",
				zap.String("service", serviceName),
				zap.String("output", output),
				zap.Error(err))
		}
		return ServiceStatusUnknown, err
	}
}

// EnsureService ensures a systemd service is running, starting it if necessary
func EnsureService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Ensuring service is running", zap.String("service", serviceName))
	
	// ASSESS - Check current status
	status, err := CheckService(rc, serviceName)
	if err == nil && status == ServiceStatusActive {
		logger.Debug("Service is already active", zap.String("service", serviceName))
		return nil
	}
	
	// INTERVENE - Start the service
	logger.Info("Starting service", zap.String("service", serviceName))
	
	// Enable the service first
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", serviceName},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to enable service", 
			zap.String("service", serviceName),
			zap.Error(err))
	}
	
	// Start the service
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", serviceName},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to start service %s: %w", serviceName, err)
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