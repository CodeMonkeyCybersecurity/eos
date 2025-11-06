// pkg/storage/threshold/actions.go

package threshold

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ActionExecutor handles the execution of threshold-based actions
type ActionExecutor struct {
	rc *eos_io.RuntimeContext
}

// NewActionExecutor creates a new action executor
func NewActionExecutor(rc *eos_io.RuntimeContext) *ActionExecutor {
	return &ActionExecutor{rc: rc}
}

// Execute performs the specified action
func (e *ActionExecutor) Execute(action Action, mountPoint string) error {
	logger := otelzap.Ctx(e.rc.Ctx)
	logger.Info("Executing storage action",
		zap.String("action", string(action)),
		zap.String("mount_point", mountPoint))

	switch action {
	case ActionNone:
		return nil
	case ActionMonitor:
		return e.executeMonitor(mountPoint)
	case ActionCompress:
		return e.executeCompress(mountPoint)
	case ActionCleanup:
		return e.executeCleanup(mountPoint)
	case ActionDegrade:
		return e.executeDegrade(mountPoint)
	case ActionEmergency:
		return e.executeEmergency(mountPoint)
	case ActionCritical:
		return e.executeCritical(mountPoint)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

// executeMonitor increases monitoring frequency
func (e *ActionExecutor) executeMonitor(mountPoint string) error {
	logger := otelzap.Ctx(e.rc.Ctx)
	logger.Info("Activating enhanced monitoring",
		zap.String("mount_point", mountPoint))

	// In a real implementation, this would:
	// - Increase metric collection frequency
	// - Enable additional logging
	// - Send notifications

	return nil
}

// executeCompress compresses logs and old files
func (e *ActionExecutor) executeCompress(mountPoint string) error {
	logger := otelzap.Ctx(e.rc.Ctx)
	logger.Info("Starting compression of old files",
		zap.String("mount_point", mountPoint))

	// Compress old logs
	logDirs := []string{"/var/log", "/var/log/journal"}
	for _, dir := range logDirs {
		if !strings.HasPrefix(dir, mountPoint) && mountPoint != "/" {
			continue
		}

		// Find and compress logs older than 7 days
		output, err := execute.Run(e.rc.Ctx, execute.Options{
			Command: "find",
			Args: []string{
				dir,
				"-type", "f",
				"-name", "*.log",
				"-mtime", "+7",
				"-exec", "gzip", "{}", ";",
			},
			Capture: true,
		})
		if err != nil {
			logger.Error("Failed to compress logs",
				zap.String("directory", dir),
				zap.Error(err))
			continue
		}

		logger.Info("Compressed old logs",
			zap.String("directory", dir),
			zap.String("output", output))
	}

	return nil
}

// executeCleanup removes expendable files
func (e *ActionExecutor) executeCleanup(mountPoint string) error {
	logger := otelzap.Ctx(e.rc.Ctx)
	logger.Info("Starting cleanup of expendable files",
		zap.String("mount_point", mountPoint))

	// Clean package manager cache
	if mountPoint == "/" {
		// APT cache cleanup
		if _, err := execute.Run(e.rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"clean"},
			Capture: false,
		}); err != nil {
			logger.Warn("Failed to clean APT cache", zap.Error(err))
		}

		// Clean old kernels
		if output, err := execute.Run(e.rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"autoremove", "--purge", "-y"},
			Capture: true,
		}); err != nil {
			logger.Warn("Failed to autoremove packages", zap.Error(err))
		} else {
			logger.Info("Removed old packages", zap.String("output", output))
		}
	}

	// Clean temporary files
	tempDirs := []string{"/tmp", "/var/tmp"}
	for _, dir := range tempDirs {
		if !strings.HasPrefix(dir, mountPoint) && mountPoint != "/" {
			continue
		}

		// Remove files older than 7 days
		if _, err := execute.Run(e.rc.Ctx, execute.Options{
			Command: "find",
			Args: []string{
				dir,
				"-type", "f",
				"-atime", "+7",
				"-delete",
			},
			Capture: false,
		}); err != nil {
			logger.Warn("Failed to clean temporary files",
				zap.String("directory", dir),
				zap.Error(err))
		}
	}

	// Docker cleanup if applicable
	if mountPoint == "/" || strings.Contains(mountPoint, "docker") {
		if _, err := execute.Run(e.rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"system", "prune", "-f", "--volumes"},
			Capture: false,
		}); err != nil {
			logger.Debug("Docker cleanup skipped or failed", zap.Error(err))
		}
	}

	return nil
}

// executeDegrade stops non-critical services
func (e *ActionExecutor) executeDegrade(mountPoint string) error {
	logger := otelzap.Ctx(e.rc.Ctx)
	logger.Warn("Degrading non-critical services",
		zap.String("mount_point", mountPoint))

	// Services to stop in degraded mode (would be configurable)
	nonCriticalServices := []string{
		"jenkins",
		"gitlab-runner",
		"elasticsearch",
	}

	for _, service := range nonCriticalServices {
		// Check if service exists
		if _, err := execute.Run(e.rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", service},
			Capture: true,
		}); err == nil {
			// Service is active, stop it
			if _, err := execute.Run(e.rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"stop", service},
				Capture: false,
			}); err != nil {
				logger.Error("Failed to stop service",
					zap.String("service", service),
					zap.Error(err))
			} else {
				logger.Info("Stopped non-critical service",
					zap.String("service", service))
			}
		}
	}

	return nil
}

// executeEmergency performs emergency cleanup actions
func (e *ActionExecutor) executeEmergency(mountPoint string) error {
	logger := otelzap.Ctx(e.rc.Ctx)
	logger.Error("Executing emergency storage recovery",
		zap.String("mount_point", mountPoint))

	// First, try all previous actions
	if err := e.executeCompress(mountPoint); err != nil {
		logger.Warn("Compression failed during emergency", zap.Error(err))
	}

	if err := e.executeCleanup(mountPoint); err != nil {
		logger.Warn("Cleanup failed during emergency", zap.Error(err))
	}

	if err := e.executeDegrade(mountPoint); err != nil {
		logger.Warn("Service degradation failed during emergency", zap.Error(err))
	}

	// Emergency-specific actions
	// Clear all logs older than 1 day
	if _, err := execute.Run(e.rc.Ctx, execute.Options{
		Command: "find",
		Args: []string{
			"/var/log",
			"-type", "f",
			"-name", "*.log*",
			"-mtime", "+1",
			"-delete",
		},
		Capture: false,
	}); err != nil {
		logger.Error("Failed to delete old logs", zap.Error(err))
	}

	// Clear journal logs
	if _, err := execute.Run(e.rc.Ctx, execute.Options{
		Command: "journalctl",
		Args:    []string{"--vacuum-time=1d"},
		Capture: false,
	}); err != nil {
		logger.Error("Failed to vacuum journal", zap.Error(err))
	}

	return nil
}

// executeCritical handles critical storage situations
func (e *ActionExecutor) executeCritical(mountPoint string) error {
	logger := otelzap.Ctx(e.rc.Ctx)
	logger.Error("CRITICAL: Storage at critical levels",
		zap.String("mount_point", mountPoint))

	// Create emergency marker file
	markerPath := filepath.Join("/tmp", fmt.Sprintf("storage_critical_%d", time.Now().Unix()))
	if _, err := execute.Run(e.rc.Ctx, execute.Options{
		Command: "touch",
		Args:    []string{markerPath},
		Capture: false,
	}); err != nil {
		logger.Error("Failed to create critical marker", zap.Error(err))
	}

	// In a real implementation, this would:
	// - Send emergency alerts
	// - Potentially reboot services
	// - Activate emergency backup procedures

	return fmt.Errorf("critical storage condition on %s requires immediate manual intervention", mountPoint)
}
