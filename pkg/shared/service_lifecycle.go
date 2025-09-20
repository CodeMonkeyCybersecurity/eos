// pkg/shared/service_lifecycle.go

package shared

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceLifecycleManager handles safe service operations following systemd best practices
type ServiceLifecycleManager struct {
	serviceManager *ServiceManager
}

// NewServiceLifecycleManager creates a new lifecycle manager
func NewServiceLifecycleManager() *ServiceLifecycleManager {
	return &ServiceLifecycleManager{
		serviceManager: GetGlobalServiceManager(),
	}
}

// ServiceRemovalPlan represents a plan for safely removing services
type ServiceRemovalPlan struct {
	ServiceName     string `json:"service_name"`
	IsRunning       bool   `json:"is_running"`
	IsEnabled       bool   `json:"is_enabled"`
	HasUnitFile     bool   `json:"has_unit_file"`
	RequiresStop    bool   `json:"requires_stop"`
	RequiresDisable bool   `json:"requires_disable"`
	RequiresRemoval bool   `json:"requires_removal"`
	PID             int    `json:"pid,omitempty"`
}

// DetectZombieServices finds services that are running but have no unit file
func (slm *ServiceLifecycleManager) DetectZombieServices(ctx context.Context) ([]ServiceRemovalPlan, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Scanning for zombie services (running without unit files)")

	var zombieServices []ServiceRemovalPlan

	// Get all known service names from registry
	allServiceNames := slm.serviceManager.registry.GetActiveServiceNames()

	// Also check for some common variations that might be zombies
	commonVariations := []string{
		"delphi-llm-worker", // This specific zombie mentioned in the issue
		"llm-worker",
		"delphi-emailer",
		"email-worker",
	}

	allServiceNames = append(allServiceNames, commonVariations...)

	for _, serviceName := range allServiceNames {
		plan, err := slm.analyzeServiceForRemoval(ctx, serviceName)
		if err != nil {
			logger.Warn("Failed to analyze service",
				zap.String("service", serviceName),
				zap.Error(err))
			continue
		}

		// Check if this is a zombie (running but no unit file)
		if plan.IsRunning && !plan.HasUnitFile {
			logger.Warn(" Zombie service detected",
				zap.String("service", serviceName),
				zap.Bool("is_running", plan.IsRunning),
				zap.Bool("has_unit_file", plan.HasUnitFile),
				zap.Int("pid", plan.PID))
			zombieServices = append(zombieServices, plan)
		}
	}

	if len(zombieServices) > 0 {
		logger.Error(" Zombie services found - these need immediate attention",
			zap.Int("zombie_count", len(zombieServices)))
	} else {
		logger.Info(" No zombie services detected")
	}

	return zombieServices, nil
}

// SafelyRemoveService removes a service following systemd best practices
func (slm *ServiceLifecycleManager) SafelyRemoveService(ctx context.Context, serviceName string) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Starting safe service removal process",
		zap.String("service", serviceName))

	plan, err := slm.analyzeServiceForRemoval(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("failed to analyze service for removal: %w", err)
	}

	return slm.executeRemovalPlan(ctx, plan)
}

// analyzeServiceForRemoval creates a removal plan for a service
func (slm *ServiceLifecycleManager) analyzeServiceForRemoval(ctx context.Context, serviceName string) (ServiceRemovalPlan, error) {
	logger := otelzap.Ctx(ctx)

	plan := ServiceRemovalPlan{
		ServiceName: serviceName,
	}

	// Check if service is running
	if isRunning, pid, err := slm.isServiceRunning(serviceName); err == nil {
		plan.IsRunning = isRunning
		plan.PID = pid
	}

	// Check if service is enabled
	if isEnabled, err := slm.serviceManager.isServiceEnabled(serviceName); err == nil {
		plan.IsEnabled = isEnabled
	}

	// Check if unit file exists
	plan.HasUnitFile = slm.hasUnitFile(serviceName)

	// Determine what actions are needed
	plan.RequiresStop = plan.IsRunning
	plan.RequiresDisable = plan.IsEnabled && plan.HasUnitFile
	plan.RequiresRemoval = plan.HasUnitFile

	logger.Debug("Service removal analysis completed",
		zap.String("service", serviceName),
		zap.Bool("is_running", plan.IsRunning),
		zap.Bool("is_enabled", plan.IsEnabled),
		zap.Bool("has_unit_file", plan.HasUnitFile),
		zap.Bool("requires_stop", plan.RequiresStop),
		zap.Bool("requires_disable", plan.RequiresDisable),
		zap.Bool("requires_removal", plan.RequiresRemoval),
		zap.Int("pid", plan.PID))

	return plan, nil
}

// executeRemovalPlan safely executes a service removal plan
func (slm *ServiceLifecycleManager) executeRemovalPlan(ctx context.Context, plan ServiceRemovalPlan) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Executing service removal plan",
		zap.String("service", plan.ServiceName),
		zap.Bool("requires_stop", plan.RequiresStop),
		zap.Bool("requires_disable", plan.RequiresDisable),
		zap.Bool("requires_removal", plan.RequiresRemoval))

	// Step 1: Stop the service if running
	if plan.RequiresStop {
		logger.Info(" Step 1: Stopping service",
			zap.String("service", plan.ServiceName),
			zap.Int("pid", plan.PID))

		if err := slm.stopServiceSafely(ctx, plan.ServiceName, plan.PID); err != nil {
			logger.Error("Failed to stop service",
				zap.String("service", plan.ServiceName),
				zap.Error(err))
			return fmt.Errorf("failed to stop service %s: %w", plan.ServiceName, err)
		}

		logger.Info(" Service stopped successfully",
			zap.String("service", plan.ServiceName))
	}

	// Step 2: Disable the service if enabled
	if plan.RequiresDisable {
		logger.Info(" Step 2: Disabling service",
			zap.String("service", plan.ServiceName))

		if err := slm.disableService(ctx, plan.ServiceName); err != nil {
			logger.Error("Failed to disable service",
				zap.String("service", plan.ServiceName),
				zap.Error(err))
			return fmt.Errorf("failed to disable service %s: %w", plan.ServiceName, err)
		}

		logger.Info(" Service disabled successfully",
			zap.String("service", plan.ServiceName))
	}

	// Step 3: Remove unit file if it exists
	if plan.RequiresRemoval {
		logger.Info(" Step 3: Removing unit file",
			zap.String("service", plan.ServiceName))

		if err := slm.removeUnitFile(ctx, plan.ServiceName); err != nil {
			logger.Error("Failed to remove unit file",
				zap.String("service", plan.ServiceName),
				zap.Error(err))
			return fmt.Errorf("failed to remove unit file for %s: %w", plan.ServiceName, err)
		}

		logger.Info(" Unit file removed successfully",
			zap.String("service", plan.ServiceName))
	}

	// Step 4: Reload systemd daemon
	logger.Info("🔄 Step 4: Reloading systemd daemon")
	if err := slm.reloadSystemdDaemon(ctx); err != nil {
		logger.Warn("Failed to reload systemd daemon",
			zap.Error(err))
		// Not fatal, but log warning
	} else {
		logger.Info(" Systemd daemon reloaded")
	}

	logger.Info(" Service removal completed successfully",
		zap.String("service", plan.ServiceName))

	return nil
}

// stopServiceSafely stops a service with proper timeout and fallback to SIGKILL
func (slm *ServiceLifecycleManager) stopServiceSafely(ctx context.Context, serviceName string, pid int) error {
	logger := otelzap.Ctx(ctx)

	// First try systemctl stop (graceful)
	logger.Info("Attempting graceful stop via systemctl",
		zap.String("service", serviceName))

	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(stopCtx, "systemctl", "stop", serviceName)
	if err := cmd.Run(); err == nil {
		logger.Info(" Service stopped gracefully via systemctl",
			zap.String("service", serviceName))
		return nil
	} else {
		logger.Warn("  systemctl stop failed, trying direct process termination",
			zap.String("service", serviceName),
			zap.Error(err))
	}

	// If systemctl stop fails, try direct process termination
	if pid > 0 {
		logger.Info(" Attempting direct process termination",
			zap.String("service", serviceName),
			zap.Int("pid", pid))

		// First try SIGTERM
		if err := slm.killProcess(pid, "TERM"); err == nil {
			// Wait a bit for graceful shutdown
			time.Sleep(5 * time.Second)

			// Check if process still exists
			if !slm.processExists(pid) {
				logger.Info(" Process terminated gracefully",
					zap.String("service", serviceName),
					zap.Int("pid", pid))
				return nil
			}
		}

		// If SIGTERM didn't work, use SIGKILL
		logger.Warn("🔨 Process didn't respond to SIGTERM, using SIGKILL",
			zap.String("service", serviceName),
			zap.Int("pid", pid))

		if err := slm.killProcess(pid, "KILL"); err != nil {
			return fmt.Errorf("failed to kill process %d: %w", pid, err)
		}

		logger.Info("💀 Process forcefully terminated",
			zap.String("service", serviceName),
			zap.Int("pid", pid))
		return nil
	}

	return fmt.Errorf("unable to stop service %s: no PID available and systemctl failed", serviceName)
}

// isServiceRunning checks if a service is running and returns its PID
func (slm *ServiceLifecycleManager) isServiceRunning(serviceName string) (bool, int, error) {
	// Try to get the main PID from systemctl
	cmd := exec.Command("systemctl", "show", serviceName, "--property=MainPID", "--value")
	output, err := cmd.Output()
	if err == nil {
		pidStr := strings.TrimSpace(string(output))
		if pidStr != "0" && pidStr != "" {
			if pid := slm.parsePID(pidStr); pid > 0 && slm.processExists(pid) {
				return true, pid, nil
			}
		}
	}

	// Fallback: search for process by name
	cmd = exec.Command("pgrep", "-f", serviceName)
	output, err = cmd.Output()
	if err == nil {
		pidStr := strings.TrimSpace(string(output))
		if pid := slm.parsePID(pidStr); pid > 0 {
			return true, pid, nil
		}
	}

	return false, 0, nil
}

// hasUnitFile checks if a service has a unit file
func (slm *ServiceLifecycleManager) hasUnitFile(serviceName string) bool {
	cmd := exec.Command("systemctl", "cat", serviceName)
	err := cmd.Run()
	return err == nil
}

// disableService disables a systemd service
func (slm *ServiceLifecycleManager) disableService(ctx context.Context, serviceName string) error {
	cmd := exec.CommandContext(ctx, "systemctl", "disable", serviceName)
	return cmd.Run()
}

// removeUnitFile removes the systemd unit file
func (slm *ServiceLifecycleManager) removeUnitFile(_ context.Context, serviceName string) error {
	unitPaths := []string{
		"/etc/systemd/system/" + serviceName + ".service",
		"/usr/lib/systemd/system/" + serviceName + ".service",
		"/lib/systemd/system/" + serviceName + ".service",
	}

	var removed bool
	for _, path := range unitPaths {
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove %s: %w", path, err)
			}
			removed = true
		}
	}

	if !removed {
		return fmt.Errorf("no unit file found for service %s", serviceName)
	}

	return nil
}

// reloadSystemdDaemon reloads the systemd daemon
func (slm *ServiceLifecycleManager) reloadSystemdDaemon(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "daemon-reload")
	return cmd.Run()
}

// Helper functions
func (slm *ServiceLifecycleManager) killProcess(pid int, signal string) error {
	cmd := exec.Command("kill", "-"+signal, fmt.Sprintf("%d", pid))
	return cmd.Run()
}

func (slm *ServiceLifecycleManager) processExists(pid int) bool {
	cmd := exec.Command("kill", "-0", fmt.Sprintf("%d", pid))
	return cmd.Run() == nil
}

func (slm *ServiceLifecycleManager) parsePID(pidStr string) int {
	var pid int
	if _, err := fmt.Sscanf(pidStr, "%d", &pid); err == nil {
		return pid
	}
	return 0
}

// Global lifecycle manager instance
var globalServiceLifecycleManager = NewServiceLifecycleManager()

// GetGlobalServiceLifecycleManager returns the global lifecycle manager
func GetGlobalServiceLifecycleManager() *ServiceLifecycleManager {
	return globalServiceLifecycleManager
}
