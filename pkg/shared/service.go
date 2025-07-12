package shared

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Service management utilities to standardize systemd operations across the codebase

// ServiceState represents the state of a systemd service
type ServiceState struct {
	Name       string    `json:"name"`
	Active     bool      `json:"active"`
	Enabled    bool      `json:"enabled"`
	Failed     bool      `json:"failed"`
	Status     string    `json:"status"`
	Since      time.Time `json:"since,omitempty"`
	MainPID    int       `json:"main_pid,omitempty"`
	Memory     string    `json:"memory,omitempty"`
	LoadState  string    `json:"load_state,omitempty"`
	SubState   string    `json:"sub_state,omitempty"`
}

// ServiceOperation represents different service operations
type ServiceOperation string

const (
	OperationStart    ServiceOperation = "start"
	OperationStop     ServiceOperation = "stop"
	OperationRestart  ServiceOperation = "restart"
	OperationReload   ServiceOperation = "reload"
	OperationEnable   ServiceOperation = "enable"
	OperationDisable  ServiceOperation = "disable"
	OperationStatus   ServiceOperation = "status"
	OperationIsActive ServiceOperation = "is-active"
	OperationIsEnabled ServiceOperation = "is-enabled"
)

// ServiceConfig holds configuration for service operations
type ServiceConfig struct {
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	ServiceFile   string        `json:"service_file,omitempty"`
	User          string        `json:"user,omitempty"`
	Group         string        `json:"group,omitempty"`
	WorkingDir    string        `json:"working_dir,omitempty"`
	ExecStart     string        `json:"exec_start,omitempty"`
	ExecStop      string        `json:"exec_stop,omitempty"`
	Environment   []string      `json:"environment,omitempty"`
	Restart       string        `json:"restart,omitempty"`
	RestartDelay  time.Duration `json:"restart_sec,omitempty"` // Keep JSON tag for compatibility
	WantedBy      string        `json:"wanted_by,omitempty"`
	After         []string      `json:"after,omitempty"`
	Requires      []string      `json:"requires,omitempty"`
}

// SystemdServiceManager provides standardized systemd service management
type SystemdServiceManager struct {
	ctx    ContextProvider
	logger Logger
}

// NewSystemdServiceManager creates a new systemd service manager with dependency injection
func NewSystemdServiceManager(ctx ContextProvider, logger Logger) *SystemdServiceManager {
	return &SystemdServiceManager{
		ctx:    ctx,
		logger: logger,
	}
}

// Compatibility wrapper - creates a simple service manager that can work without RuntimeContext
// This allows gradual migration of existing code
func NewSimpleServiceManager() *SystemdServiceManager {
	// Use a simple logger that doesn't require external dependencies
	logger := &simpleLogger{}
	ctx := &simpleContext{}
	return NewSystemdServiceManager(ctx, logger)
}

// Simple implementations for compatibility
type simpleLogger struct{}

func (sl *simpleLogger) Info(msg string, fields ...zap.Field)  {}
func (sl *simpleLogger) Debug(msg string, fields ...zap.Field) {}
func (sl *simpleLogger) Warn(msg string, fields ...zap.Field)  {}
func (sl *simpleLogger) Error(msg string, fields ...zap.Field) {}

type simpleContext struct{}

func (sc *simpleContext) Context() context.Context {
	return context.Background()
}

// GetServiceState retrieves comprehensive service state information
func (sm *SystemdServiceManager) GetServiceState(serviceName string) (*ServiceState, error) {
	sm.logger.Info("Getting service state",
		zap.String("service", serviceName))

	state := &ServiceState{
		Name: serviceName,
	}

	// Check if service is active
	if active, err := sm.IsActive(serviceName); err == nil {
		state.Active = active
	}

	// Check if service is enabled
	if enabled, err := sm.IsEnabled(serviceName); err == nil {
		state.Enabled = enabled
	}

	// Get detailed status
	if status, err := sm.GetStatus(serviceName); err == nil {
		state.Status = status
	}

	// Check if service has failed
	state.Failed = strings.Contains(state.Status, "failed")

	return state, nil
}

// IsActive checks if a service is currently active
func (sm *SystemdServiceManager) IsActive(serviceName string) (bool, error) {
	sm.logger.Debug("Checking if service is active",
		zap.String("service", serviceName))

	output, err := sm.runSystemctl(OperationIsActive, serviceName)
	if err != nil {
		// systemctl is-active returns non-zero for inactive services
		return false, nil
	}

	return strings.TrimSpace(output) == "active", nil
}

// IsEnabled checks if a service is enabled for automatic startup
func (sm *SystemdServiceManager) IsEnabled(serviceName string) (bool, error) {
	sm.logger.Debug("Checking if service is enabled",
		zap.String("service", serviceName))

	output, err := sm.runSystemctl(OperationIsEnabled, serviceName)
	if err != nil {
		// systemctl is-enabled returns non-zero for disabled services
		return false, nil
	}

	status := strings.TrimSpace(output)
	return status == "enabled" || status == "enabled-runtime", nil
}

// GetStatus returns the full status output for a service
func (sm *SystemdServiceManager) GetStatus(serviceName string) (string, error) {
	sm.logger.Debug("Getting service status",
		zap.String("service", serviceName))

	return sm.runSystemctl(OperationStatus, serviceName)
}

// Start starts a systemd service
func (sm *SystemdServiceManager) Start(serviceName string) error {
	sm.logger.Info("Starting service",
		zap.String("service", serviceName))

	_, err := sm.runSystemctl(OperationStart, serviceName)
	if err != nil {
		return WrapServiceError("start", serviceName, err)
	}

	// Verify service started
	if active, checkErr := sm.IsActive(serviceName); checkErr == nil && !active {
		return fmt.Errorf("service %s failed to start", serviceName)
	}

	sm.logger.Info("Service started successfully",
		zap.String("service", serviceName))

	return nil
}

// Stop stops a systemd service
func (sm *SystemdServiceManager) Stop(serviceName string) error {
	sm.logger.Info("Stopping service",
		zap.String("service", serviceName))

	_, err := sm.runSystemctl(OperationStop, serviceName)
	if err != nil {
		return WrapServiceError("stop", serviceName, err)
	}

	sm.logger.Info("Service stopped successfully",
		zap.String("service", serviceName))

	return nil
}

// Restart restarts a systemd service
func (sm *SystemdServiceManager) Restart(serviceName string) error {
	sm.logger.Info("Restarting service",
		zap.String("service", serviceName))

	_, err := sm.runSystemctl(OperationRestart, serviceName)
	if err != nil {
		return WrapServiceError("restart", serviceName, err)
	}

	// Verify service restarted
	if active, checkErr := sm.IsActive(serviceName); checkErr == nil && !active {
		return fmt.Errorf("service %s failed to restart", serviceName)
	}

	sm.logger.Info("Service restarted successfully",
		zap.String("service", serviceName))

	return nil
}

// Reload reloads a systemd service configuration
func (sm *SystemdServiceManager) Reload(serviceName string) error {
	sm.logger.Info("Reloading service",
		zap.String("service", serviceName))

	_, err := sm.runSystemctl(OperationReload, serviceName)
	if err != nil {
		return WrapServiceError("reload", serviceName, err)
	}

	sm.logger.Info("Service reloaded successfully",
		zap.String("service", serviceName))

	return nil
}

// Enable enables a service for automatic startup
func (sm *SystemdServiceManager) Enable(serviceName string) error {
	sm.logger.Info("Enabling service",
		zap.String("service", serviceName))

	_, err := sm.runSystemctl(OperationEnable, serviceName)
	if err != nil {
		return WrapServiceError("enable", serviceName, err)
	}

	sm.logger.Info("Service enabled successfully",
		zap.String("service", serviceName))

	return nil
}

// Disable disables a service from automatic startup
func (sm *SystemdServiceManager) Disable(serviceName string) error {
	sm.logger.Info("Disabling service",
		zap.String("service", serviceName))

	_, err := sm.runSystemctl(OperationDisable, serviceName)
	if err != nil {
		return WrapServiceError("disable", serviceName, err)
	}

	sm.logger.Info("Service disabled successfully",
		zap.String("service", serviceName))

	return nil
}

// DaemonReload reloads systemd configuration
func (sm *SystemdServiceManager) DaemonReload() error {
	sm.logger.Info("Reloading systemd daemon")

	_, err := sm.runSystemctl("daemon-reload")
	if err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	sm.logger.Info("Systemd daemon reloaded successfully")
	return nil
}

// EnsureServiceState ensures a service is in the desired state
func (sm *SystemdServiceManager) EnsureServiceState(serviceName string, shouldBeActive, shouldBeEnabled bool) error {
	sm.logger.Info("Ensuring service state",
		zap.String("service", serviceName),
		zap.Bool("should_be_active", shouldBeActive),
		zap.Bool("should_be_enabled", shouldBeEnabled))

	// Handle enabled state
	if enabled, err := sm.IsEnabled(serviceName); err == nil {
		if shouldBeEnabled && !enabled {
			if err := sm.Enable(serviceName); err != nil {
				return err
			}
		} else if !shouldBeEnabled && enabled {
			if err := sm.Disable(serviceName); err != nil {
				return err
			}
		}
	}

	// Handle active state
	if active, err := sm.IsActive(serviceName); err == nil {
		if shouldBeActive && !active {
			if err := sm.Start(serviceName); err != nil {
				return err
			}
		} else if !shouldBeActive && active {
			if err := sm.Stop(serviceName); err != nil {
				return err
			}
		}
	}

	return nil
}

// InstallService creates and installs a systemd service file
func (sm *SystemdServiceManager) InstallService(config *ServiceConfig) error {
	sm.logger.Info("Installing service",
		zap.String("service", config.Name),
		zap.String("service_file", config.ServiceFile))

	// ASSESS - Check prerequisites
	if config.ServiceFile == "" {
		config.ServiceFile = fmt.Sprintf("/etc/systemd/system/%s.service", config.Name)
	}

	// Generate service file content
	content := sm.generateServiceFile(config)

	// INTERVENE - Write service file
	if err := WriteFileContents(config.ServiceFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd daemon
	if err := sm.DaemonReload(); err != nil {
		return err
	}

	// EVALUATE - Verify service file was loaded
	if _, err := sm.GetStatus(config.Name); err != nil {
		return fmt.Errorf("service file was not loaded correctly: %w", err)
	}

	sm.logger.Info("Service installed successfully",
		zap.String("service", config.Name))

	return nil
}

// RemoveService removes a systemd service
func (sm *SystemdServiceManager) RemoveService(serviceName string) error {
	sm.logger.Info("Removing service",
		zap.String("service", serviceName))

	// Stop and disable service first
	_ = sm.Stop(serviceName)     // Ignore errors - service might not be running
	_ = sm.Disable(serviceName)  // Ignore errors - service might not be enabled

	// Remove service file
	serviceFile := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	if FileExists(serviceFile) {
		if err := SecureDelete(serviceFile); err != nil {
			return fmt.Errorf("failed to remove service file: %w", err)
		}
	}

	// Reload daemon
	if err := sm.DaemonReload(); err != nil {
		return err
	}

	sm.logger.Info("Service removed successfully",
		zap.String("service", serviceName))

	return nil
}

// runSystemctl executes systemctl commands with proper error handling
func (sm *SystemdServiceManager) runSystemctl(operation ServiceOperation, args ...string) (string, error) {
	cmdArgs := []string{string(operation)}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.CommandContext(sm.ctx.Context(), "systemctl", cmdArgs...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		sm.logger.Debug("systemctl command failed",
			zap.String("operation", string(operation)),
			zap.Strings("args", args),
			zap.Error(err),
			zap.String("output", string(output)))
		return "", err
	}

	return string(output), nil
}

// generateServiceFile creates a systemd service file from configuration
func (sm *SystemdServiceManager) generateServiceFile(config *ServiceConfig) string {
	var content strings.Builder

	// [Unit] section
	content.WriteString("[Unit]\n")
	if config.Description != "" {
		content.WriteString(fmt.Sprintf("Description=%s\n", config.Description))
	}
	
	for _, after := range config.After {
		content.WriteString(fmt.Sprintf("After=%s\n", after))
	}
	
	for _, requires := range config.Requires {
		content.WriteString(fmt.Sprintf("Requires=%s\n", requires))
	}
	
	content.WriteString("\n")

	// [Service] section
	content.WriteString("[Service]\n")
	content.WriteString("Type=simple\n")
	
	if config.User != "" {
		content.WriteString(fmt.Sprintf("User=%s\n", config.User))
	}
	
	if config.Group != "" {
		content.WriteString(fmt.Sprintf("Group=%s\n", config.Group))
	}
	
	if config.WorkingDir != "" {
		content.WriteString(fmt.Sprintf("WorkingDirectory=%s\n", config.WorkingDir))
	}
	
	if config.ExecStart != "" {
		content.WriteString(fmt.Sprintf("ExecStart=%s\n", config.ExecStart))
	}
	
	if config.ExecStop != "" {
		content.WriteString(fmt.Sprintf("ExecStop=%s\n", config.ExecStop))
	}
	
	for _, env := range config.Environment {
		content.WriteString(fmt.Sprintf("Environment=%s\n", env))
	}
	
	if config.Restart != "" {
		content.WriteString(fmt.Sprintf("Restart=%s\n", config.Restart))
	} else {
		content.WriteString("Restart=always\n")
	}
	
	if config.RestartDelay > 0 {
		content.WriteString(fmt.Sprintf("RestartSec=%ds\n", int(config.RestartDelay.Seconds())))
	}
	
	content.WriteString("\n")

	// [Install] section
	content.WriteString("[Install]\n")
	if config.WantedBy != "" {
		content.WriteString(fmt.Sprintf("WantedBy=%s\n", config.WantedBy))
	} else {
		content.WriteString("WantedBy=multi-user.target\n")
	}

	return content.String()
}

// WrapServiceError creates a standardized service operation error
func WrapServiceError(operation, serviceName string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("failed to %s service '%s': %w", operation, serviceName, err)
}

// Convenience functions for common operations

// StartAndEnable starts and enables a service
func (sm *SystemdServiceManager) StartAndEnable(serviceName string) error {
	if err := sm.Enable(serviceName); err != nil {
		return err
	}
	return sm.Start(serviceName)
}

// StopAndDisable stops and disables a service
func (sm *SystemdServiceManager) StopAndDisable(serviceName string) error {
	if err := sm.Stop(serviceName); err != nil {
		// Continue even if stop fails
		sm.logger.Warn("Failed to stop service, continuing with disable",
			zap.String("service", serviceName),
			zap.Error(err))
	}
	return sm.Disable(serviceName)
}

// RestartIfActive restarts a service only if it's currently active
func (sm *SystemdServiceManager) RestartIfActive(serviceName string) error {
	if active, err := sm.IsActive(serviceName); err == nil && active {
		return sm.Restart(serviceName)
	}
	return nil
}

// EnableIfInstalled enables a service only if the service file exists
func (sm *SystemdServiceManager) EnableIfInstalled(serviceName string) error {
	// Try to get status to see if service exists
	if _, err := sm.GetStatus(serviceName); err == nil {
		return sm.Enable(serviceName)
	}
	return nil
}