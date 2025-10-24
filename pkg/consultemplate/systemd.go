// pkg/consultemplate/systemd.go
//
// Consul Template Systemd Service Manager
//
// Manages systemd services for consul-template instances.
// Each service gets its own systemd unit: consul-template-{service}.service

package consultemplate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemdManager manages systemd services for consul-template
type SystemdManager struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewSystemdManager creates a new systemd manager
func NewSystemdManager(rc *eos_io.RuntimeContext) *SystemdManager {
	return &SystemdManager{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// SystemdServiceConfig contains systemd-specific configuration
type SystemdServiceConfig struct {
	ServiceName    string   // Name of the service (e.g., "bionicgpt")
	Description    string   // Service description
	ConfigPath     string   // Path to consul-template config file
	BinaryPath     string   // Path to consul-template binary
	User           string   // User to run as
	Group          string   // Group to run as
	Environment    []string // Environment variables
	WorkingDir     string   // Working directory
	RestartPolicy  string   // Restart policy (default: "always")
	RestartSec     int      // Restart delay in seconds
	KillMode       string   // Kill mode (default: "process")
	KillSignal     string   // Kill signal (default: "SIGTERM")
	TimeoutStopSec int      // Stop timeout in seconds
	After          []string // Services to start after
	Requires       []string // Required services
	Wants          []string // Wanted services
}

// DefaultSystemdServiceConfig returns default systemd configuration
func DefaultSystemdServiceConfig(serviceName string) *SystemdServiceConfig {
	configPath := GetConfigPath(serviceName)

	return &SystemdServiceConfig{
		ServiceName:    serviceName,
		Description:    fmt.Sprintf("Consul Template for %s", serviceName),
		ConfigPath:     configPath,
		BinaryPath:     BinaryPath,
		User:           SystemUser,
		Group:          SystemGroup,
		Environment:    []string{},
		WorkingDir:     DataDir,
		RestartPolicy:  SystemdRestartPolicy,
		RestartSec:     SystemdRestartSec,
		KillMode:       SystemdKillMode,
		KillSignal:     SystemdKillSignal,
		TimeoutStopSec: 30,
		After:          []string{"network-online.target", "consul.service", "vault.service"},
		Requires:       []string{"network-online.target"},
		Wants:          []string{"consul.service", "vault.service"},
	}
}

// CreateService creates a systemd service for a consul-template instance
func (m *SystemdManager) CreateService(config *SystemdServiceConfig) error {
	m.logger.Info("Creating systemd service",
		zap.String("service", config.ServiceName))

	// Generate systemd unit file content
	unitContent, err := m.generateUnitFile(config)
	if err != nil {
		return fmt.Errorf("failed to generate unit file: %w", err)
	}

	// Write unit file
	unitPath := m.getUnitFilePath(config.ServiceName)
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("failed to write unit file: %w", err)
	}

	m.logger.Info("Systemd unit file created",
		zap.String("path", unitPath))

	// Reload systemd daemon
	if err := m.reloadDaemon(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	m.logger.Info("Systemd service created successfully",
		zap.String("service", m.getServiceName(config.ServiceName)))

	return nil
}

// generateUnitFile generates the systemd unit file content
func (m *SystemdManager) generateUnitFile(config *SystemdServiceConfig) (string, error) {
	var unit strings.Builder

	// [Unit] section
	unit.WriteString("[Unit]\n")
	unit.WriteString(fmt.Sprintf("Description=%s\n", config.Description))
	unit.WriteString("Documentation=https://github.com/hashicorp/consul-template\n")

	// After
	if len(config.After) > 0 {
		unit.WriteString(fmt.Sprintf("After=%s\n", strings.Join(config.After, " ")))
	}

	// Requires
	if len(config.Requires) > 0 {
		unit.WriteString(fmt.Sprintf("Requires=%s\n", strings.Join(config.Requires, " ")))
	}

	// Wants
	if len(config.Wants) > 0 {
		unit.WriteString(fmt.Sprintf("Wants=%s\n", strings.Join(config.Wants, " ")))
	}

	unit.WriteString("\n")

	// [Service] section
	unit.WriteString("[Service]\n")
	unit.WriteString("Type=notify\n")
	unit.WriteString(fmt.Sprintf("User=%s\n", config.User))
	unit.WriteString(fmt.Sprintf("Group=%s\n", config.Group))

	// Working directory
	if config.WorkingDir != "" {
		unit.WriteString(fmt.Sprintf("WorkingDirectory=%s\n", config.WorkingDir))
	}

	// Environment variables
	for _, env := range config.Environment {
		unit.WriteString(fmt.Sprintf("Environment=%q\n", env))
	}

	// ExecStart command
	execStart := fmt.Sprintf("%s -config=%s", config.BinaryPath, config.ConfigPath)
	unit.WriteString(fmt.Sprintf("ExecStart=%s\n", execStart))

	// Restart policy
	unit.WriteString(fmt.Sprintf("Restart=%s\n", config.RestartPolicy))
	unit.WriteString(fmt.Sprintf("RestartSec=%d\n", config.RestartSec))

	// Kill mode and signal
	unit.WriteString(fmt.Sprintf("KillMode=%s\n", config.KillMode))
	unit.WriteString(fmt.Sprintf("KillSignal=%s\n", config.KillSignal))
	unit.WriteString(fmt.Sprintf("TimeoutStopSec=%d\n", config.TimeoutStopSec))

	// Security hardening
	unit.WriteString("\n# Security Hardening\n")
	unit.WriteString("NoNewPrivileges=true\n")
	unit.WriteString("PrivateTmp=true\n")
	unit.WriteString("ProtectSystem=full\n")
	unit.WriteString("ProtectHome=true\n")
	unit.WriteString("ReadWritePaths=" + DataDir + "\n")
	unit.WriteString("ReadWritePaths=" + LogDir + "\n")

	unit.WriteString("\n")

	// [Install] section
	unit.WriteString("[Install]\n")
	unit.WriteString(fmt.Sprintf("WantedBy=%s\n", SystemdWantedByTarget))

	return unit.String(), nil
}

// EnableService enables a systemd service to start on boot
func (m *SystemdManager) EnableService(serviceName string) error {
	m.logger.Info("Enabling systemd service",
		zap.String("service", serviceName))

	fullServiceName := m.getServiceName(serviceName)
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", fullServiceName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to enable service: %s: %w", output, err)
	}

	m.logger.Info("Service enabled successfully",
		zap.String("service", fullServiceName))

	return nil
}

// DisableService disables a systemd service from starting on boot
func (m *SystemdManager) DisableService(serviceName string) error {
	m.logger.Info("Disabling systemd service",
		zap.String("service", serviceName))

	fullServiceName := m.getServiceName(serviceName)
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"disable", fullServiceName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to disable service: %s: %w", output, err)
	}

	m.logger.Info("Service disabled successfully",
		zap.String("service", fullServiceName))

	return nil
}

// StartService starts a systemd service
func (m *SystemdManager) StartService(serviceName string) error {
	m.logger.Info("Starting systemd service",
		zap.String("service", serviceName))

	fullServiceName := m.getServiceName(serviceName)
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", fullServiceName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to start service: %s: %w", output, err)
	}

	m.logger.Info("Service started successfully",
		zap.String("service", fullServiceName))

	return nil
}

// StopService stops a systemd service
func (m *SystemdManager) StopService(serviceName string) error {
	m.logger.Info("Stopping systemd service",
		zap.String("service", serviceName))

	fullServiceName := m.getServiceName(serviceName)
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", fullServiceName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to stop service: %s: %w", output, err)
	}

	m.logger.Info("Service stopped successfully",
		zap.String("service", fullServiceName))

	return nil
}

// RestartService restarts a systemd service
func (m *SystemdManager) RestartService(serviceName string) error {
	m.logger.Info("Restarting systemd service",
		zap.String("service", serviceName))

	fullServiceName := m.getServiceName(serviceName)
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", fullServiceName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart service: %s: %w", output, err)
	}

	m.logger.Info("Service restarted successfully",
		zap.String("service", fullServiceName))

	return nil
}

// ReloadService reloads a systemd service configuration
func (m *SystemdManager) ReloadService(serviceName string) error {
	m.logger.Info("Reloading systemd service",
		zap.String("service", serviceName))

	fullServiceName := m.getServiceName(serviceName)
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"reload-or-restart", fullServiceName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to reload service: %s: %w", output, err)
	}

	m.logger.Info("Service reloaded successfully",
		zap.String("service", fullServiceName))

	return nil
}

// GetServiceStatus returns the status of a systemd service
func (m *SystemdManager) GetServiceStatus(serviceName string) (string, error) {
	fullServiceName := m.getServiceName(serviceName)
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", fullServiceName},
		Capture: true,
	})
	if err != nil {
		// is-active returns non-zero for inactive services
		return strings.TrimSpace(output), nil
	}

	return strings.TrimSpace(output), nil
}

// IsServiceActive checks if a systemd service is active
func (m *SystemdManager) IsServiceActive(serviceName string) bool {
	status, err := m.GetServiceStatus(serviceName)
	if err != nil {
		return false
	}
	return status == "active"
}

// IsServiceEnabled checks if a systemd service is enabled
func (m *SystemdManager) IsServiceEnabled(serviceName string) bool {
	fullServiceName := m.getServiceName(serviceName)
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-enabled", fullServiceName},
		Capture: true,
	})
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) == "enabled"
}

// RemoveService removes a systemd service
func (m *SystemdManager) RemoveService(serviceName string) error {
	m.logger.Info("Removing systemd service",
		zap.String("service", serviceName))

	// Stop service first
	_ = m.StopService(serviceName)

	// Disable service
	_ = m.DisableService(serviceName)

	// Remove unit file
	unitPath := m.getUnitFilePath(serviceName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove unit file: %w", err)
	}

	// Reload daemon
	if err := m.reloadDaemon(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	m.logger.Info("Service removed successfully",
		zap.String("service", m.getServiceName(serviceName)))

	return nil
}

// ListServices lists all consul-template services
func (m *SystemdManager) ListServices() ([]string, error) {
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-units", "--all", "--no-pager", "consul-template-*.service"},
		Capture: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	// Parse output to extract service names
	var services []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "consul-template-") && strings.HasSuffix(line, ".service") {
			// Extract service name
			fields := strings.Fields(line)
			if len(fields) > 0 {
				serviceName := fields[0]
				// Remove consul-template- prefix and .service suffix
				serviceName = strings.TrimPrefix(serviceName, "consul-template-")
				serviceName = strings.TrimSuffix(serviceName, ".service")
				services = append(services, serviceName)
			}
		}
	}

	return services, nil
}

// reloadDaemon reloads the systemd daemon
func (m *SystemdManager) reloadDaemon() error {
	m.logger.Debug("Reloading systemd daemon")

	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to reload daemon: %s: %w", output, err)
	}

	return nil
}

// getUnitFilePath returns the path to the systemd unit file
func (m *SystemdManager) getUnitFilePath(serviceName string) string {
	return filepath.Join(SystemdServiceDir, m.getServiceName(serviceName))
}

// getServiceName returns the full systemd service name
func (m *SystemdManager) getServiceName(serviceName string) string {
	return fmt.Sprintf("consul-template-%s.service", serviceName)
}

// GetServiceLogs retrieves logs for a service
func (m *SystemdManager) GetServiceLogs(serviceName string, lines int) (string, error) {
	fullServiceName := m.getServiceName(serviceName)

	args := []string{"-u", fullServiceName, "--no-pager"}
	if lines > 0 {
		args = append(args, "-n", fmt.Sprintf("%d", lines))
	}

	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "journalctl",
		Args:    args,
		Capture: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %w", err)
	}

	return output, nil
}
