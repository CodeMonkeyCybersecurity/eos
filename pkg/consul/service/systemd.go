// pkg/consul/service/systemd.go
// Systemd service management wrapper for Consul

package service

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemdManager manages systemd service operations
type SystemdManager struct {
	rc          *eos_io.RuntimeContext
	logger      otelzap.LoggerWithCtx
	serviceName string
}

// NewSystemdManager creates a new systemd manager
func NewSystemdManager(rc *eos_io.RuntimeContext, serviceName string) *SystemdManager {
	return &SystemdManager{
		rc:          rc,
		logger:      otelzap.Ctx(rc.Ctx),
		serviceName: serviceName,
	}
}

// Start starts the systemd service
func (sm *SystemdManager) Start() error {
	sm.logger.Info("Starting systemd service",
		zap.String("service", sm.serviceName))

	cmd := exec.Command("systemctl", "start", sm.serviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start service %s: %w", sm.serviceName, err)
	}

	return nil
}

// Stop stops the systemd service
func (sm *SystemdManager) Stop() error {
	sm.logger.Info("Stopping systemd service",
		zap.String("service", sm.serviceName))

	cmd := exec.Command("systemctl", "stop", sm.serviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop service %s: %w", sm.serviceName, err)
	}

	return nil
}

// Enable enables the service to start on boot
func (sm *SystemdManager) Enable() error {
	sm.logger.Info("Enabling systemd service",
		zap.String("service", sm.serviceName))

	cmd := exec.Command("systemctl", "enable", sm.serviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable service %s: %w", sm.serviceName, err)
	}

	return nil
}

// Disable disables the service from starting on boot
func (sm *SystemdManager) Disable() error {
	sm.logger.Info("Disabling systemd service",
		zap.String("service", sm.serviceName))

	cmd := exec.Command("systemctl", "disable", sm.serviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to disable service %s: %w", sm.serviceName, err)
	}

	return nil
}

// Restart restarts the systemd service
func (sm *SystemdManager) Restart() error {
	sm.logger.Info("Restarting systemd service",
		zap.String("service", sm.serviceName))

	cmd := exec.Command("systemctl", "restart", sm.serviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart service %s: %w", sm.serviceName, err)
	}

	return nil
}

// IsActive checks if the service is currently active
func (sm *SystemdManager) IsActive() bool {
	cmd := exec.Command("systemctl", "is-active", sm.serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return string(output) == "active\n"
}

// GetStatus returns the current service status
func (sm *SystemdManager) GetStatus() (string, error) {
	cmd := exec.Command("systemctl", "status", sm.serviceName, "--no-pager")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Status command returns non-zero for inactive services, but we still want the output
		return string(output), nil
	}

	return string(output), nil
}

// ReloadDaemon reloads the systemd daemon configuration
func (sm *SystemdManager) ReloadDaemon() error {
	sm.logger.Info("Reloading systemd daemon")

	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	// CRITICAL: daemon-reload is async - systemd scans /etc/systemd/system/
	// Wait briefly for reload to complete to prevent race conditions
	time.Sleep(500 * time.Millisecond)

	return nil
}

// CreateServiceFile creates a systemd service file
func (sm *SystemdManager) CreateServiceFile(content string) error {
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", sm.serviceName)

	sm.logger.Info("Creating systemd service file",
		zap.String("path", servicePath))

	// Write service file with proper permissions
	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd to pick up new service file
	if err := sm.ReloadDaemon(); err != nil {
		return fmt.Errorf("failed to reload systemd after creating service: %w", err)
	}

	sm.logger.Info("Systemd service file created successfully",
		zap.String("path", servicePath))

	return nil
}

// RemoveServiceFile removes the systemd service file
func (sm *SystemdManager) RemoveServiceFile() error {
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", sm.serviceName)

	sm.logger.Info("Removing systemd service file",
		zap.String("path", servicePath))

	if err := os.Remove(servicePath); err != nil {
		if os.IsNotExist(err) {
			sm.logger.Debug("Service file does not exist, nothing to remove")
			return nil
		}
		return fmt.Errorf("failed to remove service file: %w", err)
	}

	// Reload systemd to pick up removal
	if err := sm.ReloadDaemon(); err != nil {
		return fmt.Errorf("failed to reload systemd after removing service: %w", err)
	}

	return nil
}

// WaitForStop waits for the service to fully stop
func (sm *SystemdManager) WaitForStop(timeout time.Duration) error {
	sm.logger.Info("Waiting for service to stop",
		zap.String("service", sm.serviceName),
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		if !sm.IsActive() {
			sm.logger.Info("Service stopped successfully")
			return nil
		}
		<-ticker.C
	}

	return fmt.Errorf("service %s failed to stop within %v", sm.serviceName, timeout)
}
