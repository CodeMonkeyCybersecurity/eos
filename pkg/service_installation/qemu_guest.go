// pkg/service_installation/qemu_guest.go
package service_installation

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installQemuGuest installs QEMU Guest Agent
func (sim *ServiceInstallationManager) installQemuGuest(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing QEMU Guest Agent",
		zap.String("version", options.Version),
		zap.String("method", string(options.Method)))

	if options.DryRun {
		result.Success = true
		result.Message = "Dry run completed - QEMU Guest Agent would be installed via apt"
		return nil
	}

	// Step 1: Update package index
	step1 := InstallationStep{
		Name:        "Update Packages",
		Description: "Updating package index",
		Status:      "running",
	}
	step1Start := time.Now()

	if err := sim.runCommand(rc, "Update packages", "sudo", "apt-get", "update"); err != nil {
		step1.Status = "failed"
		step1.Error = err.Error()
		step1.Duration = time.Since(step1Start)
		result.Steps = append(result.Steps, step1)
		return fmt.Errorf("failed to update packages: %w", err)
	}

	step1.Status = "completed"
	step1.Duration = time.Since(step1Start)
	result.Steps = append(result.Steps, step1)

	// Step 2: Install QEMU Guest Agent
	step2 := InstallationStep{
		Name:        "Install Package",
		Description: "Installing qemu-guest-agent package",
		Status:      "running",
	}
	step2Start := time.Now()

	if err := sim.runCommand(rc, "Install QEMU Guest Agent", "sudo", "apt-get", "install", "-y", "qemu-guest-agent"); err != nil {
		step2.Status = "failed"
		step2.Error = err.Error()
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return fmt.Errorf("failed to install qemu-guest-agent: %w", err)
	}

	step2.Status = "completed"
	step2.Duration = time.Since(step2Start)
	result.Steps = append(result.Steps, step2)

	// Step 3: Enable and start service
	step3 := InstallationStep{
		Name:        "Enable Service",
		Description: "Enabling and starting qemu-guest-agent service",
		Status:      "running",
	}
	step3Start := time.Now()

	// Enable the service
	if err := sim.runCommand(rc, "Enable service", "sudo", "systemctl", "enable", "qemu-guest-agent"); err != nil {
		logger.Warn("Failed to enable QEMU Guest Agent service", zap.Error(err))
	}

	// Start the service
	if err := sim.runCommand(rc, "Start service", "sudo", "systemctl", "start", "qemu-guest-agent"); err != nil {
		logger.Warn("Failed to start QEMU Guest Agent service", zap.Error(err))
	}

	step3.Status = "completed"
	step3.Duration = time.Since(step3Start)
	result.Steps = append(result.Steps, step3)

	// Get version info
	cmd := exec.Command("dpkg", "-s", "qemu-guest-agent")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Version:") {
				result.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
				break
			}
		}
	}

	// Set result
	result.Success = true
	result.Message = "QEMU Guest Agent installed successfully"
	result.Method = MethodNative

	logger.Info("QEMU Guest Agent installation completed successfully",
		zap.String("version", result.Version))

	return nil
}

// getQemuGuestStatus retrieves QEMU Guest Agent service status
func (sim *ServiceInstallationManager) getQemuGuestStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if package is installed
	cmd := exec.Command("dpkg", "-l", "qemu-guest-agent")
	output, err := cmd.Output()
	if err != nil || !strings.Contains(string(output), "ii  qemu-guest-agent") {
		status.Status = "not_installed"
		return status, nil
	}

	status.Method = MethodNative

	// Get version
	cmd = exec.Command("dpkg", "-s", "qemu-guest-agent")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Version:") {
				status.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
				break
			}
		}
	}

	// Check service status
	cmd = exec.Command("systemctl", "is-active", "qemu-guest-agent")
	if output, err := cmd.Output(); err == nil {
		serviceStatus := strings.TrimSpace(string(output))
		switch serviceStatus {
		case "active":
			status.Status = "running"
		case "inactive":
			status.Status = "stopped"
		case "failed":
			status.Status = "failed"
		default:
			status.Status = serviceStatus
		}
	} else {
		status.Status = "unknown"
	}

	// Get uptime if running
	if status.Status == "running" {
		cmd = exec.Command("systemctl", "show", "qemu-guest-agent", "--property=ActiveEnterTimestamp", "--value")
		if output, err := cmd.Output(); err == nil {
			timestampStr := strings.TrimSpace(string(output))
			if timestampStr != "" && timestampStr != "n/a" {
				if startTime, err := time.Parse("Mon 2006-01-02 15:04:05 MST", timestampStr); err == nil {
					status.Uptime = time.Since(startTime)
				}
			}
		}

		// Simple health check
		status.HealthCheck = &HealthCheckResult{
			Healthy:   true,
			Timestamp: time.Now(),
			Checks: []HealthCheck{
				{
					Name:    "Service Status",
					Status:  "PASSED",
					Message: "QEMU Guest Agent service is running",
				},
			},
		}
	}

	logger.Info("QEMU Guest Agent status retrieved",
		zap.String("status", status.Status),
		zap.String("version", status.Version))

	return status, nil
}
