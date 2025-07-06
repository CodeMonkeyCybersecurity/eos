// pkg/service_installation/tailscale.go
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

// installTailscale installs Tailscale using the official installation script
func (sim *ServiceInstallationManager) installTailscale(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Tailscale",
		zap.String("version", options.Version),
		zap.String("method", string(options.Method)))

	if options.DryRun {
		result.Success = true
		result.Message = "Dry run completed - Tailscale would be installed via official script"
		return nil
	}

	// Step 1: Download and run installation script
	step1 := InstallationStep{
		Name:        "Install Tailscale",
		Description: "Downloading and running Tailscale installation script",
		Status:      "running",
	}
	step1Start := time.Now()

	// Use curl to download and pipe to sh
	cmd := exec.Command("bash", "-c", "curl -fsSL https://tailscale.com/install.sh | sh")
	output, err := cmd.CombinedOutput()
	if err != nil {
		step1.Status = "failed"
		step1.Error = fmt.Sprintf("Installation failed: %v\nOutput: %s", err, string(output))
		step1.Duration = time.Since(step1Start)
		result.Steps = append(result.Steps, step1)
		return fmt.Errorf("failed to install Tailscale: %w", err)
	}

	step1.Status = "completed"
	step1.Duration = time.Since(step1Start)
	result.Steps = append(result.Steps, step1)

	logger.Info("Tailscale installed successfully")

	// Step 2: Verify installation
	step2 := InstallationStep{
		Name:        "Verify Installation",
		Description: "Verifying Tailscale installation",
		Status:      "running",
	}
	step2Start := time.Now()

	// Check if tailscale command exists
	if _, err := exec.LookPath("tailscale"); err != nil {
		step2.Status = "failed"
		step2.Error = "Tailscale command not found after installation"
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return fmt.Errorf("tailscale command not found after installation")
	}

	// Get version
	cmd = exec.Command("tailscale", "version")
	if output, err := cmd.Output(); err == nil {
		version := strings.TrimSpace(string(output))
		result.Version = version
	}

	step2.Status = "completed"
	step2.Duration = time.Since(step2Start)
	result.Steps = append(result.Steps, step2)

	// Step 3: Enable and start service
	step3 := InstallationStep{
		Name:        "Enable Service",
		Description: "Enabling Tailscale service",
		Status:      "running",
	}
	step3Start := time.Now()

	// Enable the service
	if err := sim.runCommand(rc, "Enable service", "sudo", "systemctl", "enable", "tailscaled"); err != nil {
		logger.Warn("Failed to enable Tailscale service", zap.Error(err))
	}

	// Start the service if not already running
	if err := sim.runCommand(rc, "Start service", "sudo", "systemctl", "start", "tailscaled"); err != nil {
		logger.Warn("Failed to start Tailscale service", zap.Error(err))
	}

	step3.Status = "completed"
	step3.Duration = time.Since(step3Start)
	result.Steps = append(result.Steps, step3)

	// Set result
	result.Success = true
	result.Message = "Tailscale installed successfully"
	result.Method = MethodNative
	
	// Note about authentication
	result.Credentials = map[string]string{
		"Note": "Run 'sudo tailscale up' to authenticate and connect to your Tailscale network",
	}

	logger.Info("Tailscale installation completed successfully")

	return nil
}

// getTailscaleStatus retrieves Tailscale service status
func (sim *ServiceInstallationManager) getTailscaleStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Tailscale is installed
	cmd := exec.Command("which", "tailscale")
	if err := cmd.Run(); err != nil {
		status.Status = "not_installed"
		return status, nil
	}

	status.Method = MethodNative

	// Get version
	cmd = exec.Command("tailscale", "version")
	if output, err := cmd.Output(); err == nil {
		status.Version = strings.TrimSpace(string(output))
	}

	// Check service status
	cmd = exec.Command("systemctl", "is-active", "tailscaled")
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

	// Get Tailscale status
	if status.Status == "running" {
		cmd = exec.Command("tailscale", "status", "--json")
		if output, err := cmd.Output(); err == nil {
			// Parse JSON output to get more details
			// For now, just check if we're connected
			if strings.Contains(string(output), "\"Self\"") {
				status.HealthCheck = &HealthCheckResult{
					Healthy:   true,
					Timestamp: time.Now(),
					Checks: []HealthCheck{
						{
							Name:    "Connection Status",
							Status:  "PASSED",
							Message: "Connected to Tailscale network",
						},
					},
				}
			}
		}

		// Get uptime
		cmd = exec.Command("systemctl", "show", "tailscaled", "--property=ActiveEnterTimestamp", "--value")
		if output, err := cmd.Output(); err == nil {
			timestampStr := strings.TrimSpace(string(output))
			if timestampStr != "" && timestampStr != "n/a" {
				if startTime, err := time.Parse("Mon 2006-01-02 15:04:05 MST", timestampStr); err == nil {
					status.Uptime = time.Since(startTime)
				}
			}
		}
	}

	logger.Info("Tailscale status retrieved",
		zap.String("status", status.Status),
		zap.String("version", status.Version))

	return status, nil
}