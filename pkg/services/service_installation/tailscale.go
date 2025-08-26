// pkg/service_installation/tailscale.go
package service_installation

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/serviceutil"
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
	outputStr := string(output)
	
	// Check for installation success indicators in output
	installSuccess := false
	if err == nil {
		// Look for success indicators in the output
		if strings.Contains(outputStr, "Installation complete!") || 
		   strings.Contains(outputStr, "Tailscale installed") ||
		   strings.Contains(outputStr, "Setting up tailscale") {
			installSuccess = true
		}
	}
	
	if err != nil || !installSuccess {
		step1.Status = "failed"
		if err != nil {
			step1.Error = fmt.Sprintf("Installation command failed: %v\nOutput: %s", err, outputStr)
		} else {
			step1.Error = fmt.Sprintf("Installation script completed but did not indicate success\nOutput: %s", outputStr)
		}
		step1.Duration = time.Since(step1Start)
		result.Steps = append(result.Steps, step1)
		return fmt.Errorf("failed to install Tailscale - installation script did not complete successfully")
	}

	step1.Status = "completed"
	step1.Duration = time.Since(step1Start)
	result.Steps = append(result.Steps, step1)
	
	// Log a preview of the output (first 200 chars)
	previewLen := len(outputStr)
	if previewLen > 200 {
		previewLen = 200
	}
	logger.Info("Tailscale installation script completed", zap.String("output_preview", outputStr[:previewLen]))

	logger.Info("Tailscale installed successfully")

	// Step 2: Verify installation
	step2 := InstallationStep{
		Name:        "Verify Installation",
		Description: "Verifying Tailscale installation",
		Status:      "running",
	}
	step2Start := time.Now()

	// Check if tailscale command exists
	tailscalePath, err := exec.LookPath("tailscale")
	if err != nil {
		step2.Status = "failed"
		step2.Error = fmt.Sprintf("Tailscale command not found after installation. PATH searched: %s", err.Error())
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		
		// Try alternative locations
		alternativePaths := []string{"/usr/bin/tailscale", "/usr/local/bin/tailscale", "/opt/tailscale/bin/tailscale"}
		for _, altPath := range alternativePaths {
			if _, statErr := os.Stat(altPath); statErr == nil {
				logger.Warn("Tailscale found in alternative location", 
					zap.String("path", altPath), 
					zap.String("expected_in_path", "not found"))
				break
			}
		}
		
		return fmt.Errorf("tailscale command not found after installation - installation may have failed silently")
	}
	
	logger.Info("Tailscale binary verified", zap.String("path", tailscalePath))

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
		Description: "Enabling and starting Tailscale service",
		Status:      "running",
	}
	step3Start := time.Now()

	// Use standardized service manager for consistent service operations
	serviceManager := serviceutil.NewServiceManager(rc)
	
	// Check if tailscaled service exists
	tailscaledExists := false
	if checkCmd := exec.Command("systemctl", "list-unit-files", "tailscaled.service"); checkCmd.Run() == nil {
		tailscaledExists = true
		logger.Info("tailscaled service unit found")
	}
	
	if !tailscaledExists {
		step3.Status = "failed"
		step3.Error = "tailscaled.service unit file not found - installation may be incomplete"
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return fmt.Errorf("tailscaled service not found after installation")
	}
	
	// Enable the service
	if err := serviceManager.Enable("tailscaled"); err != nil {
		logger.Warn("Failed to enable Tailscale service", zap.Error(err))
		step3.Status = "failed"
		step3.Error = fmt.Sprintf("Failed to enable tailscaled service: %v", err)
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return fmt.Errorf("failed to enable tailscaled service: %w", err)
	}

	// Start the service if not already running
	if err := serviceManager.Start("tailscaled"); err != nil {
		logger.Warn("Failed to start Tailscale service", zap.Error(err))
		step3.Status = "failed"
		step3.Error = fmt.Sprintf("Failed to start tailscaled service: %v", err)
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return fmt.Errorf("failed to start tailscaled service: %w", err)
	}
	
	// Verify the service is actually running
	if active, err := serviceManager.IsActive("tailscaled"); err != nil || !active {
		step3.Status = "failed"
		step3.Error = fmt.Sprintf("Service failed to start properly - active check failed: %v", err)
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return fmt.Errorf("tailscaled service is not running after start attempt")
	}

	step3.Status = "completed"
	step3.Duration = time.Since(step3Start)
	result.Steps = append(result.Steps, step3)
	
	logger.Info("Tailscale service enabled and started successfully")

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

	// Check service status using standardized service manager
	serviceManager := serviceutil.NewServiceManager(rc)
	if active, err := serviceManager.IsActive("tailscaled"); err == nil {
		var serviceStatus string
		if active {
			serviceStatus = "active"
		} else {
			serviceStatus = "inactive"
		}
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
		// TODO: Migrate to ServiceManager.GetUptime() when that method is implemented
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
