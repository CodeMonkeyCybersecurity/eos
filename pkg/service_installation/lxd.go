// pkg/service_installation/lxd.go
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

// installLxd installs LXD using snap
func (sim *ServiceInstallationManager) installLxd(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing LXD",
		zap.String("version", options.Version),
		zap.String("method", string(options.Method)))

	if options.DryRun {
		result.Success = true
		result.Message = "Dry run completed - LXD would be installed via snap"
		return nil
	}

	// Step 1: Update system packages
	step1 := InstallationStep{
		Name:        "Update System",
		Description: "Updating system package index",
		Status:      "running",
	}
	step1Start := time.Now()

	if err := sim.runCommand(rc, "Update packages", "sudo", "apt", "update"); err != nil {
		step1.Status = "failed"
		step1.Error = err.Error()
		step1.Duration = time.Since(step1Start)
		result.Steps = append(result.Steps, step1)
		return fmt.Errorf("failed to update packages: %w", err)
	}

	step1.Status = "completed"
	step1.Duration = time.Since(step1Start)
	result.Steps = append(result.Steps, step1)

	// Step 2: Install snap if not present
	step2 := InstallationStep{
		Name:        "Install Snap",
		Description: "Installing snap package manager",
		Status:      "running",
	}
	step2Start := time.Now()

	if err := sim.runCommand(rc, "Install snap", "sudo", "apt", "install", "-y", "snap", "snapd"); err != nil {
		step2.Status = "failed"
		step2.Error = err.Error()
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return fmt.Errorf("failed to install snap: %w", err)
	}

	step2.Status = "completed"
	step2.Duration = time.Since(step2Start)
	result.Steps = append(result.Steps, step2)

	// Step 3: Install LXD via snap
	step3 := InstallationStep{
		Name:        "Install LXD",
		Description: "Installing LXD via snap",
		Status:      "running",
	}
	step3Start := time.Now()

	channel := "latest/stable"
	if options.Version != "" && options.Version != "latest" {
		channel = options.Version
	}

	if err := sim.runCommand(rc, "Install LXD", "sudo", "snap", "install", "lxd", "--channel="+channel); err != nil {
		step3.Status = "failed"
		step3.Error = err.Error()
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return fmt.Errorf("failed to install LXD: %w", err)
	}

	step3.Status = "completed"
	step3.Duration = time.Since(step3Start)
	result.Steps = append(result.Steps, step3)

	// Step 4: Add current user to lxd group
	step4 := InstallationStep{
		Name:        "Configure User",
		Description: "Adding current user to lxd group",
		Status:      "running",
	}
	step4Start := time.Now()

	// Get current username
	currentUser := getCurrentUsername()
	if currentUser != "" {
		// Check if user is already in lxd group
		cmd := exec.Command("getent", "group", "lxd")
		output, _ := cmd.Output()
		if !strings.Contains(string(output), currentUser) {
			if err := sim.runCommand(rc, "Add user to group", "sudo", "usermod", "-aG", "lxd", currentUser); err != nil {
				logger.Warn("Failed to add user to lxd group", 
					zap.String("user", currentUser),
					zap.Error(err))
			} else {
				logger.Info("Added user to lxd group", zap.String("user", currentUser))
			}
		}
	}

	step4.Status = "completed"
	step4.Duration = time.Since(step4Start)
	result.Steps = append(result.Steps, step4)

	// Set result
	result.Success = true
	result.Version = channel
	result.Message = "LXD installed successfully via snap"
	result.ConfigFiles = []string{
		"/var/snap/lxd/common/lxd",
	}

	logger.Info("LXD installation completed successfully",
		zap.String("channel", channel))

	return nil
}

// getLxdStatus retrieves LXD service status
func (sim *ServiceInstallationManager) getLxdStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if LXD is installed via snap
	cmd := exec.Command("snap", "list", "lxd")
	output, err := cmd.Output()
	if err != nil {
		status.Status = "not_installed"
		return status, nil
	}

	status.Method = MethodSnap

	// Parse snap output for version
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "lxd" {
			status.Version = fields[1]
			break
		}
	}

	// Check LXD service status
	cmd = exec.Command("systemctl", "is-active", "snap.lxd.daemon.service")
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
		// Fallback: check if lxd process is running
		cmd = exec.Command("lxc", "list")
		if err := cmd.Run(); err == nil {
			status.Status = "running"
		} else {
			status.Status = "stopped"
		}
	}

	// Get additional info if running
	if status.Status == "running" {
		// Check LXD info
		cmd = exec.Command("lxd", "version")
		if output, err := cmd.Output(); err == nil {
			detailedVersion := strings.TrimSpace(string(output))
			if detailedVersion != "" {
				status.Version = detailedVersion
			}
		}
	}

	// No direct health check endpoint for LXD
	status.HealthCheck = &HealthCheckResult{
		Healthy:   status.Status == "running",
		Timestamp: time.Now(),
		Checks: []HealthCheck{
			{
				Name:    "Service Status",
				Status:  "PASSED",
				Message: fmt.Sprintf("LXD service is %s", status.Status),
			},
		},
	}

	logger.Info("LXD status retrieved",
		zap.String("status", status.Status),
		zap.String("version", status.Version))

	return status, nil
}

// Helper function to get current username
func getCurrentUsername() string {
	if output, err := exec.Command("whoami").Output(); err == nil {
		return strings.TrimSpace(string(output))
	}
	return ""
}