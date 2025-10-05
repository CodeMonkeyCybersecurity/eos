// pkg/service_installation/caddy.go
package service_installation

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/serviceutil"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installCaddy installs Caddy using the official repository
func (sim *ServiceInstallationManager) installCaddy(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Caddy",
		zap.String("version", options.Version),
		zap.String("method", string(options.Method)))

	if options.DryRun {
		result.Success = true
		result.Message = "Dry run completed - Caddy would be installed via repository"
		return nil
	}

	// Step 1: Install prerequisites
	step1 := InstallationStep{
		Name:        "Install Prerequisites",
		Description: "Installing required packages (debian-keyring, curl, gpg)",
		Status:      "running",
	}
	step1Start := time.Now()

	if err := sim.runCommand(rc, "Install prerequisites", "sudo", "apt", "install", "-y",
		"debian-keyring", "debian-archive-keyring", "apt-transport-https", "curl"); err != nil {
		step1.Status = "failed"
		step1.Error = err.Error()
		step1.Duration = time.Since(step1Start)
		result.Steps = append(result.Steps, step1)
		return err
	}

	step1.Status = "completed"
	step1.Duration = time.Since(step1Start)
	result.Steps = append(result.Steps, step1)

	// Step 2: Add Caddy GPG key
	step2 := InstallationStep{
		Name:        "Add GPG Key",
		Description: "Adding Caddy stable repository GPG key",
		Status:      "running",
	}
	step2Start := time.Now()

	// SECURITY P0 FIX: Download GPG key without shell piping
	resp, err := http.Get("https://dl.cloudsmith.io/public/caddy/stable/gpg.key")
	if err != nil {
		step2.Status = "failed"
		step2.Error = fmt.Sprintf("Failed to download GPG key: %v", err)
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		step2.Status = "failed"
		step2.Error = fmt.Sprintf("Failed to download GPG key: HTTP %d", resp.StatusCode)
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Run gpg --dearmor with stdin from downloaded key
	cmd := exec.Command("gpg", "--dearmor", "-o", "/usr/share/keyrings/caddy-stable-archive-keyring.gpg")
	cmd.Stdin = resp.Body
	if err := cmd.Run(); err != nil {
		step2.Status = "failed"
		step2.Error = fmt.Sprintf("Failed to import GPG key: %v", err)
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return err
	}

	step2.Status = "completed"
	step2.Duration = time.Since(step2Start)
	result.Steps = append(result.Steps, step2)

	// Step 3: Add repository
	step3 := InstallationStep{
		Name:        "Add Repository",
		Description: "Adding Caddy stable repository to sources",
		Status:      "running",
	}
	step3Start := time.Now()

	// SECURITY P0 FIX: Download and write repository source without shell piping
	resp2, err := http.Get("https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt")
	if err != nil {
		step3.Status = "failed"
		step3.Error = fmt.Sprintf("Failed to download repository config: %v", err)
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return err
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		step3.Status = "failed"
		step3.Error = fmt.Sprintf("Failed to download repository config: HTTP %d", resp2.StatusCode)
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return fmt.Errorf("HTTP %d", resp2.StatusCode)
	}

	// Write directly to file (no shell piping)
	repoFile, err := os.Create("/etc/apt/sources.list.d/caddy-stable.list")
	if err != nil {
		step3.Status = "failed"
		step3.Error = fmt.Sprintf("Failed to create repository file: %v", err)
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return err
	}
	defer repoFile.Close()

	if _, err := io.Copy(repoFile, resp2.Body); err != nil {
		step3.Status = "failed"
		step3.Error = fmt.Sprintf("Failed to write repository file: %v", err)
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return err
	}

	step3.Status = "completed"
	step3.Duration = time.Since(step3Start)
	result.Steps = append(result.Steps, step3)

	// Step 4: Update package index
	step4 := InstallationStep{
		Name:        "Update Packages",
		Description: "Updating package index",
		Status:      "running",
	}
	step4Start := time.Now()

	if err := sim.runCommand(rc, "Update package index", "sudo", "apt", "update"); err != nil {
		step4.Status = "failed"
		step4.Error = err.Error()
		step4.Duration = time.Since(step4Start)
		result.Steps = append(result.Steps, step4)
		return err
	}

	step4.Status = "completed"
	step4.Duration = time.Since(step4Start)
	result.Steps = append(result.Steps, step4)

	// Step 5: Install Caddy
	step5 := InstallationStep{
		Name:        "Install Caddy",
		Description: "Installing Caddy package",
		Status:      "running",
	}
	step5Start := time.Now()

	if err := sim.runCommand(rc, "Install Caddy", "sudo", "apt", "install", "-y", "caddy"); err != nil {
		step5.Status = "failed"
		step5.Error = err.Error()
		step5.Duration = time.Since(step5Start)
		result.Steps = append(result.Steps, step5)
		return err
	}

	step5.Status = "completed"
	step5.Duration = time.Since(step5Start)
	result.Steps = append(result.Steps, step5)

	// Step 6: Enable and start service
	step6 := InstallationStep{
		Name:        "Start Service",
		Description: "Enabling and starting Caddy service",
		Status:      "running",
	}
	step6Start := time.Now()

	// Use standardized service manager for consistent service operations
	serviceManager := serviceutil.NewServiceManager(rc)

	if err := serviceManager.Enable("caddy"); err != nil {
		logger.Warn("Failed to enable Caddy service", zap.Error(err))
	}

	if err := serviceManager.Start("caddy"); err != nil {
		logger.Warn("Failed to start Caddy service", zap.Error(err))
	}

	step6.Status = "completed"
	step6.Duration = time.Since(step6Start)
	result.Steps = append(result.Steps, step6)

	// Set result details
	result.Success = true
	result.Version = "latest" // Repository installs latest
	result.Port = 80          // Default HTTP port
	result.Message = "Caddy installed successfully from official repository"
	result.Endpoints = []string{"http://localhost"}

	// Add configuration note
	result.ConfigFiles = []string{"/etc/caddy/Caddyfile"}

	logger.Info("Caddy installation completed successfully")

	return nil
}

// getCaddyStatus retrieves Caddy service status
func (sim *ServiceInstallationManager) getCaddyStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Caddy is installed
	cmd := exec.Command("which", "caddy")
	if err := cmd.Run(); err != nil {
		status.Status = "not_installed"
		return status, nil
	}

	status.Method = MethodRepository

	// Get version
	cmd = exec.Command("caddy", "version")
	if output, err := cmd.Output(); err == nil {
		versionOutput := string(output)
		// Extract version from output like "v2.7.6 h1:w0NymbG2m9PcvKWsrXr09lpg1i76SbO5F3F7O4W5cNs="
		if parts := strings.Fields(versionOutput); len(parts) > 0 {
			status.Version = strings.TrimPrefix(parts[0], "v")
		}
	}

	// Check systemd service status using standardized service manager
	serviceManager := serviceutil.NewServiceManager(rc)
	if active, err := serviceManager.IsActive("caddy"); err == nil {
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

	// Get service uptime if running
	// TODO: Migrate to ServiceManager.GetUptime() when that method is implemented
	if status.Status == "running" {
		cmd = exec.Command("systemctl", "show", "caddy", "--property=ActiveEnterTimestamp", "--value")
		if output, err := cmd.Output(); err == nil {
			timestampStr := strings.TrimSpace(string(output))
			if timestampStr != "" && timestampStr != "n/a" {
				if startTime, err := time.Parse("Mon 2006-01-02 15:04:05 MST", timestampStr); err == nil {
					status.Uptime = time.Since(startTime)
				}
			}
		}
	}

	// Perform health check on port 80
	if status.Status == "running" {
		endpoint := "http://localhost"
		healthCheck, err := sim.PerformHealthCheck(rc, ServiceTypeCaddy, endpoint)
		if err == nil {
			status.HealthCheck = healthCheck
		}
	}

	logger.Info("Caddy status retrieved",
		zap.String("status", status.Status),
		zap.String("version", status.Version))

	return status, nil
}
