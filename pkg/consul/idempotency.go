// pkg/consul/idempotency.go

package consul

import (
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Status represents the current state of Consul installation
type Status struct {
	Installed      bool
	Running        bool
	Failed         bool
	ConfigValid    bool
	Version        string
	ServiceStatus  string
	LastError      string
}

// CheckStatus performs a comprehensive check of Consul's current state
func CheckStatus(rc *eos_io.RuntimeContext) (*Status, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &Status{}

	// Check if Consul binary exists
	if consulPath, err := exec.LookPath("consul"); err == nil {
		status.Installed = true
		logger.Debug("Consul binary found", zap.String("path", consulPath))
		
		// Get version
		if output, err := exec.Command("consul", "version").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// Check service status
	if output, err := exec.Command("systemctl", "is-active", "consul").Output(); err == nil {
		status.ServiceStatus = strings.TrimSpace(string(output))
		status.Running = (status.ServiceStatus == "active")
	} else {
		// Check if service is in failed state
		if exec.Command("systemctl", "is-failed", "consul").Run() == nil {
			status.Failed = true
			status.ServiceStatus = "failed"
			
			// Get last error from journal
			if output, err := exec.Command("journalctl", "-u", "consul", "-n", "10", "--no-pager").Output(); err == nil {
				status.LastError = string(output)
			}
		}
	}

	// Check config validity if Consul is installed
	if status.Installed {
		if err := exec.Command("consul", "validate", "/etc/consul.d/").Run(); err == nil {
			status.ConfigValid = true
		}
	}

	return status, nil
}

// ShouldProceedWithInstallation determines if installation should proceed based on current status and flags
func ShouldProceedWithInstallation(rc *eos_io.RuntimeContext, status *Status, force, clean bool) (bool, string) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// If Consul is running successfully and no force flags
	if status.Running && status.ConfigValid && !force && !clean {
		logger.Info("Consul is already running successfully",
			zap.String("version", status.Version),
			zap.String("status", status.ServiceStatus))
		return false, "Consul is already installed and running. Use --force to reconfigure or --clean for a fresh install."
	}
	
	// If Consul is in failed state and no force flags
	if status.Failed && !force && !clean {
		logger.Error("Consul service is in failed state",
			zap.String("last_error", status.LastError))
		return false, "Consul is installed but in a failed state. Check logs with 'journalctl -xeu consul.service'. Use --force to reconfigure or --clean for a fresh install."
	}
	
	return true, ""
}