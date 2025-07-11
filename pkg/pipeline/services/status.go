package services

import (
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetServiceStatus retrieves systemd service status
// Migrated from cmd/read/pipeline_services.go getServiceStatus
func GetServiceStatus(rc *eos_io.RuntimeContext, serviceName string) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare service status retrieval
	logger.Info("Assessing service status retrieval",
		zap.String("service", serviceName))
	
	status := &ServiceStatus{}

	// INTERVENE - Gather service status information
	logger.Debug("Gathering service status information")
	
	// Get service status
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err == nil {
		status.Active = strings.TrimSpace(string(output))
	} else {
		status.Active = "inactive"
	}

	// Get enabled status
	cmd = exec.Command("systemctl", "is-enabled", serviceName)
	output, err = cmd.Output()
	if err == nil {
		status.Enabled = strings.TrimSpace(string(output))
	} else {
		status.Enabled = "disabled"
	}

	// Get overall status
	cmd = exec.Command("systemctl", "show", "-p", "SubState", serviceName)
	output, err = cmd.Output()
	if err == nil {
		parts := strings.Split(strings.TrimSpace(string(output)), "=")
		if len(parts) == 2 {
			status.Status = parts[1]
		}
	}

	// Get uptime if active
	if status.Active == "active" {
		cmd = exec.Command("systemctl", "show", "-p", "ActiveEnterTimestamp", serviceName)
		output, err = cmd.Output()
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(output)), "=")
			if len(parts) == 2 {
				status.Uptime = parts[1]
			}
		}
	}

	// EVALUATE - Log successful status retrieval
	logger.Info("Service status retrieved successfully",
		zap.String("service", serviceName),
		zap.String("active", status.Active),
		zap.String("enabled", status.Enabled),
		zap.String("status", status.Status))

	return status, nil
}