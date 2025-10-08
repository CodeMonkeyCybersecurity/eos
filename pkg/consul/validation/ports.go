// pkg/consul/validation/ports.go
// Port availability validation for Consul

package validation

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PortValidator validates port availability
type PortValidator struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewPortValidator creates a new port validator
func NewPortValidator(rc *eos_io.RuntimeContext) *PortValidator {
	return &PortValidator{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// CheckPorts validates that all required ports are available
func (pv *PortValidator) CheckPorts(ports []int) error {
	pv.logger.Info("Checking port availability",
		zap.Ints("ports", ports))

	var portErrors []string
	for _, port := range ports {
		if err := pv.CheckPort(port); err != nil {
			portErrors = append(portErrors, err.Error())
		}
	}

	if len(portErrors) > 0 {
		return fmt.Errorf("port availability check failed:\n  - %s", strings.Join(portErrors, "\n  - "))
	}

	pv.logger.Info("All ports are available")
	return nil
}

// CheckPort validates that a specific port is available
func (pv *PortValidator) CheckPort(port int) error {
	// Check Docker containers first (lsof doesn't show these clearly)
	if dockerConflict, err := pv.checkDockerPortConflict(port); err == nil && dockerConflict != "" {
		return fmt.Errorf("port %d is exposed by Docker container: %s\nRemediation: Stop container with 'docker stop %s'",
			port, dockerConflict, dockerConflict)
	}

	// Use lsof to check what's using the port
	cmd := exec.Command("sh", "-c", fmt.Sprintf("lsof -i :%d 2>/dev/null | grep LISTEN | awk '{print $1}' | head -1", port))
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		// Port is available
		return nil
	}

	processName := strings.TrimSpace(string(output))

	// If it's Consul already using the port, check if it's managed by systemd
	if processName == "consul" {
		pv.logger.Debug("Port already in use by Consul", zap.Int("port", port))
		// This is acceptable for idempotency - the installer will handle it
		return nil
	}

	// Some other process is using the port
	return fmt.Errorf("port %d is already in use by %s", port, processName)
}

// checkDockerPortConflict checks if a Docker container is exposing the port
func (pv *PortValidator) checkDockerPortConflict(port int) (string, error) {
	// Check if docker is installed
	if _, err := exec.LookPath("docker"); err != nil {
		return "", err // Docker not installed, no conflict
	}

	// Query Docker for containers exposing this port
	cmd := exec.Command("sh", "-c", fmt.Sprintf("docker ps --format '{{.Names}}:{{.Ports}}' | grep ':%d->' | head -1", port))
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		return "", nil // No Docker conflict
	}

	// Extract container name from output
	parts := strings.Split(string(output), ":")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0]), nil
	}

	return "", nil
}

// WaitForPortsReleased polls until ports are released after service stop
func (pv *PortValidator) WaitForPortsReleased(ports []int, timeout time.Duration) error {
	pv.logger.Info("Waiting for ports to be released",
		zap.Ints("ports", ports),
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		allFree := true
		for _, port := range ports {
			if err := pv.CheckPort(port); err != nil {
				allFree = false
				break
			}
		}

		if allFree {
			pv.logger.Info("All ports released successfully")
			return nil
		}

		<-ticker.C
	}

	return fmt.Errorf("timeout waiting for ports to be released after %v", timeout)
}
