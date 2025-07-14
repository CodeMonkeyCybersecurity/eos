package hecate

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerifyHecateInstallation verifies Hecate is properly installed
func VerifyHecateInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Hecate installation")
	
	// Check if reverse proxy is installed
	backend := DetectInstalledBackend()
	if backend == "" {
		return fmt.Errorf("no reverse proxy backend found (nginx or caddy)")
	}
	
	logger.Info("Found reverse proxy backend", zap.String("backend", backend))
	
	// Verify service is running
	if !IsServiceRunning(backend) {
		return fmt.Errorf("%s service is not running", backend)
	}
	
	// Verify configuration
	switch backend {
	case "nginx":
		if err := TestNginxConfig(rc); err != nil {
			return fmt.Errorf("nginx configuration is invalid: %w", err)
		}
	case "caddy":
		// Caddy validates config on startup
		logger.Debug("Caddy configuration is validated on startup")
	}
	
	// Verify directories exist
	requiredDirs := []string{
		"/etc/hecate",
		"/var/lib/hecate",
		"/var/log/hecate",
	}
	
	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("required directory %s does not exist: %w", dir, err)
		}
	}
	
	logger.Info("Hecate verification completed successfully")
	return nil
}

// DetectInstalledBackend detects which reverse proxy backend is installed
func DetectInstalledBackend() string {
	if CheckCommandExists("nginx") {
		return "nginx"
	}
	if CheckCommandExists("caddy") {
		return "caddy"
	}
	return ""
}

// GetHecateStatus returns the current status of Hecate
func GetHecateStatus(rc *eos_io.RuntimeContext) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	status := &ServiceStatus{
		Running: false,
		Version: "unknown",
	}
	
	// Detect backend
	backend := DetectInstalledBackend()
	if backend == "" {
		status.Errors = append(status.Errors, "No reverse proxy backend installed")
		return status, nil
	}
	
	// Check if service is running
	status.Running = IsServiceRunning(backend)
	
	// Get version
	switch backend {
	case "nginx":
		status.Version = GetNginxVersion()
	case "caddy":
		status.Version = GetCaddyVersion()
	}
	
	// Test configuration
	var configErr error
	switch backend {
	case "nginx":
		configErr = TestNginxConfig(rc)
	case "caddy":
		// Caddy validates on startup
		configErr = nil
	}
	
	status.ConfigValid = configErr == nil
	if configErr != nil {
		status.Errors = append(status.Errors, fmt.Sprintf("Configuration error: %v", configErr))
	}
	
	// Count active routes (simplified)
	routesDir := "/etc/hecate/routes"
	if entries, err := os.ReadDir(routesDir); err == nil {
		status.ActiveRoutes = len(entries)
	}
	
	logger.Debug("Status retrieved",
		zap.String("backend", backend),
		zap.Bool("running", status.Running),
		zap.String("version", status.Version))
	
	return status, nil
}

// CheckListeningPorts checks which ports are listening
func CheckListeningPorts() ([]int, error) {
	cmd := exec.Command("ss", "-tlnp")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		cmd = exec.Command("netstat", "-tlnp")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to check listening ports: %w", err)
		}
	}
	
	var ports []int
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Look for nginx or caddy processes
		if strings.Contains(line, "nginx") || strings.Contains(line, "caddy") {
			// Extract port from line (simplified parsing)
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.Contains(field, ":") {
					parts := strings.Split(field, ":")
					if len(parts) >= 2 {
						// Try to parse port number
						var port int
						if _, err := fmt.Sscanf(parts[len(parts)-1], "%d", &port); err == nil {
							ports = append(ports, port)
						}
					}
				}
			}
		}
	}
	
	return ports, nil
}