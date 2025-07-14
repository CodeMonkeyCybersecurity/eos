package hecate

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallConfig represents installation configuration
type InstallConfig struct {
	Backend           string   // "nginx" or "caddy"
	ListenPort        int
	SSLListenPort     int
	AdminPort         int
	EnableSSL         bool
	EnableMonitoring  bool
	EnableRateLimiting bool
	Backends          []BackendConfig
}

// BackendConfig represents a backend configuration
type BackendConfig struct {
	Name      string
	Domain    string
	Upstreams []string
}

// ServiceStatus represents the status of the Hecate service
type ServiceStatus struct {
	Running      bool
	Version      string
	ConfigValid  bool
	ActiveRoutes int
	Errors       []string
}

// CheckCommandExists checks if a command exists in PATH
func CheckCommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// IsServiceRunning checks if a systemd service is running
func IsServiceRunning(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(output)) == "active"
}

// GetNginxVersion retrieves the nginx version
func GetNginxVersion() string {
	cmd := exec.Command("nginx", "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown"
	}
	
	// nginx outputs version to stderr
	versionStr := string(output)
	if strings.Contains(versionStr, "nginx/") {
		parts := strings.Split(versionStr, "nginx/")
		if len(parts) > 1 {
			return strings.Fields(parts[1])[0]
		}
	}
	return "unknown"
}

// GetCaddyVersion retrieves the caddy version
func GetCaddyVersion() string {
	cmd := exec.Command("caddy", "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	
	// Parse caddy version output
	versionStr := strings.TrimSpace(string(output))
	parts := strings.Fields(versionStr)
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

// TestNginxConfig tests the nginx configuration
func TestNginxConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	cmd := exec.CommandContext(rc.Ctx, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Nginx configuration test failed",
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("nginx configuration test failed: %s", output)
	}
	
	logger.Debug("Nginx configuration test passed")
	return nil
}

// ReloadNginx reloads the nginx service
func ReloadNginx(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// First try reload
	cmd := exec.CommandContext(rc.Ctx, "systemctl", "reload", "nginx")
	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to reload nginx, trying restart", zap.Error(err))
		
		// If reload fails, try restart
		restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", "nginx")
		if err := restartCmd.Run(); err != nil {
			return fmt.Errorf("failed to reload/restart nginx: %w", err)
		}
	}
	
	logger.Info("Nginx reloaded successfully")
	return nil
}

// EnableService enables and starts a systemd service
func EnableService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Enable the service
	enableCmd := exec.CommandContext(rc.Ctx, "systemctl", "enable", serviceName)
	if err := enableCmd.Run(); err != nil {
		logger.Warn("Failed to enable service", 
			zap.String("service", serviceName),
			zap.Error(err))
	}
	
	// Start the service
	startCmd := exec.CommandContext(rc.Ctx, "systemctl", "start", serviceName)
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start %s: %w", serviceName, err)
	}
	
	logger.Info("Service enabled and started", zap.String("service", serviceName))
	return nil
}

// CheckPortAvailable checks if a port is available for binding
func CheckPortAvailable(port int) error {
	cmd := exec.Command("ss", "-tln")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat if ss is not available
		cmd = exec.Command("netstat", "-tln")
		output, err = cmd.Output()
		if err != nil {
			// Can't check, assume available
			return nil
		}
	}
	
	portStr := fmt.Sprintf(":%d", port)
	if strings.Contains(string(output), portStr) {
		return fmt.Errorf("port %d is already in use", port)
	}
	
	return nil
}

// InstallNginx installs nginx using the package manager
func InstallNginx(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing nginx")
	
	// Update package list
	updateCmd := exec.CommandContext(rc.Ctx, "apt-get", "update", "-qq")
	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}
	
	// Install nginx and modules
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y", "-qq",
		"nginx",
		"nginx-module-geoip",
		"nginx-module-image-filter",
		"nginx-module-perl",
		"nginx-module-xslt")
	
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install nginx: %w", err)
	}
	
	logger.Info("Nginx installed successfully")
	return nil
}

// InstallCaddy installs caddy using the official repository
func InstallCaddy(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Caddy")
	
	// Add Caddy GPG key
	keyCmd := exec.CommandContext(rc.Ctx, "bash", "-c",
		"curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo apt-key add -")
	if err := keyCmd.Run(); err != nil {
		return fmt.Errorf("failed to add Caddy GPG key: %w", err)
	}
	
	// Add Caddy repository
	repoCmd := exec.CommandContext(rc.Ctx, "bash", "-c",
		"curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list")
	if err := repoCmd.Run(); err != nil {
		return fmt.Errorf("failed to add Caddy repository: %w", err)
	}
	
	// Update package list
	updateCmd := exec.CommandContext(rc.Ctx, "apt-get", "update", "-qq")
	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}
	
	// Install Caddy
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y", "-qq", "caddy")
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install Caddy: %w", err)
	}
	
	logger.Info("Caddy installed successfully")
	return nil
}