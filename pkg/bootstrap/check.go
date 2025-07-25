package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BootstrapStatus represents the bootstrap state of the machine
type BootstrapStatus struct {
	Bootstrapped        bool
	SaltInstalled       bool
	SaltAPIConfigured   bool
	FileRootsConfigured bool
	NetworkConfigured   bool
	SecurityConfigured  bool
	Timestamp           time.Time
	Version             string
	Issues              []string
}

// CheckBootstrap performs a comprehensive bootstrap check
func CheckBootstrap(rc *eos_io.RuntimeContext) (*BootstrapStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Performing bootstrap status check")

	status := &BootstrapStatus{
		Timestamp: time.Now(),
		Issues:    []string{},
	}

	// Check 1: Salt Installation
	if installed, version := checkSaltInstalled(rc); installed {
		status.SaltInstalled = true
		status.Version = version
		logger.Debug("Salt is installed", zap.String("version", version))
	} else {
		status.Issues = append(status.Issues, "SaltStack is not installed")
	}

	// Check 2: Salt API Configuration
	if apiConfigured := checkSaltAPIConfigured(rc); apiConfigured {
		status.SaltAPIConfigured = true
		logger.Debug("Salt API is configured")
	} else {
		status.Issues = append(status.Issues, "Salt API is not configured")
	}

	// Check 3: File Roots Configuration
	if fileRootsOK := checkFileRootsConfigured(rc); fileRootsOK {
		status.FileRootsConfigured = true
		logger.Debug("File roots are properly configured")
	} else {
		status.Issues = append(status.Issues, "Salt file_roots are not properly configured")
	}

	// Check 4: Network Configuration (basic checks)
	if networkOK := checkNetworkConfiguration(rc); networkOK {
		status.NetworkConfigured = true
		logger.Debug("Network configuration looks good")
	} else {
		status.Issues = append(status.Issues, "Network configuration may need attention")
	}

	// Check 5: Security Configuration (basic checks)
	if securityOK := checkSecurityConfiguration(rc); securityOK {
		status.SecurityConfigured = true
		logger.Debug("Basic security configuration is in place")
	} else {
		status.Issues = append(status.Issues, "Security configuration needs attention")
	}

	// Check 6: Bootstrap marker file
	if _, err := os.Stat("/etc/eos/bootstrapped"); err == nil {
		status.Bootstrapped = true
		logger.Debug("Bootstrap marker file found")
	}

	// Overall bootstrap status
	if status.SaltInstalled && status.SaltAPIConfigured && status.FileRootsConfigured && len(status.Issues) == 0 {
		status.Bootstrapped = true
	}

	return status, nil
}

// RequireBootstrap checks if the system is bootstrapped and returns an error if not
func RequireBootstrap(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	status, err := CheckBootstrap(rc)
	if err != nil {
		return fmt.Errorf("failed to check bootstrap status: %w", err)
	}

	if !status.Bootstrapped {
		logger.Error("System is not bootstrapped",
			zap.Bool("salt_installed", status.SaltInstalled),
			zap.Bool("api_configured", status.SaltAPIConfigured),
			zap.Bool("file_roots_ok", status.FileRootsConfigured),
			zap.Strings("issues", status.Issues))

		// Provide helpful error message
		logger.Info("terminal prompt: ❌ ERROR: This system has not been bootstrapped!")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: The Eos bootstrap process prepares your system for:")
		logger.Info("terminal prompt:   • Configuration management with SaltStack")
		logger.Info("terminal prompt:   • Secure API communication")
		logger.Info("terminal prompt:   • Service orchestration and deployment")
		logger.Info("terminal prompt:   • Automated system management")
		logger.Info("terminal prompt: ")
		
		if len(status.Issues) > 0 {
			logger.Info("terminal prompt: Issues detected:")
			for _, issue := range status.Issues {
				logger.Info(fmt.Sprintf("terminal prompt:   ✗ %s", issue))
			}
			logger.Info("terminal prompt: ")
		}
		
		logger.Info("terminal prompt: To bootstrap this system, run:")
		logger.Info("terminal prompt:   sudo eos bootstrap")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Or for a complete setup with all components:")
		logger.Info("terminal prompt:   sudo eos bootstrap all")
		
		return fmt.Errorf("system not bootstrapped - run 'sudo eos bootstrap' first")
	}

	logger.Debug("Bootstrap check passed")
	return nil
}

// checkSaltInstalled checks if Salt is installed
func checkSaltInstalled(rc *eos_io.RuntimeContext) (bool, string) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--version"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil {
		return false, ""
	}

	// Parse version from output
	version := "unknown"
	if output != "" {
		// Output format: "salt-call 3006.3"
		parts := strings.Fields(output)
		if len(parts) >= 2 {
			version = parts[1]
		}
	}

	return true, version
}

// checkSaltAPIConfigured checks if Salt API is configured and accessible
func checkSaltAPIConfigured(rc *eos_io.RuntimeContext) bool {
	// Check if API credentials exist
	if _, err := saltstack.LoadAPICredentials(); err != nil {
		return false
	}

	// Check if API service is running
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "salt-api"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil || strings.TrimSpace(output) != "active" {
		return false
	}

	// Check if API endpoint responds
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-k", "-s", "-o", "/dev/null", "-w", "%{http_code}", "https://localhost:8000"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	httpCode := strings.TrimSpace(output)
	return httpCode == "401" || httpCode == "200" // 401 is expected without auth
}

// checkFileRootsConfigured verifies Salt file_roots are properly set up
func checkFileRootsConfigured(rc *eos_io.RuntimeContext) bool {
	// Check if required directories exist
	requiredDirs := []string{
		"/srv/salt",
		"/opt/eos/salt/states",
	}

	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return false
		}
	}

	// Check if symlinks are correct
	expectedLink := "/srv/salt/hashicorp"
	if target, err := os.Readlink(expectedLink); err != nil || target != "/opt/eos/salt/states/hashicorp" {
		return false
	}

	return true
}

// checkNetworkConfiguration performs basic network checks
func checkNetworkConfiguration(rc *eos_io.RuntimeContext) bool {
	// Basic check - can we resolve DNS?
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "getent",
		Args:    []string{"hosts", "github.com"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	return err == nil && output != ""
}

// checkSecurityConfiguration performs basic security checks
func checkSecurityConfiguration(rc *eos_io.RuntimeContext) bool {
	// Check if UFW is installed (common Ubuntu firewall)
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"ufw"},
		Capture: true,
		Timeout: 2 * time.Second,
	})

	// For now, just check if firewall tool exists
	// More comprehensive checks can be added
	return err == nil
}

// MarkBootstrapped creates a marker file indicating successful bootstrap
func MarkBootstrapped(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create eos directory if it doesn't exist
	if err := os.MkdirAll("/etc/eos", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/eos directory: %w", err)
	}

	// Create bootstrap marker file with metadata
	content := fmt.Sprintf(`# Eos Bootstrap Marker
# Generated: %s
# Version: 1.0
bootstrapped=true
timestamp=%d
`, time.Now().Format(time.RFC3339), time.Now().Unix())

	if err := os.WriteFile("/etc/eos/bootstrapped", []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create bootstrap marker: %w", err)
	}

	logger.Info("System marked as bootstrapped")
	return nil
}