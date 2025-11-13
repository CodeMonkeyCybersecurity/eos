package dev_environment

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckPrerequisites verifies the system is ready for dev environment installation
func CheckPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking prerequisites for development environment")

	// Check if running as root (needed for systemd service installation)
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges, please run with sudo")
	}

	// Check Ubuntu version
	if _, err := os.Stat("/etc/os-release"); err != nil {
		return fmt.Errorf("cannot determine OS version, this command requires Ubuntu")
	}

	// Check for required commands
	requiredCommands := []string{"systemctl", "ufw", "curl", "apt-get"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command '%s' not found in PATH", cmd)
		}
	}

	// Check if port 8080 is already in use
	if err := checkPortAvailable(8080); err != nil {
		logger.Warn("Port 8080 may already be in use", zap.Error(err))
		// Not a fatal error, code-server might already be installed
	}

	logger.Info("All prerequisites satisfied")
	return nil
}

// GetCurrentUser returns the current non-root user
func GetCurrentUser(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// If running as sudo, get the original user
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		logger.Debug("Found SUDO_USER", zap.String("user", sudoUser))
		return sudoUser, nil
	}

	// Otherwise, use the current user (but warn if it's root)
	currentUser := os.Getenv("USER")
	if currentUser == "root" {
		logger.Warn("Running as root without SUDO_USER set, defaulting to root user")
	}

	return currentUser, nil
}

// checkPortAvailable checks if a port is available for binding
func checkPortAvailable(port int) error {
	// Use netstat or ss to check if port is in use
	cmd := exec.Command("ss", "-tlnp", fmt.Sprintf("sport = :%d", port))
	output, err := cmd.CombinedOutput()
	if err != nil {
		// ss command failed, try netstat
		cmd = exec.Command("netstat", "-tlnp")
		output, err = cmd.CombinedOutput()
		if err != nil {
			// Can't check, assume it's available
			return nil
		}
	}

	if len(output) > 0 && contains(string(output), fmt.Sprintf(":%d", port)) {
		return fmt.Errorf("port %d is already in use", port)
	}

	return nil
}

func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 1; i < len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
