package dev_environment

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallCodeServer installs code-server for the specified user
func InstallCodeServer(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if already installed
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", fmt.Sprintf("code-server@%s", config.User)},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		logger.Info("code-server already installed and running")
		return nil
	}

	// Download and install code-server
	logger.Info("Downloading code-server", zap.String("version", CodeServerVersion))
	
	debURL := fmt.Sprintf(CodeServerURL, CodeServerVersion, CodeServerVersion)
	debFile := fmt.Sprintf("/tmp/code-server_%s_amd64.deb", CodeServerVersion)
	
	// Download the deb file
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-fsSL", "-o", debFile, debURL},
		Timeout: InstallTimeout,
	}); err != nil {
		return fmt.Errorf("failed to download code-server: %w", err)
	}
	defer func() { _ = os.Remove(debFile) }()

	// Install the deb package
	logger.Info("Installing code-server package")
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-i", debFile},
		Timeout: InstallTimeout,
	}); err != nil {
		// Try to fix dependencies if dpkg fails
		logger.Debug("dpkg failed, attempting to fix dependencies")
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"install", "-f", "-y"},
			Timeout: InstallTimeout,
		})
		
		// Retry installation
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "dpkg",
			Args:    []string{"-i", debFile},
			Timeout: InstallTimeout,
		}); err != nil {
			return fmt.Errorf("failed to install code-server package: %w", err)
		}
	}

	logger.Info("code-server installed successfully")
	return nil
}

// ConfigureCodeServer configures code-server for the user and returns access information
func ConfigureCodeServer(rc *eos_io.RuntimeContext, config *Config) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create config directory for user
	userHome := fmt.Sprintf("/home/%s", config.User)
	if config.User == "root" {
		userHome = "/root"
	}
	
	configDir := filepath.Join(userHome, ".config", "code-server")
	configFile := filepath.Join(configDir, "config.yaml")
	
	// Create directory with proper ownership
	if err := os.MkdirAll(configDir, shared.ServiceDirPerm); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Set ownership
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "chown",
		Args:    []string{"-R", fmt.Sprintf("%s:%s", config.User, config.User), filepath.Join(userHome, ".config")},
		Timeout: 10 * time.Second,
	}); err != nil {
		logger.Warn("Failed to set config directory ownership", zap.Error(err))
	}

	// Generate or use provided password
	password := config.Password
	if password == "" {
		// Generate a secure password
		password = generatePassword()
		logger.Info("Generated password for code-server")
	}

	// Get the server's IP addresses
	ipAddresses, err := getServerIPAddresses(rc)
	if err != nil {
		logger.Warn("Failed to get server IP addresses", zap.Error(err))
		ipAddresses = []string{"localhost"}
	}

	// Create config file
	configContent := fmt.Sprintf(`bind-addr: 0.0.0.0:%d
auth: password
password: %s
cert: false
`, CodeServerPort, password)

	if err := os.WriteFile(configFile, []byte(configContent), shared.SecretFilePerm); err != nil {
		return "", fmt.Errorf("failed to write config file: %w", err)
	}

	// Set ownership of config file
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "chown",
		Args:    []string{fmt.Sprintf("%s:%s", config.User, config.User), configFile},
		Timeout: 5 * time.Second,
	}); err != nil {
		logger.Warn("Failed to set config file ownership", zap.Error(err))
	}

	// Enable and start the service
	logger.Info("Enabling code-server service")
	serviceName := fmt.Sprintf("code-server@%s", config.User)
	
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", serviceName},
		Timeout: 10 * time.Second,
	}); err != nil {
		return "", fmt.Errorf("failed to enable code-server service: %w", err)
	}

	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", serviceName},
		Timeout: 30 * time.Second,
	}); err != nil {
		return "", fmt.Errorf("failed to start code-server service: %w", err)
	}

	// Wait for service to be ready
	time.Sleep(3 * time.Second)

	// Build access information
	var accessInfo strings.Builder
	accessInfo.WriteString("Code-Server Access Information:\n")
	accessInfo.WriteString("================================\n")
	accessInfo.WriteString(fmt.Sprintf("Password: %s\n\n", password))
	accessInfo.WriteString("Access URLs:\n")
	
	for _, ip := range ipAddresses {
		accessInfo.WriteString(fmt.Sprintf("  • http://%s:%d\n", ip, CodeServerPort))
	}
	
	if isTailscaleIP := findTailscaleIP(ipAddresses); isTailscaleIP != "" {
		accessInfo.WriteString(fmt.Sprintf("\nTailscale URL: http://%s:%d\n", isTailscaleIP, CodeServerPort))
	}

	return accessInfo.String(), nil
}

// InstallClaudeExtension installs the Claude Code extension
func InstallClaudeExtension(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// We need to install the extension as the user
	// The extension ID for Claude Code is: anthropic.claude-code
	
	logger.Info("Installing Claude Code extension")
	
	// Run code-server command to install extension
	installCmd := fmt.Sprintf("sudo -u %s code-server --install-extension anthropic.claude-code", config.User)
	
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "bash",
		Args:    []string{"-c", installCmd},
		Timeout: 2 * time.Minute,
	}); err != nil {
		// Try alternative approach - download and install manually
		logger.Debug("Direct installation failed, trying manual approach")
		
		// Get extension directory
		userHome := fmt.Sprintf("/home/%s", config.User)
		if config.User == "root" {
			userHome = "/root"
		}
		extensionDir := filepath.Join(userHome, ".local", "share", "code-server", "extensions")
		
		// Create directory
		if err := os.MkdirAll(extensionDir, shared.ServiceDirPerm); err != nil {
			return fmt.Errorf("failed to create extensions directory: %w", err)
		}
		
		// Set ownership
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "chown",
			Args:    []string{"-R", fmt.Sprintf("%s:%s", config.User, config.User), filepath.Join(userHome, ".local")},
			Timeout: 5 * time.Second,
		})
		
		return fmt.Errorf("automatic installation failed, please install Claude Code extension manually from VS Code marketplace")
	}
	
	logger.Info("Claude Code extension installed successfully")
	return nil
}

// Helper functions

func generatePassword() string {
	// Use URL-safe password for code-server web authentication
	// This avoids issues with special characters in web auth headers and URLs
	password, err := crypto.GenerateURLSafePassword(16)
	if err != nil {
		// Fallback: generate from crypto/rand directly using URL-safe chars
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
		passwordBytes := make([]byte, 16)
		randomBytes := make([]byte, 16)

		if _, readErr := rand.Read(randomBytes); readErr != nil {
			// This should never happen, but if it does, panic is appropriate
			// as we cannot generate secure passwords
			panic(fmt.Sprintf("crypto/rand failed: %v", readErr))
		}

		for i, b := range randomBytes {
			passwordBytes[i] = chars[int(b)%len(chars)]
		}
		return string(passwordBytes)
	}
	return password
}

func getServerIPAddresses(rc *eos_io.RuntimeContext) ([]string, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "hostname",
		Args:    []string{"-I"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	
	ips := strings.Fields(output)
	
	// Also get hostname
	hostname, _ := execute.Run(rc.Ctx, execute.Options{
		Command: "hostname",
		Capture: true,
		Timeout: 5 * time.Second,
	})
	hostname = strings.TrimSpace(hostname)
	
	if hostname != "" && hostname != "localhost" {
		ips = append([]string{hostname}, ips...)
	}
	
	return ips, nil
}

func findTailscaleIP(ips []string) string {
	for _, ip := range ips {
		if strings.HasPrefix(ip, "100.") {
			return ip
		}
	}
	return ""
}