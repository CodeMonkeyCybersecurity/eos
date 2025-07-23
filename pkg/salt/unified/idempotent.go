package unified

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// EnsureSaltInstalled ensures Salt is installed and configured
func (c *Client) EnsureSaltInstalled(ctx context.Context) error {
	logger := c.logger.With(zap.String("method", "EnsureSaltInstalled"))
	logger.Info("Ensuring Salt is installed")
	
	// ASSESS - Check if Salt is already installed
	if c.isBinaryAvailable(SaltCallBinaryName) {
		logger.Info("Salt is already installed")
		return nil
	}
	
	// INTERVENE - Install Salt using bootstrap script
	logger.Info("Installing Salt using bootstrap script")
	
	// Download and run the official Salt bootstrap script
	bootstrapCmd := `
		curl -L https://bootstrap.saltstack.com -o /tmp/bootstrap_salt.sh && \
		sudo sh /tmp/bootstrap_salt.sh -X stable && \
		rm -f /tmp/bootstrap_salt.sh
	`
	
	output, err := execute.Run(ctx, execute.Options{
		Command: "bash",
		Args:    []string{"-c", bootstrapCmd},
		Capture: true,
		Timeout: 10 * time.Minute,
	})
	
	if err != nil {
		return &SaltError{
			Type:    ErrorTypeConfig,
			Message: fmt.Sprintf("Salt installation failed: %s", err.Error()),
			Details: map[string]interface{}{"output": output},
			Cause:   err,
			Mode:    ModeUnavailable,
		}
	}
	
	// EVALUATE - Verify installation
	if !c.isBinaryAvailable(SaltCallBinaryName) {
		return &SaltError{
			Type:    ErrorTypeConfig,
			Message: "Salt installation completed but salt-call binary not found",
			Mode:    ModeUnavailable,
		}
	}
	
	logger.Info("Salt installation completed successfully")
	return nil
}

// EnsureSaltAPIConfigured ensures Salt API is configured
func (c *Client) EnsureSaltAPIConfigured(ctx context.Context) error {
	logger := c.logger.With(zap.String("method", "EnsureSaltAPIConfigured"))
	logger.Info("Ensuring Salt API is configured")
	
	// ASSESS - Check if Salt API is already configured
	if c.fileExists(c.config.ConfigPath) && c.isPackageInstalled("salt-api") {
		logger.Info("Salt API is already configured")
		return nil
	}
	
	// INTERVENE - Install and configure Salt API
	logger.Info("Installing and configuring Salt API")
	
	// Install salt-api package if not installed
	if !c.isPackageInstalled("salt-api") {
		logger.Info("Installing salt-api package")
		
		_, err := execute.Run(ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"update", "&&", "apt-get", "install", "-y", "salt-api"},
			Capture: true,
			Timeout: 5 * time.Minute,
		})
		
		if err != nil {
			return &SaltError{
				Type:    ErrorTypeConfig,
				Message: fmt.Sprintf("Failed to install salt-api package: %s", err.Error()),
				Cause:   err,
				Mode:    ModeLocal,
			}
		}
	}
	
	// Create API configuration
	if err := c.createAPIConfig(); err != nil {
		return fmt.Errorf("failed to create API configuration: %w", err)
	}
	
	// EVALUATE - Verify configuration
	if !c.fileExists(c.config.ConfigPath) {
		return &SaltError{
			Type:    ErrorTypeConfig,
			Message: "Salt API configuration file was not created",
			Mode:    ModeLocal,
		}
	}
	
	logger.Info("Salt API configuration completed successfully")
	return nil
}

// EnsureSaltAPIRunning ensures Salt API service is running
func (c *Client) EnsureSaltAPIRunning(ctx context.Context) error {
	logger := c.logger.With(zap.String("method", "EnsureSaltAPIRunning"))
	logger.Info("Ensuring Salt API service is running")
	
	// ASSESS - Check if Salt API is already running
	if c.isServiceActive("salt-api") {
		logger.Info("Salt API service is already running")
		return nil
	}
	
	// INTERVENE - Start Salt API service
	logger.Info("Starting Salt API service")
	
	// Enable and start the service
	commands := [][]string{
		{"systemctl", "enable", "salt-api"},
		{"systemctl", "start", "salt-api"},
	}
	
	for _, cmdArgs := range commands {
		output, err := execute.Run(ctx, execute.Options{
			Command: cmdArgs[0],
			Args:    cmdArgs[1:],
			Capture: true,
			Timeout: 30 * time.Second,
		})
		
		if err != nil {
			return &SaltError{
				Type:    ErrorTypeConfig,
				Message: fmt.Sprintf("Failed to start Salt API service: %s", err.Error()),
				Details: map[string]interface{}{"output": output, "command": strings.Join(cmdArgs, " ")},
				Cause:   err,
				Mode:    ModeLocal,
			}
		}
	}
	
	// Wait a moment for service to start
	time.Sleep(3 * time.Second)
	
	// EVALUATE - Verify service is running
	if !c.isServiceActive("salt-api") {
		return &SaltError{
			Type:    ErrorTypeConfig,
			Message: "Salt API service failed to start",
			Mode:    ModeLocal,
		}
	}
	
	logger.Info("Salt API service started successfully")
	return nil
}

// EnsureCredentialsConfigured ensures API credentials are configured
func (c *Client) EnsureCredentialsConfigured(ctx context.Context) error {
	logger := c.logger.With(zap.String("method", "EnsureCredentialsConfigured"))
	logger.Info("Ensuring Salt API credentials are configured")
	
	// ASSESS - Check if credentials are already available
	if c.hasCredentials() {
		logger.Info("Salt API credentials are already configured")
		return nil
	}
	
	// INTERVENE - Create or configure credentials
	logger.Info("Configuring Salt API credentials")
	
	username := c.config.Username
	password := c.config.Password
	
	// If password not provided in config, generate one
	if password == "" {
		var err error
		password, err = c.generateSecurePassword()
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
		c.config.Password = password
	}
	
	// Create system user for Salt API
	if err := c.createSaltAPIUser(ctx, username, password); err != nil {
		return fmt.Errorf("failed to create Salt API user: %w", err)
	}
	
	// Save credentials to file
	if err := SaveCredentialsToFile(c.config.CredentialsPath, username, password); err != nil {
		logger.Warn("Failed to save credentials to file", zap.Error(err))
		// Continue - credentials are still available in memory
	}
	
	// EVALUATE - Verify credentials work
	if !c.canAuthenticateToAPI(ctx) {
		return &SaltError{
			Type:    ErrorTypeAuth,
			Message: "Salt API credentials were configured but authentication still fails",
			Mode:    ModeLocal,
		}
	}
	
	logger.Info("Salt API credentials configured successfully")
	return nil
}

// createAPIConfig creates the Salt API configuration file
func (c *Client) createAPIConfig() error {
	configContent := `# Salt API Configuration - Generated by EOS

# Enable CherryPy REST API
rest_cherrypy:
  port: 8000
  host: 0.0.0.0
  disable_ssl: false
  ssl_crt: /etc/salt/api.crt
  ssl_key: /etc/salt/api.key

# Authentication
external_auth:
  pam:
    eos-service:
      - .*
      - '@wheel'
      - '@runner'

# Enable event publishing
event_return_queue: 10000
`
	
	// Ensure the directory exists
	configDir := filepath.Dir(c.config.ConfigPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Write configuration file
	if err := os.WriteFile(c.config.ConfigPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	// Generate SSL certificates if they don't exist
	if err := c.generateSSLCertificates(); err != nil {
		return fmt.Errorf("failed to generate SSL certificates: %w", err)
	}
	
	return nil
}

// createSaltAPIUser creates a system user for Salt API authentication
func (c *Client) createSaltAPIUser(ctx context.Context, username, password string) error {
	logger := c.logger.With(
		zap.String("method", "createSaltAPIUser"),
		zap.String("username", username))
	
	logger.Info("Creating Salt API user")
	
	// Check if user already exists
	if _, err := exec.LookPath("id"); err == nil {
		if output, err := exec.Command("id", username).Output(); err == nil {
			logger.Info("User already exists", zap.String("output", strings.TrimSpace(string(output))))
			// Update password anyway
			return c.setUserPassword(ctx, username, password)
		}
	}
	
	// Create the user
	createUserCmd := []string{
		"useradd",
		"--system",
		"--home-dir", "/var/lib/salt",
		"--shell", "/bin/false",
		"--comment", "Salt API Service User",
		username,
	}
	
	output, err := execute.Run(ctx, execute.Options{
		Command: createUserCmd[0],
		Args:    createUserCmd[1:],
		Capture: true,
		Timeout: 30 * time.Second,
	})
	
	if err != nil {
		// Check if error is because user already exists
		if strings.Contains(string(output), "already exists") {
			logger.Info("User already exists, updating password")
		} else {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}
	
	// Set user password
	if err := c.setUserPassword(ctx, username, password); err != nil {
		return fmt.Errorf("failed to set user password: %w", err)
	}
	
	// Add user to salt group if it exists
	if _, err := exec.Command("getent", "group", "salt").Output(); err == nil {
		logger.Debug("Adding user to salt group")
		
		_, err := execute.Run(ctx, execute.Options{
			Command: "usermod",
			Args:    []string{"-a", "-G", "salt", username},
			Capture: true,
		})
		
		if err != nil {
			logger.Warn("Failed to add user to salt group", zap.Error(err))
			// Not critical, continue
		}
	}
	
	logger.Info("Salt API user created successfully")
	return nil
}

// setUserPassword sets the password for a user securely
func (c *Client) setUserPassword(ctx context.Context, username, password string) error {
	// Use chpasswd to set password securely
	cmd := exec.CommandContext(ctx, "chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}
	
	return nil
}

// generateSSLCertificates generates self-signed SSL certificates for Salt API
func (c *Client) generateSSLCertificates() error {
	certPath := "/etc/salt/api.crt"
	keyPath := "/etc/salt/api.key"
	
	// Check if certificates already exist
	if c.fileExists(certPath) && c.fileExists(keyPath) {
		return nil
	}
	
	// Generate self-signed certificate
	opensslCmd := fmt.Sprintf(`
		openssl req -new -x509 -keyout %s -out %s -days 365 -nodes \
		-subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
	`, keyPath, certPath)
	
	cmd := exec.Command("bash", "-c", opensslCmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate SSL certificates: %w", err)
	}
	
	// Set appropriate permissions
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}
	
	if err := os.Chmod(certPath, 0644); err != nil {
		return fmt.Errorf("failed to set cert file permissions: %w", err)
	}
	
	return nil
}

// generateSecurePassword generates a secure random password
func (c *Client) generateSecurePassword() (string, error) {
	// Use openssl to generate a secure password
	cmd := exec.Command("openssl", "rand", "-base64", "32")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}
	
	// Clean up the password (remove newlines)
	password := strings.TrimSpace(string(output))
	return password, nil
}

// GetFullSetupStatus returns the status of all Salt components
func (c *Client) GetFullSetupStatus(ctx context.Context) (map[string]interface{}, error) {
	status := make(map[string]interface{})
	
	// Check Salt installation
	status["salt_installed"] = c.isBinaryAvailable(SaltCallBinaryName)
	status["salt_api_package_installed"] = c.isPackageInstalled("salt-api")
	
	// Check configuration
	status["api_config_exists"] = c.fileExists(c.config.ConfigPath)
	status["credentials_available"] = c.hasCredentials()
	
	// Check services
	status["salt_master_running"] = c.isServiceActive("salt-master")
	status["salt_minion_running"] = c.isServiceActive("salt-minion")
	status["salt_api_running"] = c.isServiceActive("salt-api")
	
	// Check connectivity
	status["api_connectable"] = c.canConnectToAPI(ctx)
	status["api_authenticated"] = c.canAuthenticateToAPI(ctx)
	
	// Overall assessment
	allConfigured := status["salt_installed"].(bool) &&
		status["salt_api_package_installed"].(bool) &&
		status["api_config_exists"].(bool) &&
		status["credentials_available"].(bool) &&
		status["salt_api_running"].(bool) &&
		status["api_connectable"].(bool) &&
		status["api_authenticated"].(bool)
	
	status["fully_configured"] = allConfigured
	
	if allConfigured {
		status["recommended_mode"] = "api"
	} else if status["salt_installed"].(bool) {
		status["recommended_mode"] = "local"
	} else {
		status["recommended_mode"] = "unavailable"
	}
	
	return status, nil
}