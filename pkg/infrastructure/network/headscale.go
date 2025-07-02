package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HeadscaleConfig represents the configuration for Headscale setup
type HeadscaleConfig struct {
	ServerURL     string   `json:"server_url"`
	Username      string   `json:"username"`
	ConfigDir     string   `json:"config_dir"`
	DatabasePath  string   `json:"database_path"`
	FirewallPorts []string `json:"firewall_ports"`
	Interactive   bool     `json:"interactive"`
}

// HeadscaleStatus represents the current state of Headscale
type HeadscaleStatus struct {
	Installed     bool   `json:"installed"`
	Running       bool   `json:"running"`
	Version       string `json:"version"`
	ConfigExists  bool   `json:"config_exists"`
	DatabaseReady bool   `json:"database_ready"`
	Users         []HeadscaleUser `json:"users"`
	PreAuthKeys   []PreAuthKey    `json:"preauth_keys"`
}

// HeadscaleUser represents a Headscale user
type HeadscaleUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PreAuthKey represents a pre-authentication key
type PreAuthKey struct {
	ID         string `json:"id"`
	Key        string `json:"key"`
	Reusable   bool   `json:"reusable"`
	Expiration string `json:"expiration"`
	Used       bool   `json:"used"`
}

// InstallHeadscale performs a complete Headscale installation and setup
func InstallHeadscale(rc *eos_io.RuntimeContext, config *HeadscaleConfig) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.InstallHeadscale")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting Headscale installation", zap.String("server_url", config.ServerURL))

	// Set defaults
	if config.ConfigDir == "" {
		config.ConfigDir = "/etc/headscale"
	}
	if config.DatabasePath == "" {
		config.DatabasePath = "/var/lib/headscale/db.sqlite"
	}
	if len(config.FirewallPorts) == 0 {
		config.FirewallPorts = []string{"80/tcp", "443/tcp", "41641/udp"}
	}

	// Check current status
	status, err := GetHeadscaleStatus(rc)
	if err != nil {
		logger.Warn("Failed to get initial Headscale status", zap.Error(err))
		status = &HeadscaleStatus{}
	}

	// Update system
	if err := updateSystem(rc); err != nil {
		return fmt.Errorf("system update failed: %w", err)
	}

	// Install dependencies
	if err := installDependencies(rc); err != nil {
		return fmt.Errorf("dependency installation failed: %w", err)
	}

	// Download and install Headscale if not already installed
	if !status.Installed {
		if err := downloadAndInstallHeadscale(rc); err != nil {
			return fmt.Errorf("headscale installation failed: %w", err)
		}
	}

	// Create configuration directory
	if err := os.MkdirAll(config.ConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate and configure Headscale
	if !status.ConfigExists {
		if err := generateHeadscaleConfig(rc, config); err != nil {
			return fmt.Errorf("configuration generation failed: %w", err)
		}
	}

	// Setup database
	if !status.DatabaseReady {
		if err := setupHeadscaleDatabase(rc); err != nil {
			return fmt.Errorf("database setup failed: %w", err)
		}
	}

	// Create systemd service
	if err := createHeadscaleService(rc); err != nil {
		return fmt.Errorf("service creation failed: %w", err)
	}

	// Start and enable service
	if err := enableAndStartHeadscale(rc); err != nil {
		return fmt.Errorf("service startup failed: %w", err)
	}

	// Create user and generate pre-auth key
	if config.Interactive {
		if err := interactiveUserSetup(rc, config); err != nil {
			logger.Warn("Interactive user setup failed", zap.Error(err))
		}
	}

	// Configure firewall
	if err := configureFirewall(rc, config.FirewallPorts); err != nil {
		logger.Warn("Firewall configuration failed", zap.Error(err))
	}

	logger.Info("Headscale installation completed successfully")
	return nil
}

// GetHeadscaleStatus returns the current status of Headscale
func GetHeadscaleStatus(rc *eos_io.RuntimeContext) (*HeadscaleStatus, error) {
	ctx, span := telemetry.Start(rc.Ctx, "network.GetHeadscaleStatus")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Checking Headscale status")

	status := &HeadscaleStatus{}

	// Check if Headscale is installed
	if _, err := execute.Run(ctx, execute.Options{
		Command: "headscale",
		Args:    []string{"version"},
		Capture: true,
	}); err == nil {
		status.Installed = true
		
		// Get version
		if output, err := execute.Run(ctx, execute.Options{
			Command: "headscale",
			Args:    []string{"version"},
			Capture: true,
		}); err == nil {
			status.Version = strings.TrimSpace(output)
		}
	}

	// Check if service is running
	if _, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "headscale"},
		Capture: true,
	}); err == nil {
		status.Running = true
	}

	// Check if config exists
	if _, err := os.Stat("/etc/headscale/headscale.conf"); err == nil {
		status.ConfigExists = true
	}

	// Check database
	if _, err := os.Stat("/var/lib/headscale/db.sqlite"); err == nil {
		status.DatabaseReady = true
	}

	// Get users if Headscale is running
	if status.Running {
		users, err := listHeadscaleUsers(rc)
		if err == nil {
			status.Users = users
		}
	}

	logger.Info("Headscale status checked", 
		zap.Bool("installed", status.Installed),
		zap.Bool("running", status.Running),
		zap.String("version", status.Version))

	return status, nil
}

// updateSystem updates the package manager
func updateSystem(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.updateSystem")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Updating system packages")

	_, err := execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"apt", "update"},
	})
	if err != nil {
		return err
	}

	_, err = execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"apt", "upgrade", "-y"},
	})
	return err
}

// installDependencies installs required packages
func installDependencies(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.installDependencies")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Installing dependencies")

	_, err := execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"apt", "install", "curl", "jq", "-y"},
	})
	return err
}

// downloadAndInstallHeadscale downloads and installs the latest Headscale
func downloadAndInstallHeadscale(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.downloadAndInstallHeadscale")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Downloading latest Headscale version")

	// Get latest version
	versionOutput, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "https://api.github.com/repos/juanfont/headscale/releases/latest"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to get latest version: %w", err)
	}

	// Parse version from JSON (simplified)
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal([]byte(versionOutput), &release); err != nil {
		return fmt.Errorf("failed to parse version JSON: %w", err)
	}

	version := release.TagName
	logger.Info("Latest Headscale version found", zap.String("version", version))

	// Construct download URL
	architecture := "amd64" // Default to amd64, could be dynamic
	downloadURL := fmt.Sprintf("https://github.com/juanfont/headscale/releases/download/%s/headscale_%s_linux_%s",
		version, version, architecture)

	// Download Headscale
	logger.Info("Downloading Headscale binary", zap.String("url", downloadURL))
	_, err = execute.Run(ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-Lo", "headscale", downloadURL},
	})
	if err != nil {
		return fmt.Errorf("failed to download Headscale: %w", err)
	}

	// Make executable and move to /usr/local/bin
	if err := os.Chmod("headscale", 0755); err != nil {
		return fmt.Errorf("failed to make Headscale executable: %w", err)
	}

	_, err = execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"mv", "headscale", "/usr/local/bin/"},
	})
	if err != nil {
		return fmt.Errorf("failed to install Headscale: %w", err)
	}

	logger.Info("Headscale installed successfully")
	return nil
}

// generateHeadscaleConfig generates the Headscale configuration file
func generateHeadscaleConfig(rc *eos_io.RuntimeContext, config *HeadscaleConfig) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.generateHeadscaleConfig")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Generating Headscale configuration")

	// Generate default config
	output, err := execute.Run(ctx, execute.Options{
		Command: "headscale",
		Args:    []string{"generate", "config"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Write config to file
	configPath := filepath.Join(config.ConfigDir, "headscale.conf")
	if err := os.WriteFile(configPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Update server URL if provided
	if config.ServerURL != "" && config.Interactive {
		serverURL, err := interaction.PromptUser(rc, fmt.Sprintf("Enter server URL (current: %s)", config.ServerURL))
		if err != nil {
			return err
		}
		if strings.TrimSpace(serverURL) != "" {
			config.ServerURL = strings.TrimSpace(serverURL)
		}
	}

	if config.ServerURL == "" && config.Interactive {
		serverURL, err := interaction.PromptUser(rc, "Enter the server URL for Headscale (e.g., http://localhost:8080)")
		if err != nil {
			return err
		}
		if strings.TrimSpace(serverURL) == "" {
			return eos_err.NewExpectedError(ctx, fmt.Errorf("server URL cannot be empty"))
		}
		config.ServerURL = strings.TrimSpace(serverURL)
	}

	// Update server URL in config file
	if config.ServerURL != "" {
		_, err = execute.Run(ctx, execute.Options{
			Command: "sudo",
			Args:    []string{"sed", "-i", fmt.Sprintf("s|^server_url:.*|server_url: %s|", config.ServerURL), configPath},
		})
		if err != nil {
			logger.Warn("Failed to update server URL in config", zap.Error(err))
		}
	}

	logger.Info("Headscale configuration generated", zap.String("config_path", configPath))
	return nil
}

// setupHeadscaleDatabase initializes the Headscale database
func setupHeadscaleDatabase(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.setupHeadscaleDatabase")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Setting up Headscale database")

	// Create database directory
	if err := os.MkdirAll("/var/lib/headscale", 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Run database migration
	_, err := execute.Run(ctx, execute.Options{
		Command: "headscale",
		Args:    []string{"migrate"},
	})
	if err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}

	logger.Info("Headscale database setup completed")
	return nil
}

// createHeadscaleService creates the systemd service file
func createHeadscaleService(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.createHeadscaleService")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Creating Headscale systemd service")

	serviceContent := `[Unit]
Description=Headscale
After=network.target

[Service]
Type=notify
User=root
ExecStart=/usr/local/bin/headscale serve
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

	servicePath := "/etc/systemd/system/headscale.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	// Reload systemd
	_, err := execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"systemctl", "daemon-reload"},
	})
	if err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	logger.Info("Headscale systemd service created")
	return nil
}

// enableAndStartHeadscale enables and starts the Headscale service
func enableAndStartHeadscale(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.enableAndStartHeadscale")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Enabling and starting Headscale service")

	// Enable service
	_, err := execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"systemctl", "enable", "headscale"},
	})
	if err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service
	_, err = execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"systemctl", "start", "headscale"},
	})
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	logger.Info("Headscale service enabled and started")
	return nil
}

// interactiveUserSetup handles interactive user creation and pre-auth key generation
func interactiveUserSetup(rc *eos_io.RuntimeContext, config *HeadscaleConfig) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.interactiveUserSetup")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting interactive user setup")

	// Prompt for username
	if config.Username == "" {
		username, err := interaction.PromptUser(rc, "Enter a username for Headscale")
		if err != nil {
			return err
		}
		if strings.TrimSpace(username) == "" {
			return eos_err.NewExpectedError(ctx, fmt.Errorf("username cannot be empty"))
		}
		config.Username = strings.TrimSpace(username)
	}

	// Create user
	_, err := execute.Run(ctx, execute.Options{
		Command: "headscale",
		Args:    []string{"users", "create", config.Username},
	})
	if err != nil {
		logger.Warn("User creation failed (user might already exist)", zap.Error(err))
	}

	// Generate pre-auth key
	output, err := execute.Run(ctx, execute.Options{
		Command: "headscale",
		Args:    []string{"preauthkeys", "create", "--reusable", "--expiration", "24h", "--user", config.Username},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to generate pre-auth key: %w", err)
	}

	// Extract key from output (simplified parsing)
	lines := strings.Split(output, "\n")
	var preAuthKey string
	for _, line := range lines {
		if strings.Contains(line, "key:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				preAuthKey = parts[1]
				break
			}
		}
	}

	logger.Info("User setup completed", 
		zap.String("username", config.Username),
		zap.String("preauth_key", preAuthKey))

	return nil
}

// configureFirewall opens necessary ports
func configureFirewall(rc *eos_io.RuntimeContext, ports []string) error {
	ctx, span := telemetry.Start(rc.Ctx, "network.configureFirewall")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Configuring firewall", zap.Strings("ports", ports))

	for _, port := range ports {
		_, err := execute.Run(ctx, execute.Options{
			Command: "sudo",
			Args:    []string{"ufw", "allow", port},
		})
		if err != nil {
			logger.Warn("Failed to open port", zap.String("port", port), zap.Error(err))
		}
	}

	logger.Info("Firewall configuration completed")
	return nil
}

// listHeadscaleUsers returns the list of Headscale users
func listHeadscaleUsers(rc *eos_io.RuntimeContext) ([]HeadscaleUser, error) {
	ctx, span := telemetry.Start(rc.Ctx, "network.listHeadscaleUsers")
	defer span.End()

	output, err := execute.Run(ctx, execute.Options{
		Command: "headscale",
		Args:    []string{"users", "list"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	// Parse output (simplified)
	var users []HeadscaleUser
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "ID") && !strings.Contains(line, "---") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				users = append(users, HeadscaleUser{
					ID:   fields[0],
					Name: fields[1],
				})
			}
		}
	}

	return users, nil
}