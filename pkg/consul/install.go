// pkg/consul/install.go

package consul

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// ConsulInstaller handles Consul installation using native methods
type ConsulInstaller struct {
	rc       *eos_io.RuntimeContext
	config   *InstallConfig
	logger   otelzap.LoggerWithCtx
	runner   *CommandRunner
	systemd  *SystemdService
	dirs     *DirectoryManager
	files    *FileManager
	progress *ProgressReporter
	user     *UserHelper
	validate *ValidationHelper
	network  *HTTPClient
}

// InstallConfig contains all configuration for Consul installation
type InstallConfig struct {
	// Installation method
	Version       string // Version to install (e.g., "1.21.3" or "latest")
	UseRepository bool   // Use APT repository vs direct binary download
	BinaryPath    string // Path for binary installation
	
	// Consul configuration
	Datacenter      string
	ServerMode      bool
	BootstrapExpect int
	UIEnabled       bool
	ConnectEnabled  bool
	BindAddr        string
	ClientAddr      string
	LogLevel        string
	
	// Integration options
	VaultIntegration bool
	VaultAddr        string
	
	// Installation behavior
	ForceReinstall bool // Force reinstallation even if already installed
	CleanInstall   bool // Remove existing data before installation
	DryRun         bool // Dry run mode
}

// NewConsulInstaller creates a new Consul installer instance
func NewConsulInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *ConsulInstaller {
	// Set defaults
	if config.Version == "" {
		config.Version = "latest"
	}
	if config.Datacenter == "" {
		config.Datacenter = "dc1"
	}
	if config.BindAddr == "" {
		config.BindAddr = getDefaultBindAddr()
	}
	if config.ClientAddr == "" {
		config.ClientAddr = "0.0.0.0"
	}
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	if config.BinaryPath == "" {
		config.BinaryPath = "/usr/bin/consul"
	}
	
	logger := otelzap.Ctx(rc.Ctx)
	runner := NewCommandRunner(rc)
	
	return &ConsulInstaller{
		rc:       rc,
		config:   config,
		logger:   logger,
		runner:   runner,
		systemd:  NewSystemdService(runner, "consul"),
		dirs:     NewDirectoryManager(runner),
		files:    NewFileManager(runner),
		progress: NewProgressReporter(logger, "Consul Installation", 100),
		user:     NewUserHelper(runner),
		validate: NewValidationHelper(logger),
		network:  NewHTTPClient(30 * time.Second),
	}
}

// Install performs the complete Consul installation
func (ci *ConsulInstaller) Install() error {
	ci.logger.Info("Starting Consul installation",
		zap.String("version", ci.config.Version),
		zap.String("datacenter", ci.config.Datacenter),
		zap.Bool("use_repository", ci.config.UseRepository))
	
	// Phase 1: ASSESS - Check if already installed
	ci.progress.Update("[16%] Checking current Consul status")
	shouldInstall, err := ci.assess()
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}
	
	// If Consul is already properly installed and running, we're done
	if !shouldInstall {
		ci.logger.Info("Consul is already installed and running properly")
		ci.progress.Complete("Consul is already installed and running")
		return nil
	}
	
	// Phase 2: Prerequisites
	ci.progress.Update("[33%] Validating prerequisites")
	if err := ci.validatePrerequisites(); err != nil {
		return fmt.Errorf("prerequisite validation failed: %w", err)
	}
	
	// Phase 3: INTERVENE - Install
	ci.progress.Update("[50%] Installing Consul binary")
	if err := ci.installBinary(); err != nil {
		return fmt.Errorf("binary installation failed: %w", err)
	}
	
	// Phase 4: Configure
	ci.progress.Update("[66%] Configuring Consul")
	if err := ci.configure(); err != nil {
		return fmt.Errorf("configuration failed: %w", err)
	}
	
	// Phase 5: Setup Service
	ci.progress.Update("[83%] Setting up systemd service")
	if err := ci.setupService(); err != nil {
		return fmt.Errorf("service setup failed: %w", err)
	}
	
	// Phase 6: EVALUATE - Verify
	ci.progress.Update("[100%] Verifying installation")
	if err := ci.verify(); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	
	ci.progress.Complete("Consul installation completed successfully")
	return nil
}

// assess checks the current state of Consul installation
// Returns true if installation should proceed, false if already installed
func (ci *ConsulInstaller) assess() (bool, error) {
	ci.logger.Info("Assessing current Consul installation")
	
	// Create context with timeout for assessment operations
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 30*time.Second)
	defer cancel()
	
	// First, check if Consul binary exists
	if _, err := os.Stat(ci.config.BinaryPath); err == nil {
		// Binary exists, check version with context
		if output, err := ci.runner.RunOutput(ci.config.BinaryPath, "version"); err == nil {
			ci.logger.Info("Consul binary found", zap.String("output", output))
		}
	}
	
	// Check context cancellation
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	
	// Check if Consul service exists
	if status, err := ci.systemd.GetStatus(); err == nil {
		ci.logger.Info("Consul service found", zap.String("status", status))
		
		if !ci.config.ForceReinstall {
			// Check if it's running
			if ci.systemd.IsActive() {
				// Verify it's actually working
				if ci.isConsulReady() {
					ci.logger.Info("Consul is already installed and running properly")
					
					// Print service information
					ci.logger.Info(fmt.Sprintf("terminal prompt: ✅ Consul is already installed and running"))
					ci.logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", shared.PortConsul))
					ci.logger.Info("terminal prompt: ")
					ci.logger.Info("terminal prompt: To check status: consul members")
					ci.logger.Info("terminal prompt: To view logs: journalctl -u consul -f")
					
					return false, nil // Don't install, already running
				}
				ci.logger.Warn("Consul service is active but not responding properly")
				// Fall through to attempt repair/reinstall
			} else {
				ci.logger.Info("Consul is installed but not running")
				// Don't try to start it here - if it's not running, there's likely a reason
				// (broken config, missing dependencies, etc.)
				// Let Install() fix the underlying issue first, then start it properly
				ci.logger.Info("Service not running, will proceed with installation to fix any issues")
			}
		} else {
			ci.logger.Info("Force reinstall requested, proceeding with installation")
			if ci.config.CleanInstall {
				if err := ci.cleanExistingInstallation(); err != nil {
					return false, fmt.Errorf("failed to clean existing installation: %w", err)
				}
			}
		}
	}
	
	return true, nil // Proceed with installation
}

// validatePrerequisites checks system requirements
func (ci *ConsulInstaller) validatePrerequisites() error {
	ci.logger.Info("Validating prerequisites")
	
	// Validate configuration with better error context
	if ci.config.Version == "" {
		return eos_err.NewUserError("consul version must be specified")
	}
	
	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}
	
	// Create context for prerequisite checks
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 15*time.Second)
	defer cancel()
	
	// Check memory requirements (minimum 256MB recommended)
	if err := ci.checkMemoryWithContext(ctx); err != nil {
		return fmt.Errorf("memory check failed: %w", err)
	}
	
	// Check disk space (minimum 100MB for Consul)
	if err := ci.checkDiskSpaceWithContext(ctx, "/var/lib", 100); err != nil {
		return fmt.Errorf("disk space check failed: %w", err)
	}
	
	// Check port availability - but be smart about it
	// If we're doing a force reinstall, stop the existing service first
	if ci.config.ForceReinstall && ci.systemd.IsActive() {
		ci.logger.Info("Stopping existing Consul service for reinstallation")
		if err := ci.systemd.Stop(); err != nil {
			ci.logger.Warn("Failed to stop existing Consul service", zap.Error(err))
		}
		time.Sleep(2 * time.Second) // Give it time to release ports
	}
	
	// Check port availability
	requiredPorts := []int{
		shared.PortConsul,     // HTTP API (8161)
		8300,                   // Server RPC
		8301,                   // Serf LAN
		8302,                   // Serf WAN
		8502,                   // gRPC
		8600,                   // DNS
	}
	
	var portErrors []string
	for _, port := range requiredPorts {
		if err := ci.checkPortAvailable(port); err != nil {
			portErrors = append(portErrors, err.Error())
		}
	}
	
	if len(portErrors) > 0 {
		return fmt.Errorf("port availability check failed:\n  - %s", strings.Join(portErrors, "\n  - "))
	}
	
	return nil
}

// installBinary installs the Consul binary
func (ci *ConsulInstaller) installBinary() error {
	if ci.config.UseRepository {
		return ci.installViaRepository()
	}
	return ci.installViaBinary()
}

// installViaRepository installs Consul using APT repository
func (ci *ConsulInstaller) installViaRepository() error {
	ci.logger.Info("Installing Consul via HashiCorp APT repository")
	
	// Add HashiCorp GPG key
	ci.logger.Info("Adding HashiCorp GPG key")
	if output, err := ci.runner.RunOutput("sh", "-c",
		"wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg"); err != nil {
		return fmt.Errorf("failed to add GPG key: %w (output: %s)", err, output)
	}
	
	// Add HashiCorp repository
	ci.logger.Info("Adding HashiCorp repository")
	repoLine := fmt.Sprintf("deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com %s main",
		getUbuntuCodename())
	
	if err := ci.writeFile("/etc/apt/sources.list.d/hashicorp.list", []byte(repoLine), 0644); err != nil {
		return fmt.Errorf("failed to add repository: %w", err)
	}
	
	// Update package list
	ci.logger.Info("Updating package list")
	if err := ci.runner.Run("apt-get", "update"); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}
	
	// Install Consul package
	ci.logger.Info("Installing Consul package")
	installCmd := []string{"apt-get", "install", "-y"}
	if ci.config.Version != "latest" {
		installCmd = append(installCmd, fmt.Sprintf("consul=%s", ci.config.Version))
	} else {
		installCmd = append(installCmd, "consul")
	}
	
	if err := ci.runner.Run(installCmd[0], installCmd[1:]...); err != nil {
		return fmt.Errorf("failed to install Consul package: %w", err)
	}
	
	return nil
}

// installViaBinary downloads and installs Consul binary directly
func (ci *ConsulInstaller) installViaBinary() error {
	ci.logger.Info("Installing Consul via direct binary download")
	
	// Determine version to install
	version := ci.config.Version
	if version == "latest" {
		var err error
		version, err = ci.getLatestVersion()
		if err != nil {
			return fmt.Errorf("failed to determine latest version: %w", err)
		}
	}
	
	// Download binary
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "amd64"
	} else if arch == "arm64" {
		arch = "arm64"
	}
	
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_%s.zip",
		version, version, arch)
	
	ci.logger.Info("Downloading Consul binary",
		zap.String("version", version),
		zap.String("url", downloadURL))
	
	tmpDir := "/tmp/consul-install"
	if err := ci.createDirectory(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	
	zipPath := filepath.Join(tmpDir, "consul.zip")
	if err := ci.downloadFileWithWget(downloadURL, zipPath); err != nil {
		return fmt.Errorf("failed to download Consul: %w", err)
	}
	
	// Extract binary
	if err := ci.runner.Run("unzip", "-o", zipPath, "-d", tmpDir); err != nil {
		return fmt.Errorf("failed to extract Consul: %w", err)
	}
	
	// Install binary
	binaryPath := filepath.Join(tmpDir, "consul")
	if err := ci.runner.Run("install", "-m", "755", binaryPath, ci.config.BinaryPath); err != nil {
		return fmt.Errorf("failed to install binary: %w", err)
	}
	
	return nil
}

// DirectoryConfig represents a directory to be created with specific permissions
type DirectoryConfig struct {
	Path  string
	Mode  os.FileMode
	Owner string
}

// configure sets up Consul configuration
func (ci *ConsulInstaller) configure() error {
	ci.logger.Info("=== EXECUTING: configure() ===")
	ci.logger.Info("Configuring Consul")

	// Create context for configuration operations
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 30*time.Second)
	defer cancel()

	// Create consul user and group
	if err := ci.user.CreateSystemUser("consul", "/var/lib/consul"); err != nil {
		return fmt.Errorf("failed to create consul user: %w", err)
	}

	// Define required directories using struct for better organization
	directories := []DirectoryConfig{
		{Path: "/etc/consul.d", Mode: 0755, Owner: "consul"},
		{Path: "/var/lib/consul", Mode: 0755, Owner: "consul"},
		{Path: "/var/log/consul", Mode: 0755, Owner: "consul"},
		{Path: "/opt/consul", Mode: 0755, Owner: "consul"}, // Required by config generator
	}

	ci.logger.Info("Creating Consul directories",
		zap.Int("directory_count", len(directories)))

	// Create directories with proper error handling
	for _, dir := range directories {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := ci.createDirectory(dir.Path, dir.Mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir.Path, err)
		}
		ci.logger.Info("Created directory",
			zap.String("path", dir.Path),
			zap.String("mode", fmt.Sprintf("%o", dir.Mode)))

		// Set ownership after creation
		if err := ci.runner.Run("chown", "-R", dir.Owner+":"+dir.Owner, dir.Path); err != nil {
			ci.logger.Warn("Failed to set directory ownership",
				zap.String("path", dir.Path),
				zap.String("owner", dir.Owner),
				zap.Error(err))
		} else {
			ci.logger.Info("Set directory ownership",
				zap.String("path", dir.Path),
				zap.String("owner", dir.Owner))
		}
	}

	ci.logger.Info("All Consul directories created successfully")

	// IDEMPOTENCY: Check if service is in crash loop before regenerating config
	// If service is crash looping, stop it before changing config to prevent racing restarts
	configDir := "/etc/consul.d"
	needsReconfiguration := false

	// Check ALL .hcl files in config directory for deprecated directives
	ci.logger.Info("Scanning config directory for stale configurations",
		zap.String("config_dir", configDir))

	entries, err := os.ReadDir(configDir)
	if err != nil {
		ci.logger.Warn("Failed to read config directory",
			zap.String("config_dir", configDir),
			zap.Error(err))
	} else {
		ci.logger.Info("Found config directory entries",
			zap.Int("count", len(entries)))

		for _, entry := range entries {
			ci.logger.Debug("Checking directory entry",
				zap.String("name", entry.Name()),
				zap.Bool("is_dir", entry.IsDir()))

			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".hcl") {
				continue
			}

			fullPath := filepath.Join(configDir, entry.Name())
			ci.logger.Info("Scanning HCL file for deprecated directives",
				zap.String("file", fullPath))

			configContent, err := os.ReadFile(fullPath)
			if err != nil {
				ci.logger.Warn("Failed to read config file",
					zap.String("file", fullPath),
					zap.Error(err))
				continue
			}

			configStr := string(configContent)
			if strings.Contains(configStr, "log_file") {
				ci.logger.Warn("Detected deprecated log_file directive in config file",
					zap.String("config_file", fullPath))
				needsReconfiguration = true

				// Backup and remove the stale config file
				ci.logger.Info("Removing stale config file with deprecated directives",
					zap.String("config_file", fullPath))
				if err := ci.files.BackupFile(fullPath); err != nil {
					ci.logger.Warn("Failed to backup stale config",
						zap.String("file", fullPath),
						zap.Error(err))
				}
				if err := os.Remove(fullPath); err != nil {
					ci.logger.Warn("Failed to remove stale config",
						zap.String("file", fullPath),
						zap.Error(err))
				} else {
					ci.logger.Info("Successfully removed stale config file",
						zap.String("file", fullPath))
				}
			} else {
				ci.logger.Debug("Config file does not contain log_file directive",
					zap.String("file", fullPath))
			}
		}
	}

	// Check if service is crash looping (activating with failures)
	if status, err := ci.systemd.GetStatus(); err == nil {
		if strings.Contains(strings.ToLower(status), "activating") &&
		   strings.Contains(strings.ToLower(status), "exit-code") {
			ci.logger.Warn("Service is in crash loop, will stop before reconfiguration",
				zap.String("status", status))
			needsReconfiguration = true

			// Stop crash looping service before config change
			if err := ci.systemd.Stop(); err != nil {
				ci.logger.Warn("Failed to stop crash looping service",
					zap.Error(err))
			} else {
				ci.logger.Info("Stopped crash looping service for clean reconfiguration")
				// Give systemd a moment to fully stop
				time.Sleep(2 * time.Second)
			}
		}
	}

	// Log reconfiguration decision
	if needsReconfiguration {
		ci.logger.Info("Reconfiguration needed, will regenerate consul.hcl",
			zap.String("reason", "deprecated directives or crash loop detected"))
	}

	// Use the config generator with network interface detection
	// Convert InstallConfig to config.ConsulConfig
	consulConfig := &config.ConsulConfig{
		DatacenterName:     ci.config.Datacenter,
		EnableDebugLogging: ci.config.LogLevel == "DEBUG",
		VaultAvailable:     ci.config.VaultIntegration,
		BootstrapExpect:    ci.config.BootstrapExpect,
	}

	if err := config.Generate(ci.rc, consulConfig); err != nil {
		return fmt.Errorf("failed to generate configuration: %w", err)
	}

	// Validate configuration
	ci.logger.Info("Validating Consul configuration")
	output, err := ci.runner.RunOutput(ci.config.BinaryPath, "validate", "/etc/consul.d")

	// Always log validation output (success or failure)
	if output != "" {
		ci.logger.Info("Consul configuration validation output",
			zap.String("output", output))
	}

	if err != nil {
		ci.logger.Error("Consul configuration validation failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("configuration validation failed: %w (output: %s)", err, output)
	}

	ci.logger.Info("Consul configuration validation succeeded")
	ci.logger.Info("=== COMPLETED: configure() ===")
	return nil
}

// generateHCLConfig is deprecated - use config.Generate() instead
// Kept for backward compatibility only
func (ci *ConsulInstaller) generateHCLConfig() string {
	var sb strings.Builder
	sb.WriteString("# Consul configuration managed by Eos (DEPRECATED - use config.Generate)\n")
	sb.WriteString(fmt.Sprintf("datacenter = \"%s\"\n", ci.config.Datacenter))
	sb.WriteString("data_dir = \"/var/lib/consul\"\n")
	sb.WriteString(fmt.Sprintf("log_level = \"%s\"\n", ci.config.LogLevel))
	sb.WriteString(fmt.Sprintf("server = %t\n", ci.config.ServerMode))

	if ci.config.ServerMode {
		sb.WriteString(fmt.Sprintf("bootstrap_expect = %d\n", ci.config.BootstrapExpect))
	}

	sb.WriteString(fmt.Sprintf("bind_addr = \"%s\"\n", ci.config.BindAddr))
	sb.WriteString(fmt.Sprintf("client_addr = \"%s\"\n", ci.config.ClientAddr))
	sb.WriteString("\n")

	sb.WriteString("ui_config {\n")
	sb.WriteString(fmt.Sprintf("  enabled = %t\n", ci.config.UIEnabled))
	sb.WriteString("}\n\n")

	sb.WriteString("connect {\n")
	sb.WriteString(fmt.Sprintf("  enabled = %t\n", ci.config.ConnectEnabled))
	sb.WriteString("}\n\n")

	sb.WriteString("ports {\n")
	sb.WriteString(fmt.Sprintf("  http = %d\n", shared.PortConsul))
	sb.WriteString("  dns = 8600\n")
	sb.WriteString("  grpc = 8502\n")
	sb.WriteString("}\n\n")

	sb.WriteString("performance {\n")
	sb.WriteString("  raft_multiplier = 1\n")
	sb.WriteString("}")

	return sb.String()
}

// setupService configures and starts the Consul systemd service
func (ci *ConsulInstaller) setupService() error {
	ci.logger.Info("Setting up Consul systemd service")
	
	// Create systemd service file
	binaryPath := ci.config.BinaryPath
	if ci.config.UseRepository {
		// Repository installation puts binary in /usr/bin
		binaryPath = "/usr/bin/consul"
	}
	
	serviceContent := fmt.Sprintf(`[Unit]
Description=Consul
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
Type=simple
User=consul
Group=consul
ExecStart=%s agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binaryPath)
	
	servicePath := "/etc/systemd/system/consul.service"
	if err := ci.writeFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}
	
	// Reload systemd
	if err := ci.runner.Run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	
	// Enable service
	if err := ci.systemd.Enable(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	
	// Start service with retries
	ci.logger.Info("Starting Consul service")
	if err := ci.systemd.Start(); err != nil {
		// Get service status for debugging
		if status, statusErr := ci.systemd.GetStatus(); statusErr == nil {
			ci.logger.Error("Failed to start Consul service", 
				zap.String("status", status))
		}
		return fmt.Errorf("failed to start service: %w", err)
	}
	
	// Wait for Consul to be ready
	ci.logger.Info("Waiting for Consul to be ready")
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 30*time.Second)
	defer cancel()
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Consul to be ready")
		case <-ticker.C:
			if ci.isConsulReady() {
				ci.logger.Info("Consul is ready")
				return nil
			}
		}
	}
}

// verify performs post-installation verification
func (ci *ConsulInstaller) verify() error {
	ci.logger.Info("Verifying Consul installation")
	
	// Check service status
	if !ci.systemd.IsActive() {
		return fmt.Errorf("Consul service is not active")
	}
	
	// Check API endpoint
	apiURL := fmt.Sprintf("http://127.0.0.1:%d/v1/agent/self", shared.PortConsul)
	resp, err := ci.httpGet(apiURL)
	if err != nil {
		return fmt.Errorf("failed to connect to Consul API: %w", err)
	}
	
	var agentInfo map[string]interface{}
	if err := json.Unmarshal(resp, &agentInfo); err != nil {
		return fmt.Errorf("failed to parse API response: %w", err)
	}
	
	// Check cluster members
	membersURL := fmt.Sprintf("http://127.0.0.1:%d/v1/agent/members", shared.PortConsul)
	membersResp, err := ci.httpGet(membersURL)
	if err != nil {
		ci.logger.Warn("Failed to get cluster members", zap.Error(err))
	} else {
		var members []map[string]interface{}
		if err := json.Unmarshal(membersResp, &members); err == nil {
			ci.logger.Info("Cluster has members", zap.Int("count", len(members)))
		}
	}
	
	// Log success information
	ci.logger.Info("Consul installation verified successfully",
		zap.String("datacenter", ci.config.Datacenter),
		zap.Bool("server_mode", ci.config.ServerMode),
		zap.String("api_url", fmt.Sprintf("http://%s:%d", ci.config.BindAddr, shared.PortConsul)))
	
	return nil
}

// isConsulReady checks if Consul is ready to accept requests
func (ci *ConsulInstaller) isConsulReady() bool {
	// Try to connect to the API
	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("127.0.0.1:%d", shared.PortConsul)
	
	client, err := api.NewClient(config)
	if err != nil {
		return false
	}
	
	// Check agent status
	_, err = client.Agent().Self()
	return err == nil
}

// cleanExistingInstallation removes existing Consul installation
func (ci *ConsulInstaller) cleanExistingInstallation() error {
	ci.logger.Info("Cleaning existing Consul installation")
	
	// Stop service if running
	if ci.systemd.IsActive() {
		if err := ci.systemd.Stop(); err != nil {
			ci.logger.Warn("Failed to stop Consul service", zap.Error(err))
		}
	}
	
	// Remove data directory
	if err := os.RemoveAll("/var/lib/consul"); err != nil {
		ci.logger.Warn("Failed to remove data directory", zap.Error(err))
	}
	
	// Remove log directory
	if err := os.RemoveAll("/var/log/consul"); err != nil {
		ci.logger.Warn("Failed to remove log directory", zap.Error(err))
	}
	
	return nil
}

// getLatestVersion fetches the latest Consul version from HashiCorp
func (ci *ConsulInstaller) getLatestVersion() (string, error) {
	// Query HashiCorp checkpoint API
	resp, err := ci.httpGet("https://checkpoint-api.hashicorp.com/v1/check/consul")
	if err != nil {
		return "", fmt.Errorf("failed to fetch version info: %w", err)
	}
	
	var versionInfo struct {
		CurrentVersion string `json:"current_version"`
	}
	
	if err := json.Unmarshal(resp, &versionInfo); err != nil {
		return "", fmt.Errorf("failed to parse version info: %w", err)
	}
	
	if versionInfo.CurrentVersion == "" {
		return "", fmt.Errorf("no version found in response")
	}
	
	return versionInfo.CurrentVersion, nil
}

// checkMemoryWithContext checks available system memory with context support
func (ci *ConsulInstaller) checkMemoryWithContext(ctx context.Context) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	
	// Use a more portable approach to check memory
	cmd := exec.Command("free", "-m")
	output, err := cmd.Output()
	if err != nil {
		ci.logger.Warn("Could not check memory", zap.Error(err))
		return nil // Non-fatal, continue installation
	}
	
	// Parse free command output to get total memory
	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return nil
	}
	
	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return nil
	}
	
	totalMB := 0
	if _, err := fmt.Sscanf(fields[1], "%d", &totalMB); err != nil {
		return nil
	}
	if totalMB < 256 {
		return eos_err.NewUserError("insufficient memory: %dMB (minimum 256MB required)", totalMB)
	}
	
	ci.logger.Debug("Memory check passed", zap.Int("totalMB", totalMB))
	return nil
}

// checkDiskSpaceWithContext checks available disk space with context support
func (ci *ConsulInstaller) checkDiskSpaceWithContext(ctx context.Context, path string, requiredMB int64) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		ci.logger.Warn("Could not check disk space", zap.String("path", path), zap.Error(err))
		return nil // Non-fatal, continue installation
	}
	
	availableMB := int64(stat.Bavail) * int64(stat.Bsize) / 1024 / 1024
	if availableMB < requiredMB {
		return eos_err.NewUserError("insufficient disk space in %s: %dMB available (minimum %dMB required)", 
			path, availableMB, requiredMB)
	}
	
	ci.logger.Debug("Disk space check passed", 
		zap.String("path", path),
		zap.Int64("availableMB", availableMB),
		zap.Int64("requiredMB", requiredMB))
	return nil
}

func (ci *ConsulInstaller) checkDiskSpace(path string, requiredMB int64) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		ci.logger.Warn("Could not check disk space", zap.Error(err))
		return nil
	}
	
	availableMB := int64(stat.Bavail) * int64(stat.Bsize) / 1024 / 1024
	if availableMB < requiredMB {
		return fmt.Errorf("insufficient disk space in %s: %dMB available (minimum %dMB required)", 
			path, availableMB, requiredMB)
	}
	
	return nil
}

func (ci *ConsulInstaller) checkPortAvailable(port int) error {
	// Use lsof to check what's using the port
	output, err := ci.runner.RunOutput("sh", "-c", fmt.Sprintf("lsof -i :%d 2>/dev/null | grep LISTEN | awk '{print $1}' | head -1", port))
	if err != nil || output == "" {
		// Port is available
		return nil
	}
	
	processName := strings.TrimSpace(output)
	
	// If it's Consul already using the port, that's fine for idempotency
	if processName == "consul" {
		ci.logger.Debug("Port already in use by Consul", zap.Int("port", port))
		// Check if this is our Consul or another instance
		if ci.systemd.IsActive() {
			// It's our managed Consul, that's OK
			return nil
		}
		// It's another Consul instance
		return fmt.Errorf("port %d is already in use by another Consul instance", port)
	}
	
	// Some other process is using the port
	return fmt.Errorf("port %d is already in use by %s", port, processName)
}

func (ci *ConsulInstaller) createDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return nil
}

func (ci *ConsulInstaller) writeFile(path string, content []byte, mode os.FileMode) error {
	return os.WriteFile(path, content, mode)
}

func (ci *ConsulInstaller) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// downloadFileWithWget downloads a file using wget with proper error handling
func (ci *ConsulInstaller) downloadFileWithWget(url, dest string) error {
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 5*time.Minute)
	defer cancel()
	
	ci.logger.Info("Downloading file with wget", 
		zap.String("url", url), 
		zap.String("dest", dest))
	
	// Use wget with timeout
	cmd := exec.CommandContext(ctx, "wget", "-O", dest, url)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to download %s to %s: %w", url, dest, err)
	}
	
	return nil
}

// httpGet performs HTTP GET request with proper error wrapping and context handling
func (ci *ConsulInstaller) httpGet(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 10*time.Second)
	defer cancel()
	
	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET request failed for %s: %w", url, err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s for URL %s", resp.StatusCode, resp.Status, url)
	}
	
	return io.ReadAll(resp.Body)
}

// getDefaultBindAddr returns the default bind address (first non-loopback IP)
func getDefaultBindAddr() string {
	cmd := exec.Command("hostname", "-I")
	output, err := cmd.Output()
	if err != nil {
		return "127.0.0.1"
	}
	
	ips := strings.Fields(string(output))
	if len(ips) > 0 {
		return ips[0]
	}
	
	return "127.0.0.1"
}

// getUbuntuCodename returns the Ubuntu codename for APT repository
func getUbuntuCodename() string {
	cmd := exec.Command("lsb_release", "-cs")
	output, err := cmd.Output()
	if err != nil {
		return "noble" // Default to latest LTS
	}
	
	return strings.TrimSpace(string(output))
}

// Legacy function for backward compatibility
func InstallConsul(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	// Convert old config to new format
	installConfig := &InstallConfig{
		Version:          config.Version,
		UseRepository:    config.UseRepository,
		Datacenter:       config.Datacenter,
		ServerMode:       config.Mode == "server",
		BootstrapExpect:  config.BootstrapExpect,
		UIEnabled:        config.EnableUI || config.UI,
		ConnectEnabled:   config.ConnectEnabled,
		BindAddr:         config.BindAddr,
		ClientAddr:       config.ClientAddr,
		LogLevel:         config.LogLevel,
		VaultIntegration: config.VaultIntegration,
		ForceReinstall:   config.Force,
		CleanInstall:     config.Clean,
	}
	
	installer := NewConsulInstaller(rc, installConfig)
	return installer.Install()
}

// Additional helper functions for Consul operations

// CheckConsulHealth verifies Consul cluster health
func CheckConsulHealth(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("127.0.0.1:%d", shared.PortConsul)
	
	client, err := api.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}
	
	// Check agent health
	health, _, err := client.Health().Node("_agent", nil)
	if err != nil {
		return fmt.Errorf("failed to check agent health: %w", err)
	}
	
	for _, check := range health {
		if check.Status != "passing" {
			logger.Warn("Health check not passing",
				zap.String("check", check.Name),
				zap.String("status", check.Status),
				zap.String("output", check.Output))
		}
	}
	
	return nil
}

// GetConsulMembers returns the list of Consul cluster members
func GetConsulMembers(rc *eos_io.RuntimeContext) ([]string, error) {
	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("127.0.0.1:%d", shared.PortConsul)
	
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}
	
	members, err := client.Agent().Members(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get members: %w", err)
	}
	
	var memberList []string
	for _, member := range members {
		memberList = append(memberList, member.Name)
	}
	
	return memberList, nil
}

// RestartConsul performs a safe Consul restart
func RestartConsul(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restarting Consul service")
	
	runner := NewCommandRunner(rc)
	systemd := NewSystemdService(runner, "consul")
	
	// Gracefully stop
	if err := systemd.Stop(); err != nil {
		return fmt.Errorf("failed to stop Consul: %w", err)
	}
	
	// Wait a moment
	time.Sleep(2 * time.Second)
	
	// Start again
	if err := systemd.Start(); err != nil {
		return fmt.Errorf("failed to start Consul: %w", err)
	}
	
	// Wait for it to be ready
	installer := &ConsulInstaller{
		rc:      rc,
		logger:  logger,
		network: NewHTTPClient(30 * time.Second),
		config:  &InstallConfig{},
	}
	
	ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
	defer cancel()
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Consul to be ready after restart")
		case <-ticker.C:
			if installer.isConsulReady() {
				logger.Info("Consul restarted successfully")
				return nil
			}
		}
	}
}