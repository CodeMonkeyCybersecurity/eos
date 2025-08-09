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
	
	// Phase 1: ASSESS
	ci.progress.Update("[16%] Checking current Consul status")
	if err := ci.assess(); err != nil {
		return fmt.Errorf("assessment failed: %w", err)
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
func (ci *ConsulInstaller) assess() error {
	ci.logger.Info("Assessing current Consul installation")
	
	// Check if Consul service exists
	if _, err := ci.systemd.GetStatus(); err == nil {
		if !ci.config.ForceReinstall {
			// Check if it's running
			if ci.systemd.IsActive() {
				ci.logger.Info("Consul is already installed and running")
				return nil
			}
			ci.logger.Info("Consul is installed but not running")
		} else {
			ci.logger.Info("Force reinstall requested, proceeding with installation")
			if ci.config.CleanInstall {
				if err := ci.cleanExistingInstallation(); err != nil {
					return fmt.Errorf("failed to clean existing installation: %w", err)
				}
			}
		}
	}
	
	return nil
}

// validatePrerequisites checks system requirements
func (ci *ConsulInstaller) validatePrerequisites() error {
	ci.logger.Info("Validating prerequisites")
	
	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}
	
	// Check memory requirements (minimum 256MB recommended)
	if err := ci.checkMemory(); err != nil {
		return err
	}
	
	// Check disk space (minimum 100MB for Consul)
	if err := ci.checkDiskSpace("/var/lib", 100); err != nil {
		return err
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
	
	for _, port := range requiredPorts {
		if err := ci.checkPortAvailable(port); err != nil {
			return err
		}
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
	if err := ci.downloadFile(downloadURL, zipPath); err != nil {
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

// configure sets up Consul configuration
func (ci *ConsulInstaller) configure() error {
	ci.logger.Info("Configuring Consul")
	
	// Create consul user and group
	if err := ci.user.CreateSystemUser("consul", "/var/lib/consul"); err != nil {
		return fmt.Errorf("failed to create consul user: %w", err)
	}
	
	// Create required directories
	directories := []struct {
		path  string
		mode  os.FileMode
		owner string
	}{
		{"/etc/consul.d", 0755, "consul"},
		{"/var/lib/consul", 0755, "consul"},
		{"/var/log/consul", 0755, "consul"},
	}
	
	for _, dir := range directories {
		if err := ci.createDirectory(dir.path, dir.mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir.path, err)
		}
		if err := ci.runner.Run("chown", "-R", dir.owner+":"+dir.owner, dir.path); err != nil {
			return fmt.Errorf("failed to set ownership for %s: %w", dir.path, err)
		}
	}
	
	// Backup existing configuration if present
	configPath := "/etc/consul.d/consul.hcl"
	if ci.fileExists(configPath) {
		if err := ci.files.BackupFile(configPath); err != nil {
			ci.logger.Warn("Failed to backup existing configuration", zap.Error(err))
		}
	}
	
	// Write HCL configuration
	hclConfig := ci.generateHCLConfig()
	if err := ci.writeFile(configPath, []byte(hclConfig), 0644); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}
	
	// Set proper ownership
	if err := ci.runner.Run("chown", "consul:consul", configPath); err != nil {
		return fmt.Errorf("failed to set configuration ownership: %w", err)
	}
	
	// Validate configuration
	ci.logger.Info("Validating Consul configuration")
	if output, err := ci.runner.RunOutput(ci.config.BinaryPath, "validate", "/etc/consul.d"); err != nil {
		return fmt.Errorf("configuration validation failed: %w (output: %s)", err, output)
	}
	
	return nil
}

// generateHCLConfig generates HCL format configuration
func (ci *ConsulInstaller) generateHCLConfig() string {
	var sb strings.Builder
	sb.WriteString("# Consul configuration managed by Eos\n")
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

// Helper methods for various operations

func (ci *ConsulInstaller) checkMemory() error {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		ci.logger.Warn("Could not check memory", zap.Error(err))
		return nil
	}
	
	totalMB := info.Totalram / 1024 / 1024
	if totalMB < 256 {
		return fmt.Errorf("insufficient memory: %dMB (minimum 256MB required)", totalMB)
	}
	
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
	// Use ss command to check if port is in use
	output, err := ci.runner.RunOutput("sh", "-c", fmt.Sprintf("ss -tln | grep -q ':%d ' && echo 'in-use' || echo 'available'", port))
	if err != nil {
		// If command fails, assume port is available
		return nil
	}
	
	if strings.TrimSpace(output) == "in-use" {
		return fmt.Errorf("port %d is already in use", port)
	}
	
	return nil
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

func (ci *ConsulInstaller) downloadFile(url, dest string) error {
	// Download using wget
	if err := ci.runner.Run("wget", "-O", dest, url); err != nil {
		return err
	}
	return nil
}

func (ci *ConsulInstaller) httpGet(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 10*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := ci.network.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
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