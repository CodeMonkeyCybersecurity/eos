package consul

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NativeInstaller handles direct Consul installation without configuration management
type NativeInstaller struct {
	rc       *eos_io.RuntimeContext
	config   *InstallConfig
	runner   *CommandRunner
	systemd  *SystemdService
	dirMgr   *DirectoryManager
	fileMgr  *FileManager
	userMgr  *UserHelper
	progress *ProgressReporter
}

// InstallConfig contains configuration for Consul installation
type InstallConfig struct {
	Version           string
	Datacenter        string
	ServerMode        bool
	BootstrapExpect   int
	UIEnabled         bool
	ConnectEnabled    bool
	VaultIntegration  bool
	LogLevel          string
	BindAddr          string
	ClientAddr        string
	ForceReinstall    bool
	CleanInstall      bool
	UseRepository     bool // Use APT repository vs direct binary
}

// NewNativeInstaller creates a new native Consul installer
func NewNativeInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *NativeInstaller {
	// Set defaults
	if config.Version == "" {
		config.Version = "latest"
	}
	if config.Datacenter == "" {
		config.Datacenter = "dc1"
	}
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	if config.BindAddr == "" {
		config.BindAddr = "0.0.0.0"
	}
	if config.ClientAddr == "" {
		config.ClientAddr = "0.0.0.0"
	}
	if config.BootstrapExpect == 0 {
		config.BootstrapExpect = 1
	}

	runner := NewCommandRunner(rc)
	
	return &NativeInstaller{
		rc:       rc,
		config:   config,
		runner:   runner,
		systemd:  NewSystemdService(runner, "consul"),
		dirMgr:   NewDirectoryManager(runner),
		fileMgr:  NewFileManager(runner),
		userMgr:  NewUserHelper(runner),
		progress: nil, // Will be initialized when needed
	}
}

// Install performs the complete Consul installation
func (n *NativeInstaller) Install() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	
	logger.Info("Starting native Consul installation",
		zap.String("version", n.config.Version),
		zap.String("datacenter", n.config.Datacenter),
		zap.Bool("use_repository", n.config.UseRepository))

	// Initialize progress reporter
	n.progress = NewProgressReporter(logger, "Consul Installation", 6)

	// ASSESS - Check current state
	n.progress.Update("Checking current Consul status")
	status, err := n.checkCurrentStatus()
	if err != nil {
		logger.Warn("Could not determine current Consul status", zap.Error(err))
		status = &ConsulStatus{}
	}

	// Check idempotency
	if status.Running && status.ConfigValid && !n.config.ForceReinstall && !n.config.CleanInstall {
		n.progress.Complete("Consul is already installed and running successfully")
		return nil
	}

	// Validate prerequisites
	n.progress.Update("Validating prerequisites")
	if err := n.validatePrerequisites(); err != nil {
		n.progress.Failed("Prerequisites validation failed", err)
		return fmt.Errorf("prerequisites validation failed: %w", err)
	}

	// Clean install if requested
	if n.config.CleanInstall {
		n.progress.Update("Performing clean installation")
		if err := n.cleanExistingInstallation(); err != nil {
			n.progress.Failed("Clean installation failed", err)
			return fmt.Errorf("failed to clean existing installation: %w", err)
		}
	}

	// INTERVENE - Install Consul
	n.progress.Update("Installing Consul binary")
	if n.config.UseRepository {
		if err := n.installViaRepository(); err != nil {
			n.progress.Failed("Repository installation failed", err)
			return fmt.Errorf("repository installation failed: %w", err)
		}
	} else {
		if err := n.installViaBinary(); err != nil {
			n.progress.Failed("Binary installation failed", err)
			return fmt.Errorf("binary installation failed: %w", err)
		}
	}

	// Configure Consul
	n.progress.Update("Configuring Consul")
	if err := n.configure(); err != nil {
		n.progress.Failed("Configuration failed", err)
		return fmt.Errorf("configuration failed: %w", err)
	}

	// Setup and start service
	n.progress.Update("Setting up systemd service")
	if err := n.setupService(); err != nil {
		n.progress.Failed("Service setup failed", err)
		return fmt.Errorf("service setup failed: %w", err)
	}

	// EVALUATE - Verify installation
	n.progress.Update("Verifying installation")
	if err := n.verify(); err != nil {
		n.progress.Failed("Verification failed", err)
		return fmt.Errorf("verification failed: %w", err)
	}

	n.progress.Complete("Consul installation completed successfully")
	logger.Info("Consul installation completed successfully",
		zap.String("version", n.config.Version),
		zap.Int("http_port", shared.PortConsul))

	return nil
}

// checkCurrentStatus checks if Consul is already installed and running
func (n *NativeInstaller) checkCurrentStatus() (*ConsulStatus, error) {
	logger := otelzap.Ctx(n.rc.Ctx)
	status := &ConsulStatus{}

	// Check if binary exists
	if err := n.runner.RunQuiet("which", "consul"); err == nil {
		status.Installed = true
		
		// Get version
		if output, err := n.runner.RunOutput("consul", "version"); err == nil {
			lines := strings.Split(output, "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// Check service status using helper
	if n.systemd.IsActive() {
		status.Running = true
		status.ServiceStatus = "active"
	} else if n.systemd.IsFailed() {
		status.Failed = true
		status.ServiceStatus = "failed"
	}

	// Validate configuration if Consul is installed
	if status.Installed && fileExists("/etc/consul.d/consul.hcl") {
		if err := n.runner.RunQuiet("consul", "validate", "/etc/consul.d/"); err == nil {
			status.ConfigValid = true
		}
	}

	logger.Debug("Current Consul status",
		zap.Bool("installed", status.Installed),
		zap.Bool("running", status.Running),
		zap.Bool("config_valid", status.ConfigValid),
		zap.String("version", status.Version))

	return status, nil
}

// cleanExistingInstallation removes all Consul data and configuration
func (n *NativeInstaller) cleanExistingInstallation() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Cleaning existing Consul installation")

	// Stop and disable service using helper
	n.systemd.Stop()
	n.systemd.Disable()

	// Kill any remaining processes
	n.runner.RunQuiet("pkill", "-f", "consul")

	// Remove directories using helper
	dirsToRemove := []string{
		"/etc/consul.d",
		"/etc/consul",
		"/var/lib/consul",
		"/var/log/consul",
	}

	for _, dir := range dirsToRemove {
		if err := n.dirMgr.RemoveIfExists(dir); err != nil {
			logger.Warn("Failed to remove directory", 
				zap.String("dir", dir), 
				zap.Error(err))
		}
	}

	// Reset systemd
	n.runner.RunQuiet("systemctl", "reset-failed", "consul.service")
	n.systemd.ReloadDaemon()

	return nil
}

// installViaRepository installs Consul using HashiCorp's APT repository
func (n *NativeInstaller) installViaRepository() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Installing Consul via HashiCorp APT repository")

	// Add HashiCorp GPG key with retry
	logger.Info("Adding HashiCorp GPG key")
	gpgCmd := `wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg`
	if err := n.runner.RunWithRetries("bash", []string{"-c", gpgCmd}, 3); err != nil {
		return fmt.Errorf("failed to add GPG key: %w. Try checking your internet connection", err)
	}

	// Add repository
	logger.Info("Adding HashiCorp repository")
	repoCmd := `echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list`
	if err := n.runner.Run("bash", "-c", repoCmd); err != nil {
		return fmt.Errorf("failed to add repository: %w", err)
	}

	// Update package list with retry
	logger.Info("Updating package list")
	if err := n.runner.RunWithRetries("apt-get", []string{"update"}, 3); err != nil {
		return fmt.Errorf("failed to update package list: %w. Try running 'sudo apt-get update' manually", err)
	}

	// Install Consul
	logger.Info("Installing Consul package")
	installArgs := []string{"install", "-y"}
	if n.config.Version != "latest" {
		installArgs = append(installArgs, fmt.Sprintf("consul=%s", n.config.Version))
	} else {
		installArgs = append(installArgs, "consul")
	}

	if err := n.runner.RunWithRetries("apt-get", installArgs, 3); err != nil {
		return fmt.Errorf("failed to install Consul: %w. Check if the version %s exists", err, n.config.Version)
	}

	return nil
}

// installViaBinary downloads and installs Consul binary directly
func (n *NativeInstaller) installViaBinary() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	
	// Resolve version
	version := n.config.Version
	if version == "latest" {
		resolvedVersion, err := n.resolveLatestVersion()
		if err != nil {
			logger.Warn("Failed to resolve latest version, using fallback", zap.Error(err))
			version = "1.17.1" // Fallback version
		} else {
			version = resolvedVersion
		}
	}

	logger.Info("Installing Consul via direct binary download",
		zap.String("version", version))

	// Download binary
	zipPath := fmt.Sprintf("/tmp/consul_%s_linux_amd64.zip", version)
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_amd64.zip", version, version)
	
	logger.Info("Downloading Consul binary", zap.String("url", downloadURL))
	if err := n.downloadFile(downloadURL, zipPath); err != nil {
		return fmt.Errorf("failed to download Consul: %w", err)
	}

	// Verify checksum
	logger.Info("Verifying checksum")
	if err := n.verifyChecksum(zipPath, version); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	// Extract binary
	logger.Info("Extracting Consul binary")
	if err := n.runner.Run("unzip", "-o", zipPath, "-d", "/usr/local/bin/"); err != nil {
		return fmt.Errorf("failed to extract Consul: %w", err)
	}

	// Set permissions
	if err := os.Chmod("/usr/local/bin/consul", 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Create symlink for compatibility
	os.Remove("/usr/bin/consul") // Remove if exists
	if err := os.Symlink("/usr/local/bin/consul", "/usr/bin/consul"); err != nil {
		logger.Warn("Failed to create symlink", zap.Error(err))
	}

	// Cleanup
	os.Remove(zipPath)

	return nil
}

// resolveLatestVersion determines the latest Consul version
func (n *NativeInstaller) resolveLatestVersion() (string, error) {
	ctx, cancel := context.WithTimeout(n.rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/hashicorp/consul/releases/latest", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Eos-Consul-Installer/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	// Remove 'v' prefix if present
	version := strings.TrimPrefix(release.TagName, "v")
	
	return version, nil
}

// downloadFile downloads a file from URL to destination
func (n *NativeInstaller) downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// verifyChecksum verifies the SHA256 checksum of the downloaded file
func (n *NativeInstaller) verifyChecksum(filepath, version string) error {
	// Download checksum file
	checksumURL := fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_SHA256SUMS", version, version)
	checksumPath := "/tmp/consul_checksums.txt"
	
	if err := n.downloadFile(checksumURL, checksumPath); err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}
	defer os.Remove(checksumPath)

	// Read checksum file
	checksumData, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}

	// Find the checksum for our file
	expectedChecksum := ""
	lines := strings.Split(string(checksumData), "\n")
	targetFile := fmt.Sprintf("consul_%s_linux_amd64.zip", version)
	for _, line := range lines {
		if strings.Contains(line, targetFile) {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				expectedChecksum = parts[0]
				break
			}
		}
	}

	if expectedChecksum == "" {
		return fmt.Errorf("checksum not found for %s", targetFile)
	}

	// Calculate actual checksum
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// configure writes the Consul configuration
func (n *NativeInstaller) configure() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Configuring Consul")

	// Create consul user if it doesn't exist
	if err := n.userMgr.CreateSystemUser("consul", "/var/lib/consul"); err != nil {
		return fmt.Errorf("failed to create consul user: %w", err)
	}

	// Create directories with ownership
	dirs := []string{
		"/etc/consul.d",
		"/var/lib/consul",
		"/var/log/consul",
	}

	for _, dir := range dirs {
		if err := n.dirMgr.CreateWithOwnership(dir, "consul", "consul", 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Determine bind address
	bindAddr := n.config.BindAddr
	if bindAddr == "0.0.0.0" {
		// Get first non-loopback IP
		if ip, err := n.getFirstNonLoopbackIP(); err == nil && ip != "" {
			bindAddr = ip
		} else {
			bindAddr = "127.0.0.1"
		}
	}

	// Write configuration file
	config := fmt.Sprintf(`# Consul configuration managed by Eos
datacenter = "%s"
data_dir = "/var/lib/consul"
log_level = "%s"
server = %t
bootstrap_expect = %d
bind_addr = "%s"
client_addr = "%s"

ui_config {
  enabled = %t
}

connect {
  enabled = %t
}

ports {
  http = %d
  dns = 8600
  grpc = 8502
}

performance {
  raft_multiplier = 1
}
`, n.config.Datacenter, n.config.LogLevel, n.config.ServerMode, 
   n.config.BootstrapExpect, bindAddr, n.config.ClientAddr,
   n.config.UIEnabled, n.config.ConnectEnabled, shared.PortConsul)

	// Backup existing configuration if it exists
	configPath := "/etc/consul.d/consul.hcl"
	if err := n.fileMgr.BackupFile(configPath); err != nil {
		logger.Warn("Failed to backup existing configuration", zap.Error(err))
	}

	// Write configuration with ownership
	if err := n.fileMgr.WriteWithOwnership(configPath, []byte(config), 0640, "consul", "consul"); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Validate configuration
	logger.Info("Validating Consul configuration")
	if err := n.runner.Run("consul", "validate", "/etc/consul.d/"); err != nil {
		return fmt.Errorf("configuration validation failed: %w. Check the configuration file at %s", err, configPath)
	}

	return nil
}

// setupService creates and starts the systemd service
func (n *NativeInstaller) setupService() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Setting up Consul systemd service")

	// Determine binary path
	binaryPath := "/usr/bin/consul"
	if _, err := os.Stat("/usr/local/bin/consul"); err == nil {
		binaryPath = "/usr/local/bin/consul"
	}

	// Write systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
Description=Consul
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
Type=notify
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
	if err := n.fileMgr.WriteWithOwnership(servicePath, []byte(serviceContent), 0644, "root", "root"); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd
	if err := n.systemd.ReloadDaemon(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	if err := n.systemd.Enable(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service with retries
	logger.Info("Starting Consul service")
	if err := n.systemd.Start(); err != nil {
		// Get service status for debugging
		if status, statusErr := n.systemd.GetStatus(); statusErr == nil {
			logger.Error("Failed to start Consul service", 
				zap.String("status", status))
		}
		return fmt.Errorf("failed to start service: %w. Check 'systemctl status consul' for details", err)
	}

	return nil
}

// verify checks that Consul is running correctly
func (n *NativeInstaller) verify() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Verifying Consul installation")

	// Wait for service to stabilize with exponential backoff
	maxRetries := 5
	for i := 1; i <= maxRetries; i++ {
		time.Sleep(time.Duration(i) * time.Second)
		
		// Check service is active
		if !n.systemd.IsActive() {
			if i == maxRetries {
				return fmt.Errorf("Consul service is not active after %d retries", maxRetries)
			}
			logger.Debug("Waiting for Consul service to become active", 
				zap.Int("attempt", i),
				zap.Int("max_retries", maxRetries))
			continue
		}
		
		// Check Consul members
		if err := n.runner.RunQuiet("consul", "members"); err == nil {
			break // Service is ready
		} else if i == maxRetries {
			return fmt.Errorf("Consul is not responding to commands after %d retries: %w", maxRetries, err)
		}
	}

	// Check API endpoint with retry
	apiURL := fmt.Sprintf("http://localhost:%d/v1/status/leader", shared.PortConsul)
	client := NewHTTPClient(10 * time.Second)
	
	resp, err := client.GetWithRetry(n.rc.Ctx, apiURL)
	if err != nil {
		return fmt.Errorf("Consul API is not accessible: %w. Ensure port %d is not blocked", err, shared.PortConsul)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Consul API returned status %d. Check logs with 'journalctl -u consul'", resp.StatusCode)
	}

	logger.Info("Consul verification successful")
	return nil
}

// validatePrerequisites checks if all prerequisites are met
func (n *NativeInstaller) validatePrerequisites() error {
	validator := NewValidationHelper(otelzap.Ctx(n.rc.Ctx))
	
	// Check root privileges
	validator.ValidatePermissions()
	
	// Check port availability
	validator.ValidatePort(shared.PortConsul)
	validator.ValidatePort(8600) // DNS port
	validator.ValidatePort(8502) // gRPC port
	
	// Check disk space (100MB minimum)
	validator.ValidateDiskSpace("/var/lib/consul", 100)
	
	if validator.HasErrors() {
		return validator.GetError()
	}
	
	return nil
}

// getFirstNonLoopbackIP returns the first non-loopback IP address
func (n *NativeInstaller) getFirstNonLoopbackIP() (string, error) {
	output, err := n.runner.RunOutput("hostname", "-I")
	if err != nil {
		return "", err
	}

	ips := strings.Fields(output)
	for _, ip := range ips {
		if !strings.HasPrefix(ip, "127.") && !strings.Contains(ip, "::") {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no non-loopback IP found")
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}