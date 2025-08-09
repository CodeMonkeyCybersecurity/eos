package nomad

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NativeInstaller handles Nomad installation using shared HashiCorp helpers
type NativeInstaller struct {
	*hashicorp.BaseInstaller
	rc     *eos_io.RuntimeContext
	config *NativeInstallConfig
}

// NativeInstallConfig contains Nomad-specific installation configuration for native installer
type NativeInstallConfig struct {
	*hashicorp.InstallConfig
	ServerEnabled    bool
	ClientEnabled    bool
	Datacenter       string
	Region           string
	BootstrapExpect  int
	ConsulIntegration bool
	VaultIntegration  bool
	DockerEnabled     bool
	BindAddr         string
	AdvertiseAddr    string
	LogLevel         string
}

// NewNativeInstaller creates a new Nomad native installer
func NewNativeInstaller(rc *eos_io.RuntimeContext, config *NativeInstallConfig) *NativeInstaller {
	// Set defaults
	if config.InstallConfig == nil {
		config.InstallConfig = &hashicorp.InstallConfig{
			Product:       hashicorp.ProductNomad,
			Version:       "latest",
			InstallMethod: hashicorp.MethodBinary,
			BinaryPath:    "/usr/local/bin/nomad",
			ConfigPath:    "/etc/nomad.d",
			DataPath:      "/opt/nomad/data",
			LogPath:       "/var/log/nomad",
			ServiceName:   "nomad",
			ServiceUser:   "nomad",
			ServiceGroup:  "nomad",
			Port:          shared.PortNomad,
			TLSEnabled:    false,
		}
	}
	
	// Set Nomad-specific defaults
	if config.Datacenter == "" {
		config.Datacenter = "dc1"
	}
	if config.Region == "" {
		config.Region = "global"
	}
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	if config.BindAddr == "" {
		config.BindAddr = "0.0.0.0"
	}
	if config.BootstrapExpect == 0 && config.ServerEnabled {
		config.BootstrapExpect = 1
	}
	// Default to both server and client if neither specified
	if !config.ServerEnabled && !config.ClientEnabled {
		config.ServerEnabled = true
		config.ClientEnabled = true
	}
	
	baseInstaller := hashicorp.NewBaseInstaller(rc, hashicorp.ProductNomad)
	
	return &NativeInstaller{
		BaseInstaller: baseInstaller,
		rc:            rc,
		config:        config,
	}
}

// Install performs the complete Nomad installation
func (n *NativeInstaller) Install() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	
	// Initialize progress reporter
	progress := hashicorp.NewProgressReporter(logger, "Nomad Installation", 9)
	n.SetProgress(progress)
	
	// ASSESS - Check current status
	progress.Update("Checking current Nomad status")
	status, err := n.CheckStatus(n.config.InstallConfig)
	if err != nil {
		logger.Warn("Could not determine current Nomad status", zap.Error(err))
		status = &hashicorp.ProductStatus{}
	}
	
	// Check idempotency
	if status.Running && status.ConfigValid && !n.config.ForceReinstall {
		progress.Complete("Nomad is already installed and running")
		return nil
	}
	
	// Validate prerequisites
	progress.Update("Validating prerequisites")
	if err := n.validatePrerequisites(); err != nil {
		progress.Failed("Prerequisites validation failed", err)
		return fmt.Errorf("prerequisites validation failed: %w", err)
	}
	
	// Clean install if requested
	if n.config.CleanInstall {
		progress.Update("Performing clean installation")
		if err := n.CleanExistingInstallation(n.config.InstallConfig); err != nil {
			progress.Failed("Clean installation failed", err)
			return fmt.Errorf("failed to clean existing installation: %w", err)
		}
	}
	
	// INTERVENE - Install Nomad
	progress.Update("Installing Nomad binary")
	if n.config.InstallMethod == hashicorp.MethodRepository {
		if err := n.InstallViaRepository(n.config.InstallConfig); err != nil {
			progress.Failed("Repository installation failed", err)
			return fmt.Errorf("repository installation failed: %w", err)
		}
	} else {
		if err := n.InstallBinary(n.config.InstallConfig); err != nil {
			progress.Failed("Binary installation failed", err)
			return fmt.Errorf("binary installation failed: %w", err)
		}
	}
	
	// Install Docker if needed for client
	if n.config.ClientEnabled && n.config.DockerEnabled {
		progress.Update("Installing Docker for Nomad client")
		if err := n.installDocker(); err != nil {
			logger.Warn("Failed to install Docker", zap.Error(err))
		}
	}
	
	// Create user
	progress.Update("Creating nomad user")
	if err := n.CreateUser(n.config.InstallConfig); err != nil {
		progress.Failed("User creation failed", err)
		return fmt.Errorf("failed to create nomad user: %w", err)
	}
	
	// Setup directories
	progress.Update("Setting up directories")
	if err := n.setupDirectories(); err != nil {
		progress.Failed("Directory setup failed", err)
		return fmt.Errorf("failed to setup directories: %w", err)
	}
	
	// Configure Nomad
	progress.Update("Configuring Nomad")
	if err := n.configure(); err != nil {
		progress.Failed("Configuration failed", err)
		return fmt.Errorf("configuration failed: %w", err)
	}
	
	// Setup service
	progress.Update("Setting up systemd service")
	if err := n.setupService(); err != nil {
		progress.Failed("Service setup failed", err)
		return fmt.Errorf("service setup failed: %w", err)
	}
	
	// EVALUATE - Verify installation
	progress.Update("Verifying installation")
	if err := n.verify(); err != nil {
		progress.Failed("Verification failed", err)
		return fmt.Errorf("verification failed: %w", err)
	}
	
	progress.Complete("Nomad installation completed successfully")
	logger.Info("Nomad installation completed",
		zap.String("version", n.config.Version),
		zap.Int("port", n.config.Port),
		zap.Bool("server", n.config.ServerEnabled),
		zap.Bool("client", n.config.ClientEnabled))
	
	return nil
}

// validatePrerequisites performs Nomad-specific prerequisite checks
func (n *NativeInstaller) validatePrerequisites() error {
	if err := n.PreInstallValidation(n.config.InstallConfig); err != nil {
		return err
	}
	
	validator := hashicorp.NewValidator(otelzap.Ctx(n.rc.Ctx))
	
	// Check additional ports for Nomad
	validator.CheckPort(4647) // RPC port
	validator.CheckPort(4648) // Serf port
	
	// Check if CNI plugins are needed
	if n.config.ClientEnabled {
		validator.RequireCommand("iptables")
	}
	
	if validator.HasErrors() {
		return validator.GetError()
	}
	
	return nil
}

// setupDirectories creates Nomad-specific directories
func (n *NativeInstaller) setupDirectories() error {
	// Use base directories setup
	if err := n.SetupDirectories(n.config.InstallConfig); err != nil {
		return err
	}
	
	// Create additional Nomad directories
	additionalDirs := []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(n.config.DataPath, "alloc"), 0755},
		{filepath.Join(n.config.DataPath, "client"), 0755},
		{filepath.Join(n.config.DataPath, "server"), 0700},
	}
	
	for _, dir := range additionalDirs {
		dirMgr := hashicorp.NewDirectoryManager(n.GetRunner())
		if err := dirMgr.CreateWithOwnership(
			dir.path,
			n.config.ServiceUser,
			n.config.ServiceGroup,
			dir.mode,
		); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir.path, err)
		}
	}
	
	return nil
}

// configure writes the Nomad configuration
func (n *NativeInstaller) configure() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Configuring Nomad")
	
	// Backup existing configuration
	configFile := filepath.Join(n.config.ConfigPath, "nomad.hcl")
	n.GetFileManager().BackupFile(configFile)
	
	// Get first non-loopback IP if using 0.0.0.0
	bindAddr := n.config.BindAddr
	advertiseAddr := n.config.AdvertiseAddr
	if bindAddr == "0.0.0.0" {
		if ip, err := n.getFirstNonLoopbackIP(); err == nil && ip != "" {
			if advertiseAddr == "" {
				advertiseAddr = ip
			}
			bindAddr = ip
		}
	}
	
	// Generate server stanza if enabled
	var serverConfig string
	if n.config.ServerEnabled {
		serverConfig = fmt.Sprintf(`
server {
  enabled          = true
  bootstrap_expect = %d
  
  server_join {
    retry_join = ["127.0.0.1"]
  }
}`, n.config.BootstrapExpect)
	}
	
	// Generate client stanza if enabled
	var clientConfig string
	if n.config.ClientEnabled {
		clientConfig = `
client {
  enabled = true
  
  options {
    "driver.raw_exec.enable"    = "1"
    "docker.privileged.enabled" = "true"
  }
}`
	}
	
	// Generate Consul integration if enabled
	var consulConfig string
	if n.config.ConsulIntegration {
		consulConfig = fmt.Sprintf(`
consul {
  address = "127.0.0.1:%d"
  
  server_service_name = "nomad"
  client_service_name = "nomad-client"
  auto_advertise      = true
  
  server_auto_join = true
  client_auto_join = true
}`, shared.PortConsul)
	}
	
	// Generate Vault integration if enabled
	var vaultConfig string
	if n.config.VaultIntegration {
		vaultConfig = fmt.Sprintf(`
vault {
  enabled = true
  address = "http://127.0.0.1:%d"
}`, shared.PortVault)
	}
	
	// Generate complete configuration
	config := fmt.Sprintf(`# Nomad configuration managed by Eos
datacenter = "%s"
region     = "%s"
data_dir   = "%s"
log_level  = "%s"

bind_addr = "%s"

advertise {
  http = "%s:%d"
  rpc  = "%s:4647"
  serf = "%s:4648"
}

ports {
  http = %d
  rpc  = 4647
  serf = 4648
}
%s
%s
%s
%s

telemetry {
  collection_interval = "1s"
  disable_hostname    = true
  prometheus_metrics  = true
  publish_allocation_metrics = true
  publish_node_metrics       = true
}

acl {
  enabled = false
}

plugin "raw_exec" {
  config {
    enabled = true
  }
}

plugin "docker" {
  config {
    allow_privileged = true
    volumes {
      enabled = true
    }
  }
}
`, n.config.Datacenter, n.config.Region, n.config.DataPath, n.config.LogLevel,
   bindAddr, advertiseAddr, n.config.Port, advertiseAddr, advertiseAddr,
   n.config.Port, serverConfig, clientConfig, consulConfig, vaultConfig)
	
	// Write configuration
	if err := n.GetFileManager().WriteWithOwnership(
		configFile,
		[]byte(config),
		0640,
		n.config.ServiceUser,
		n.config.ServiceGroup,
	); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}
	
	// Validate configuration
	logger.Info("Validating Nomad configuration")
	if err := n.GetRunner().Run(n.config.BinaryPath, "config", "validate", n.config.ConfigPath); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	
	return nil
}

// setupService creates and starts the systemd service
func (n *NativeInstaller) setupService() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Setting up Nomad systemd service")
	
	// Write systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
Description=HashiCorp Nomad
Documentation=https://www.nomadproject.io/docs/
Requires=network-online.target
After=network-online.target
%s
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
User=%s
Group=%s
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=%s agent -config %s
KillMode=process
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitNPROC=512
TasksMax=infinity
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
`, n.getServiceDependencies(), n.config.ServiceUser, n.config.ServiceGroup,
   n.config.BinaryPath, n.config.ConfigPath)
	
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", n.config.ServiceName)
	if err := n.GetFileManager().WriteWithOwnership(
		servicePath,
		[]byte(serviceContent),
		0644,
		"root",
		"root",
	); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}
	
	// Reload systemd
	if err := n.GetSystemd().ReloadDaemon(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	
	// Enable service
	if err := n.GetSystemd().EnableService(n.config.ServiceName); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	
	// Start service
	logger.Info("Starting Nomad service")
	if err := n.GetSystemd().StartService(n.config.ServiceName); err != nil {
		// Get service status for debugging
		if status, statusErr := n.GetSystemd().GetServiceStatus(n.config.ServiceName); statusErr == nil {
			logger.Error("Failed to start Nomad service",
				zap.String("status", status))
		}
		return fmt.Errorf("failed to start service: %w", err)
	}
	
	return nil
}

// getServiceDependencies returns systemd dependencies based on integrations
func (n *NativeInstaller) getServiceDependencies() string {
	deps := []string{}
	if n.config.ConsulIntegration {
		deps = append(deps, "After=consul.service")
		deps = append(deps, "Wants=consul.service")
	}
	if n.config.VaultIntegration {
		deps = append(deps, "After=vault.service")
	}
	if n.config.DockerEnabled {
		deps = append(deps, "After=docker.service")
		deps = append(deps, "Wants=docker.service")
	}
	
	result := ""
	for _, dep := range deps {
		result += dep + "\n"
	}
	return result
}

// verify checks that Nomad is running correctly
func (n *NativeInstaller) verify() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Verifying Nomad installation")
	
	// Wait for service to stabilize
	maxRetries := 10
	for i := 1; i <= maxRetries; i++ {
		if n.GetSystemd().IsServiceActive(n.config.ServiceName) {
			break
		}
		
		if i == maxRetries {
			return fmt.Errorf("Nomad service failed to start after %d attempts", maxRetries)
		}
		
		logger.Debug("Waiting for Nomad service",
			zap.Int("attempt", i),
			zap.Int("max_retries", maxRetries))
		time.Sleep(time.Duration(i) * time.Second)
	}
	
	// Check Nomad node status
	if err := n.GetRunner().Run(n.config.BinaryPath, "node", "status"); err != nil {
		return fmt.Errorf("Nomad is not responding to commands: %w", err)
	}
	
	// Check server members if server is enabled
	if n.config.ServerEnabled {
		if err := n.GetRunner().Run(n.config.BinaryPath, "server", "members"); err != nil {
			return fmt.Errorf("Nomad server is not functioning: %w", err)
		}
	}
	
	logger.Info("Nomad verification successful")
	return nil
}

// installDocker installs Docker for Nomad client
func (n *NativeInstaller) installDocker() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	
	// Check if Docker is already installed
	if err := n.GetRunner().RunQuiet("docker", "--version"); err == nil {
		logger.Info("Docker is already installed")
		return nil
	}
	
	logger.Info("Installing Docker for Nomad client")
	
	// Install Docker using apt
	cmds := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "ca-certificates", "curl", "gnupg"},
		{"install", "-m", "0755", "-d", "/etc/apt/keyrings"},
	}
	
	for _, cmd := range cmds {
		if err := n.GetRunner().Run(cmd[0], cmd[1:]...); err != nil {
			return fmt.Errorf("failed to run %s: %w", cmd[0], err)
		}
	}
	
	// Add Docker GPG key
	gpgCmd := `curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg`
	if err := n.GetRunner().Run("bash", "-c", gpgCmd); err != nil {
		return fmt.Errorf("failed to add Docker GPG key: %w", err)
	}
	
	// Add Docker repository
	repoCmd := `echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null`
	if err := n.GetRunner().Run("bash", "-c", repoCmd); err != nil {
		return fmt.Errorf("failed to add Docker repository: %w", err)
	}
	
	// Install Docker
	if err := n.GetRunner().Run("apt-get", "update"); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}
	
	if err := n.GetRunner().Run("apt-get", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io"); err != nil {
		return fmt.Errorf("failed to install Docker: %w", err)
	}
	
	// Add nomad user to docker group
	if err := n.GetRunner().Run("usermod", "-aG", "docker", n.config.ServiceUser); err != nil {
		logger.Warn("Failed to add nomad user to docker group", zap.Error(err))
	}
	
	// Start Docker service
	if err := n.GetRunner().Run("systemctl", "start", "docker"); err != nil {
		return fmt.Errorf("failed to start Docker: %w", err)
	}
	
	if err := n.GetRunner().Run("systemctl", "enable", "docker"); err != nil {
		return fmt.Errorf("failed to enable Docker: %w", err)
	}
	
	logger.Info("Docker installed successfully")
	return nil
}

// getFirstNonLoopbackIP returns the first non-loopback IP address
func (n *NativeInstaller) getFirstNonLoopbackIP() (string, error) {
	output, err := n.GetRunner().RunOutput("hostname", "-I")
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