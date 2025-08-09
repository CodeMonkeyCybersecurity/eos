package vault

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NativeInstaller handles Vault installation using shared HashiCorp helpers
type NativeInstaller struct {
	*hashicorp.BaseInstaller
	rc     *eos_io.RuntimeContext
	config *VaultInstallConfig
}

// VaultInstallConfig contains Vault-specific installation configuration
type VaultInstallConfig struct {
	*hashicorp.InstallConfig
	UIEnabled        bool
	ClusterName      string
	StorageBackend   string // "file", "consul", "raft"
	ListenerAddress  string
	APIAddr          string
	ClusterAddr      string
	DisableMlock     bool
	AutoUnseal       bool
	KMSKeyID         string // For AWS KMS auto-unseal
}

// NewNativeInstaller creates a new Vault native installer
func NewNativeInstaller(rc *eos_io.RuntimeContext, config *VaultInstallConfig) *NativeInstaller {
	// Set defaults
	if config.InstallConfig == nil {
		config.InstallConfig = &hashicorp.InstallConfig{
			Product:       hashicorp.ProductVault,
			Version:       "latest",
			InstallMethod: hashicorp.MethodBinary,
			BinaryPath:    "/usr/local/bin/vault",
			ConfigPath:    "/etc/vault.d",
			DataPath:      "/opt/vault/data",
			LogPath:       "/var/log/vault",
			ServiceName:   "vault",
			ServiceUser:   "vault",
			ServiceGroup:  "vault",
			Port:          shared.PortVault,
			TLSEnabled:    true,
		}
	}
	
	if config.StorageBackend == "" {
		config.StorageBackend = "file"
	}
	if config.ListenerAddress == "" {
		config.ListenerAddress = "0.0.0.0:8200"
	}
	if config.APIAddr == "" {
		config.APIAddr = fmt.Sprintf("http://127.0.0.1:%d", shared.PortVault)
	}
	if config.ClusterAddr == "" {
		config.ClusterAddr = fmt.Sprintf("http://127.0.0.1:%d", shared.PortVault+1)
	}
	
	baseInstaller := hashicorp.NewBaseInstaller(rc, hashicorp.ProductVault)
	
	return &NativeInstaller{
		BaseInstaller: baseInstaller,
		rc:            rc,
		config:        config,
	}
}

// Install performs the complete Vault installation
func (n *NativeInstaller) Install() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	
	// Initialize progress reporter
	progress := hashicorp.NewProgressReporter(logger, "Vault Installation", 8)
	n.SetProgress(progress)
	
	// ASSESS - Check current status
	progress.Update("Checking current Vault status")
	status, err := n.CheckStatus(n.config.InstallConfig)
	if err != nil {
		logger.Warn("Could not determine current Vault status", zap.Error(err))
		status = &hashicorp.ProductStatus{}
	}
	
	// Check idempotency
	if status.Running && status.ConfigValid && !n.config.ForceReinstall {
		progress.Complete("Vault is already installed and running")
		return nil
	}
	
	// Validate prerequisites
	progress.Update("Validating prerequisites")
	if err := n.PreInstallValidation(n.config.InstallConfig); err != nil {
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
	
	// INTERVENE - Install Vault
	progress.Update("Installing Vault binary")
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
	
	// Create user
	progress.Update("Creating vault user")
	if err := n.CreateUser(n.config.InstallConfig); err != nil {
		progress.Failed("User creation failed", err)
		return fmt.Errorf("failed to create vault user: %w", err)
	}
	
	// Setup directories
	progress.Update("Setting up directories")
	if err := n.SetupDirectories(n.config.InstallConfig); err != nil {
		progress.Failed("Directory setup failed", err)
		return fmt.Errorf("failed to setup directories: %w", err)
	}
	
	// Configure Vault
	progress.Update("Configuring Vault")
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
	
	progress.Complete("Vault installation completed successfully")
	logger.Info("Vault installation completed",
		zap.String("version", n.config.Version),
		zap.Int("port", n.config.Port))
	
	return nil
}

// configure writes the Vault configuration
func (n *NativeInstaller) configure() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Configuring Vault")
	
	// Backup existing configuration
	configFile := filepath.Join(n.config.ConfigPath, "vault.hcl")
	n.GetFileManager().BackupFile(configFile)
	
	// Generate configuration based on storage backend
	var storageConfig string
	switch n.config.StorageBackend {
	case "consul":
		storageConfig = `storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault"
}`
	case "raft":
		storageConfig = fmt.Sprintf(`storage "raft" {
  path    = "%s/raft"
  node_id = "node1"
}`, n.config.DataPath)
	default: // file
		storageConfig = fmt.Sprintf(`storage "file" {
  path = "%s"
}`, n.config.DataPath)
	}
	
	// Generate seal configuration
	var sealConfig string
	if n.config.AutoUnseal && n.config.KMSKeyID != "" {
		sealConfig = fmt.Sprintf(`seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "%s"
}`, n.config.KMSKeyID)
	}
	
	// Generate complete configuration
	config := fmt.Sprintf(`# Vault configuration managed by Eos
%s

%s

listener "tcp" {
  address     = "%s"
  tls_disable = %t
}

api_addr     = "%s"
cluster_addr = "%s"

ui = %t
disable_mlock = %t

log_level = "info"
log_format = "json"
`, storageConfig, sealConfig, n.config.ListenerAddress, 
   !n.config.TLSEnabled, n.config.APIAddr, n.config.ClusterAddr,
   n.config.UIEnabled, n.config.DisableMlock)
	
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
	logger.Info("Validating Vault configuration")
	if err := n.GetRunner().Run(n.config.BinaryPath, "validate", n.config.ConfigPath); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	
	return nil
}

// setupService creates and starts the systemd service
func (n *NativeInstaller) setupService() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Setting up Vault systemd service")
	
	// Write systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=%s/vault.hcl
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
EnvironmentFile=/etc/vault.d/vault.env
User=%s
Group=%s
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
StandardOutput=journal
StandardError=journal
LimitMEMLOCK=infinity
Capabilities=CAP_IPC_LOCK+ep
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=%s server -config=%s
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
`, n.config.ConfigPath, n.config.ServiceUser, n.config.ServiceGroup,
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
	
	// Create environment file
	envContent := fmt.Sprintf(`VAULT_API_ADDR=%s
VAULT_CLUSTER_ADDR=%s
`, n.config.APIAddr, n.config.ClusterAddr)
	
	envPath := filepath.Join(n.config.ConfigPath, "vault.env")
	if err := n.GetFileManager().WriteWithOwnership(
		envPath,
		[]byte(envContent),
		0640,
		n.config.ServiceUser,
		n.config.ServiceGroup,
	); err != nil {
		return fmt.Errorf("failed to write environment file: %w", err)
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
	logger.Info("Starting Vault service")
	if err := n.GetSystemd().StartService(n.config.ServiceName); err != nil {
		// Get service status for debugging
		if status, statusErr := n.GetSystemd().GetServiceStatus(n.config.ServiceName); statusErr == nil {
			logger.Error("Failed to start Vault service",
				zap.String("status", status))
		}
		return fmt.Errorf("failed to start service: %w", err)
	}
	
	return nil
}

// verify checks that Vault is running correctly
func (n *NativeInstaller) verify() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Verifying Vault installation")
	
	// Wait for service to stabilize
	for i := 1; i <= 5; i++ {
		if n.GetSystemd().IsServiceActive(n.config.ServiceName) {
			break
		}
		logger.Debug("Waiting for Vault service",
			zap.Int("attempt", i))
		if i < 5 {
			// Exponential backoff
			sleepDuration := time.Duration(i) * time.Second
			time.Sleep(sleepDuration)
		}
	}
	
	// Check service is active
	if !n.GetSystemd().IsServiceActive(n.config.ServiceName) {
		return fmt.Errorf("Vault service is not active")
	}
	
	// Check Vault status
	if err := n.GetRunner().Run(n.config.BinaryPath, "status"); err != nil {
		// Vault returns exit code 2 when sealed, which is expected
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			logger.Info("Vault is installed and sealed (expected)")
		} else {
			return fmt.Errorf("Vault is not responding to commands: %w", err)
		}
	}
	
	logger.Info("Vault verification successful")
	return nil
}