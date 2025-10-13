// pkg/vault/install.go

package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// VaultInstaller handles Vault installation using native methods
type VaultInstaller struct {
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

// InstallConfig contains all configuration for Vault installation
type InstallConfig struct {
	// Installation method
	Version       string // Version to install (e.g., "1.15.0" or "latest")
	UseRepository bool   // Use APT repository vs direct binary download
	BinaryPath    string // Path for binary installation

	// Vault configuration
	UIEnabled       bool
	ClusterName     string
	StorageBackend  string // "raft" (recommended), "consul", "file" (deprecated)
	ListenerAddress string
	BindAddr        string // Specific IP to bind to (for Consul registration)
	APIAddr         string
	ClusterAddr     string
	ClusterPort     int    // Raft cluster communication port (default: 8180)
	NodeID          string // Unique node identifier for Raft
	DisableMlock    bool
	
	// Auto-unseal configuration
	AutoUnseal       bool
	AutoUnsealType   string // "awskms", "azurekeyvault", "gcpckms"
	KMSKeyID         string // For AWS KMS auto-unseal
	KMSRegion        string // AWS region or Azure location
	AzureTenantID    string // Azure tenant ID
	AzureClientID    string // Azure client ID
	AzureClientSecret string // Azure client secret
	AzureVaultName   string // Azure Key Vault name
	AzureKeyName     string // Azure Key Vault key name
	GCPProject       string // GCP project ID
	GCPLocation      string // GCP location
	GCPKeyRing       string // GCP KMS keyring
	GCPCryptoKey     string // GCP KMS crypto key
	GCPCredentials   string // Path to GCP credentials file
	
	LogLevel   string
	Datacenter string // Consul datacenter for service registration
	
	// Multi-node Raft cluster configuration
	RetryJoinNodes []shared.RetryJoinNode

	// Paths
	ConfigPath string
	DataPath   string
	LogPath    string

	// Service configuration
	ServiceName  string
	ServiceUser  string
	ServiceGroup string
	Port         int
	TLSEnabled   bool

	// Installation behavior
	ForceReinstall bool // Force reinstallation even if already installed
	CleanInstall   bool // Remove existing data before installation
	DryRun         bool // Dry run mode
}

// NewVaultInstaller creates a new Vault installer instance
func NewVaultInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *VaultInstaller {
	// Set defaults
	if config.Version == "" {
		config.Version = "latest"
	}
	if config.StorageBackend == "" {
		// Default to Raft Integrated Storage (recommended by HashiCorp)
		// File storage is NOT SUPPORTED in Vault Enterprise 1.12.0+
		// Reference: vault-complete-specification-v1.0-raft-integrated.md
		config.StorageBackend = "raft"
	}
	if config.ListenerAddress == "" {
		config.ListenerAddress = fmt.Sprintf("0.0.0.0:%d", shared.PortVault)
	}
	if config.APIAddr == "" {
		protocol := "http"
		if config.TLSEnabled {
			protocol = "https"
		}
		config.APIAddr = fmt.Sprintf("%s://127.0.0.1:%d", protocol, shared.PortVault)
	}
	if config.ClusterAddr == "" {
		protocol := "http"
		if config.TLSEnabled {
			protocol = "https"
		}
		config.ClusterAddr = fmt.Sprintf("%s://127.0.0.1:%d", protocol, shared.PortVault+1)
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}
	if config.BinaryPath == "" {
		config.BinaryPath = "/usr/local/bin/vault"
	}
	if config.ConfigPath == "" {
		config.ConfigPath = "/etc/vault.d"
	}
	if config.DataPath == "" {
		config.DataPath = "/opt/vault/data"
	}
	if config.LogPath == "" {
		config.LogPath = "/var/log/vault"
	}
	if config.ServiceName == "" {
		config.ServiceName = "vault"
	}
	if config.ServiceUser == "" {
		config.ServiceUser = "vault"
	}
	if config.ServiceGroup == "" {
		config.ServiceGroup = "vault"
	}
	if config.Port == 0 {
		config.Port = shared.PortVault
	}

	logger := otelzap.Ctx(rc.Ctx)
	runner := NewCommandRunner(rc)

	return &VaultInstaller{
		rc:       rc,
		config:   config,
		logger:   logger,
		runner:   runner,
		systemd:  NewSystemdService(runner, config.ServiceName),
		dirs:     NewDirectoryManager(runner),
		files:    NewFileManager(runner),
		progress: NewProgressReporter(logger, "Vault Installation", 100),
		user:     NewUserHelper(runner),
		validate: NewValidationHelper(logger),
		network:  NewHTTPClient(30 * time.Second),
	}
}

// Install performs the complete Vault installation
func (vi *VaultInstaller) Install() error {
	vi.logger.Info("Starting Vault installation",
		zap.String("version", vi.config.Version),
		zap.String("storage_backend", vi.config.StorageBackend),
		zap.Bool("use_repository", vi.config.UseRepository))

	// Phase 1: ASSESS - Check if already installed
	vi.progress.Update("[14%] Checking current Vault status")
	shouldInstall, err := vi.assess()
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// If Vault is already properly installed and running, we're done
	if !shouldInstall {
		vi.logger.Info("Vault is already installed and running properly")
		vi.progress.Complete("Vault is already installed and running")
		return nil
	}

	// Phase 2: Prerequisites
	vi.progress.Update("[28%] Validating prerequisites")
	if err := vi.validatePrerequisites(); err != nil {
		return fmt.Errorf("prerequisite validation failed: %w", err)
	}

	// Phase 3: INTERVENE - Install
	vi.progress.Update("[42%] Installing Vault binary")
	if err := vi.installBinary(); err != nil {
		return fmt.Errorf("binary installation failed: %w", err)
	}

	// Cleanup duplicate binaries (non-fatal)
	vi.logger.Debug("Checking for duplicate Vault binaries")
	if err := CleanupDuplicateBinaries(vi.rc, vi.config.BinaryPath); err != nil {
		vi.logger.Warn("Could not cleanup duplicate binaries (non-fatal)", zap.Error(err))
	}

	// Phase 4: User and directories
	vi.progress.Update("[56%] Creating user and directories")
	if err := vi.setupUserAndDirectories(); err != nil {
		return fmt.Errorf("user/directory setup failed: %w", err)
	}

	// Phase 5: Configure
	vi.progress.Update("[70%] Configuring Vault")
	if err := vi.configure(); err != nil {
		return fmt.Errorf("configuration failed: %w", err)
	}

	// Validate configuration before starting service
	vi.logger.Info("Validating Vault configuration")
	configPath := filepath.Join(vi.config.ConfigPath, "vault.hcl")
	if err := ValidateConfigBeforeStart(vi.rc); err != nil {
		return eos_err.NewUserError("Configuration validation failed: %s\n"+
			"Config file: %s\n"+
			"Fix: Review configuration and correct any errors\n"+
			"Help: Run 'sudo eos check vault --config' for details", err, configPath)
	}
	vi.logger.Info(" Configuration validated successfully")

	// Phase 6: Setup Service
	vi.progress.Update("[84%] Setting up systemd service")
	if err := vi.setupService(); err != nil {
		return fmt.Errorf("service setup failed: %w", err)
	}

	// Phase 7: EVALUATE - Verify
	vi.progress.Update("[92%] Verifying installation")
	if err := vi.verify(); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Display post-installation security checklist
	vi.logger.Info("📋 Displaying security guidance")
	DisplayPostInstallSecurityChecklist(vi.rc)

	// Phase 8: Register with Consul (if available)
	vi.progress.Update("[100%] Registering with Consul")
	if err := vi.registerWithConsul(); err != nil {
		vi.logger.Warn("Failed to register with Consul (non-critical)",
			zap.Error(err))
		// Don't fail installation if Consul registration fails
	}

	vi.progress.Complete("Vault installation completed successfully")
	return nil
}

// assess checks the current state of Vault installation
// Returns true if installation should proceed, false if already installed
func (vi *VaultInstaller) assess() (bool, error) {
	vi.logger.Info("Assessing current Vault installation")

	// First, check if Vault binary exists
	if _, err := os.Stat(vi.config.BinaryPath); err == nil {
		// Binary exists, check version
		if output, err := vi.runner.RunOutput(vi.config.BinaryPath, "version"); err == nil {
			vi.logger.Info("Vault binary found", zap.String("output", output))
		}
	}

	// Check if Vault service exists
	if status, err := vi.systemd.GetStatus(); err == nil {
		vi.logger.Info("Vault service found", zap.String("status", status))

		if !vi.config.ForceReinstall {
			// Check if it's running
			if vi.systemd.IsActive() {
				// Verify it's actually working
				if vi.isVaultReady() {
					vi.logger.Info("Vault is already installed and running properly")

					// Print service information
					vi.logger.Info("terminal prompt:  Vault is already installed and running")
					vi.logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", vi.config.Port))
					vi.logger.Info("terminal prompt: ")
					vi.logger.Info("terminal prompt: To check status: vault status")
					vi.logger.Info("terminal prompt: To view logs: journalctl -u vault -f")

					return false, nil // Don't install, already running
				}
				vi.logger.Warn("Vault service is active but not responding properly")
				// Fall through to attempt repair/reinstall
			} else {
				vi.logger.Info("Vault is installed but not running")
				// Try to start it
				vi.logger.Info("Attempting to start existing Vault service")
				if err := vi.systemd.Start(); err != nil {
					vi.logger.Warn("Failed to start existing Vault service", zap.Error(err))
				} else {
					// Wait a moment for it to start
					// SECURITY P2 #7: Use context-aware sleep to respect cancellation
					startupWait := 3 * time.Second
					select {
					case <-time.After(startupWait):
						// Continue to check if Vault is ready
					case <-vi.rc.Ctx.Done():
						return false, fmt.Errorf("vault startup check cancelled: %w", vi.rc.Ctx.Err())
					}
					if vi.isVaultReady() {
						vi.logger.Info("Successfully started existing Vault service")
						vi.logger.Info("terminal prompt:  Vault service started successfully")
						vi.logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", vi.config.Port))
						return false, nil // Don't install, successfully started existing
					}
				}
			}
		} else {
			vi.logger.Info("Force reinstall requested, proceeding with installation")
			if vi.config.CleanInstall {
				if err := vi.cleanExistingInstallation(); err != nil {
					return false, fmt.Errorf("failed to clean existing installation: %w", err)
				}
			}
		}
	}

	return true, nil // Proceed with installation
}

// validatePrerequisites checks system requirements
func (vi *VaultInstaller) validatePrerequisites() error {
	vi.logger.Info("Validating prerequisites")

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Check memory requirements (minimum 256MB recommended)
	if err := vi.checkMemory(); err != nil {
		return err
	}

	// Check disk space (minimum 100MB for Vault)
	if err := vi.checkDiskSpace("/opt", 100); err != nil {
		return err
	}

	// Check port availability - but be smart about it
	// If we're doing a force reinstall, stop the existing service first
	if vi.config.ForceReinstall && vi.systemd.IsActive() {
		vi.logger.Info("Stopping existing Vault service for reinstallation")
		if err := vi.systemd.Stop(); err != nil {
			vi.logger.Warn("Failed to stop existing Vault service", zap.Error(err))
		}
		// Give it time to release ports
		// SECURITY P2 #7: Use context-aware sleep to respect cancellation
		portReleaseWait := 2 * time.Second
		select {
		case <-time.After(portReleaseWait):
			// Continue to port availability check
		case <-vi.rc.Ctx.Done():
			return fmt.Errorf("vault service stop wait cancelled: %w", vi.rc.Ctx.Err())
		}
	}

	// Check port availability
	if err := vi.checkPortAvailable(vi.config.Port); err != nil {
		return err
	}

	return nil
}

// installBinary installs the Vault binary
func (vi *VaultInstaller) installBinary() error {
	if vi.config.UseRepository {
		return vi.installViaRepository()
	}
	return vi.installViaBinary()
}

// installViaRepository installs Vault using APT repository
func (vi *VaultInstaller) installViaRepository() error {
	vi.logger.Info("Installing Vault via HashiCorp APT repository")

	// Add HashiCorp GPG key
	vi.logger.Info("Adding HashiCorp GPG key")
	if output, err := vi.runner.RunOutput("sh", "-c",
		"wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg"); err != nil {
		return fmt.Errorf("failed to add GPG key: %w (output: %s)", err, output)
	}

	// Add HashiCorp repository
	vi.logger.Info("Adding HashiCorp repository")
	repoLine := fmt.Sprintf("deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com %s main",
		getUbuntuCodename())

	if err := vi.writeFile("/etc/apt/sources.list.d/hashicorp.list", []byte(repoLine), 0644); err != nil {
		return fmt.Errorf("failed to add repository: %w", err)
	}

	// Update package list
	vi.logger.Info("Updating package list")
	if err := vi.runner.Run("apt-get", "update"); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}

	// Install Vault package
	vi.logger.Info("Installing Vault package")
	installCmd := []string{"apt-get", "install", "-y"}
	if vi.config.Version != "latest" {
		installCmd = append(installCmd, fmt.Sprintf("vault=%s", vi.config.Version))
	} else {
		installCmd = append(installCmd, "vault")
	}

	if err := vi.runner.Run(installCmd[0], installCmd[1:]...); err != nil {
		return fmt.Errorf("failed to install Vault package: %w", err)
	}

	return nil
}

// installViaBinary downloads and installs Vault binary directly
func (vi *VaultInstaller) installViaBinary() error {
	vi.logger.Info("Installing Vault via direct binary download")

	// Determine version to install
	version := vi.config.Version
	if version == "latest" {
		var err error
		version, err = vi.getLatestVersion()
		if err != nil {
			return fmt.Errorf("failed to determine latest version: %w", err)
		}
	}

	// Download binary
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	}

	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/vault/%s/vault_%s_linux_%s.zip",
		version, version, arch)

	vi.logger.Info("Downloading Vault binary",
		zap.String("version", version),
		zap.String("url", downloadURL))

	tmpDir := "/tmp/vault-install"
	if err := vi.createDirectory(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "vault.zip")
	if err := vi.downloadFile(downloadURL, zipPath); err != nil {
		return fmt.Errorf("failed to download Vault: %w", err)
	}

	// Extract binary
	if err := vi.runner.Run("unzip", "-o", zipPath, "-d", tmpDir); err != nil {
		return fmt.Errorf("failed to extract Vault: %w", err)
	}

	// Install binary
	binaryPath := filepath.Join(tmpDir, "vault")
	if err := vi.runner.Run("install", "-m", "755", binaryPath, vi.config.BinaryPath); err != nil {
		return fmt.Errorf("failed to install binary: %w", err)
	}

	// Set IPC_LOCK capability
	if err := vi.runner.Run("setcap", "cap_ipc_lock=+ep", vi.config.BinaryPath); err != nil {
		vi.logger.Warn("Failed to set IPC_LOCK capability", zap.Error(err))
	}

	return nil
}

// setupUserAndDirectories creates the Vault user and required directories
func (vi *VaultInstaller) setupUserAndDirectories() error {
	vi.logger.Info("Setting up Vault user and directories")

	// Create vault user and group
	if err := vi.user.CreateSystemUser(vi.config.ServiceUser, vi.config.DataPath); err != nil {
		return fmt.Errorf("failed to create vault user: %w", err)
	}

	// Create required directories
	directories := []struct {
		path  string
		mode  os.FileMode
		owner string
	}{
		{vi.config.ConfigPath, 0755, vi.config.ServiceUser},
		{vi.config.DataPath, 0700, vi.config.ServiceUser},
		{vi.config.LogPath, 0755, vi.config.ServiceUser},
		{filepath.Join(vi.config.DataPath, "raft"), 0700, vi.config.ServiceUser},
	}

	for _, dir := range directories {
		if err := vi.createDirectory(dir.path, dir.mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir.path, err)
		}
		if err := vi.runner.Run("chown", "-R", dir.owner+":"+dir.owner, dir.path); err != nil {
			return fmt.Errorf("failed to set ownership for %s: %w", dir.path, err)
		}
	}

	return nil
}

// configure sets up Vault configuration
func (vi *VaultInstaller) configure() error {
	vi.logger.Info("Configuring Vault")

	// Generate TLS certificates if TLS is enabled
	if vi.config.TLSEnabled {
		if err := vi.generateSelfSignedCert(); err != nil {
			return fmt.Errorf("failed to generate TLS certificate: %w", err)
		}
	}

	// Backup existing configuration if present
	configPath := filepath.Join(vi.config.ConfigPath, "vault.hcl")
	if vi.fileExists(configPath) {
		if err := vi.files.BackupFile(configPath); err != nil {
			vi.logger.Warn("Failed to backup existing configuration", zap.Error(err))
		}
	}

	// Generate configuration based on storage backend
	var storageConfig string
	switch vi.config.StorageBackend {
	case "consul":
		storageConfig = `storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault"
}`
	case "raft":
		storageConfig = fmt.Sprintf(`storage "raft" {
  path    = "%s/raft"
  node_id = "node1"
}`, vi.config.DataPath)
	default: // file
		storageConfig = fmt.Sprintf(`storage "file" {
  path = "%s"
}`, vi.config.DataPath)
	}

	// Generate seal configuration
	var sealConfig string
	if vi.config.AutoUnseal && vi.config.KMSKeyID != "" {
		sealConfig = fmt.Sprintf(`seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "%s"
}`, vi.config.KMSKeyID)
	}

	// Generate listener configuration based on TLS setting
	var listenerConfig string
	if vi.config.TLSEnabled {
		// TLS enabled - use generated self-signed certificate
		tlsDir := filepath.Join(vi.config.ConfigPath, "tls")
		certPath := filepath.Join(tlsDir, "vault.crt")
		keyPath := filepath.Join(tlsDir, "vault.key")

		// CRITICAL FIX: Validate certificate files exist before writing to config
		// This prevents the #1 installation failure: empty cert paths causing
		// "open : no such file or directory" when Vault starts
		if !vi.fileExists(certPath) {
			return fmt.Errorf("TLS enabled but certificate not found: %s\n"+
				"This usually means certificate generation failed.\n"+
				"Try: sudo rm -rf /etc/vault.d/tls && retry installation\n"+
				"Or disable TLS: sudo eos create vault --tls=false", certPath)
		}
		if !vi.fileExists(keyPath) {
			return fmt.Errorf("TLS enabled but private key not found: %s\n"+
				"This usually means certificate generation failed.\n"+
				"Try: sudo rm -rf /etc/vault.d/tls && retry installation\n"+
				"Or disable TLS: sudo eos create vault --tls=false", keyPath)
		}

		vi.logger.Info("TLS certificate files validated",
			zap.String("cert", certPath),
			zap.String("key", keyPath))

		listenerConfig = fmt.Sprintf(`listener "tcp" {
  address       = "%s"
  tls_disable   = false
  tls_cert_file = "%s"
  tls_key_file  = "%s"
}`, vi.config.ListenerAddress, certPath, keyPath)
	} else {
		// TLS disabled - simpler configuration
		listenerConfig = fmt.Sprintf(`listener "tcp" {
  address     = "%s"
  tls_disable = true
}`, vi.config.ListenerAddress)
	}

	// Generate complete configuration
	config := fmt.Sprintf(`# Vault configuration managed by Eos
%s

%s

%s

api_addr     = "%s"
cluster_addr = "%s"

ui = %t
disable_mlock = %t

log_level = "%s"
log_format = "json"
`, storageConfig, sealConfig, listenerConfig,
		vi.config.APIAddr, vi.config.ClusterAddr,
		vi.config.UIEnabled, vi.config.DisableMlock, vi.config.LogLevel)

	// Write configuration
	if err := vi.writeFile(configPath, []byte(config), 0640); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Set proper ownership
	if err := vi.runner.Run("chown", vi.config.ServiceUser+":"+vi.config.ServiceGroup, configPath); err != nil {
		return fmt.Errorf("failed to set configuration ownership: %w", err)
	}

	// Validate configuration using improved validation with fallback
	vi.logger.Info("Validating Vault configuration")

	// CRITICAL FIX: Use ValidateConfigWithFallback which handles PATH issues
	// and falls back to manual HCL parsing if binary validation fails
	validationResult, err := ValidateConfigWithFallback(vi.rc, configPath)
	if err != nil {
		vi.logger.Error("Configuration validation encountered error",
			zap.Error(err),
			zap.String("config_path", configPath))
		return fmt.Errorf("configuration validation error: %w", err)
	}

	// Log warnings and suggestions
	for _, warning := range validationResult.Warnings {
		vi.logger.Warn("Configuration warning", zap.String("warning", warning))
	}
	for _, suggestion := range validationResult.Suggestions {
		vi.logger.Info("Configuration suggestion", zap.String("suggestion", suggestion))
	}

	// Check if configuration is valid
	if !validationResult.Valid {
		vi.logger.Error("Configuration validation failed",
			zap.Strings("errors", validationResult.Errors),
			zap.String("method", validationResult.Method))
		return fmt.Errorf("configuration invalid: %s\nConfig file: %s\nFix: Review configuration and correct any errors",
			strings.Join(validationResult.Errors, "; "), configPath)
	}

	vi.logger.Info("Configuration validated successfully",
		zap.String("method", validationResult.Method))
	return nil
}

// setupService configures and starts the Vault systemd service
func (vi *VaultInstaller) setupService() error {
	vi.logger.Info("Setting up Vault systemd service")

	// Create systemd service file
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
EnvironmentFile=%s/vault.env
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
AmbientCapabilities=CAP_IPC_LOCK
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
`, vi.config.ConfigPath, vi.config.ConfigPath,
		vi.config.ServiceUser, vi.config.ServiceGroup,
		vi.config.BinaryPath, vi.config.ConfigPath)

	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", vi.config.ServiceName)
	if err := vi.writeFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	// Create environment file
	envContent := fmt.Sprintf(`VAULT_API_ADDR=%s
VAULT_CLUSTER_ADDR=%s
`, vi.config.APIAddr, vi.config.ClusterAddr)

	envPath := filepath.Join(vi.config.ConfigPath, "vault.env")
	if err := vi.writeFile(envPath, []byte(envContent), 0640); err != nil {
		return fmt.Errorf("failed to write environment file: %w", err)
	}

	// Set ownership for env file
	if err := vi.runner.Run("chown", vi.config.ServiceUser+":"+vi.config.ServiceGroup, envPath); err != nil {
		return fmt.Errorf("failed to set env file ownership: %w", err)
	}

	// Reload systemd
	if err := vi.runner.Run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	if err := vi.systemd.Enable(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service with retries
	vi.logger.Info("Starting Vault service")
	if err := vi.systemd.Start(); err != nil {
		// Get detailed service status and logs for debugging
		if status, statusErr := vi.systemd.GetStatus(); statusErr == nil {
			vi.logger.Error("Failed to start Vault service",
				zap.String("status", status))
		}

		// Get journalctl logs to understand WHY vault failed
		if output, logErr := vi.runner.RunOutput("journalctl", "-xeu", "vault.service", "-n", "50", "--no-pager"); logErr == nil {
			vi.logger.Error("Vault service logs",
				zap.String("journalctl_output", output))
		}

		// Check if config file exists and is readable
		if _, statErr := os.Stat(vi.config.ConfigPath); statErr != nil {
			vi.logger.Error("Config file issue",
				zap.String("path", vi.config.ConfigPath),
				zap.Error(statErr))
		}

		// Provide actionable remediation
		vi.logger.Error("Vault failed to start - check the logs above for details",
			zap.String("remediation", "Run: sudo journalctl -xeu vault.service | tail -50"))

		return fmt.Errorf("failed to start service: %w", err)
	}

	// Wait for Vault to be ready
	vi.logger.Info("Waiting for Vault to be ready")
	ctx, cancel := context.WithTimeout(vi.rc.Ctx, 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Vault to be ready")
		case <-ticker.C:
			if vi.isVaultReady() {
				vi.logger.Info("Vault is ready")
				return nil
			}
		}
	}
}

// verify performs post-installation verification
func (vi *VaultInstaller) verify() error {
	vi.logger.Info("Verifying Vault installation")

	// Check service status
	if !vi.systemd.IsActive() {
		return fmt.Errorf("vault service is not active")
	}

	// Check Vault status
	if err := vi.runner.Run(vi.config.BinaryPath, "status"); err != nil {
		// Vault returns exit code 2 when sealed, which is expected
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			vi.logger.Info("Vault is installed and sealed (expected)")
		} else {
			return fmt.Errorf("vault is not responding to commands: %w", err)
		}
	}

	// Log success information
	vi.logger.Info("Vault installation verified successfully",
		zap.String("storage_backend", vi.config.StorageBackend),
		zap.String("api_url", vi.config.APIAddr))

	// Print user instructions
	vi.logger.Info("terminal prompt: ")
	vi.logger.Info("terminal prompt:  Vault installation completed successfully!")
	vi.logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", vi.config.Port))
	vi.logger.Info("terminal prompt: ")
	vi.logger.Info("terminal prompt: IMPORTANT: Vault needs to be initialized and unsealed")
	vi.logger.Info("terminal prompt: ")
	vi.logger.Info("terminal prompt: To initialize Vault:")
	vi.logger.Info("terminal prompt:   vault operator init")
	vi.logger.Info("terminal prompt: ")
	vi.logger.Info("terminal prompt: To unseal Vault (requires 3 unseal keys):")
	vi.logger.Info("terminal prompt:   vault operator unseal <key1>")
	vi.logger.Info("terminal prompt:   vault operator unseal <key2>")
	vi.logger.Info("terminal prompt:   vault operator unseal <key3>")

	return nil
}

// isVaultReady checks if Vault is ready to accept requests
func (vi *VaultInstaller) isVaultReady() bool {
	// Check if Vault process is responding
	// Note: Vault may be sealed, but that's OK - we just want to know it's running
	_, err := vi.runner.RunOutput(vi.config.BinaryPath, "status")
	if err != nil {
		// Exit code 2 means sealed, which is still "ready" for our purposes
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			return true
		}
		return false
	}
	return true
}

// cleanExistingInstallation removes existing Vault installation
func (vi *VaultInstaller) cleanExistingInstallation() error {
	vi.logger.Info("Cleaning existing Vault installation")

	// Stop service if running
	if vi.systemd.IsActive() {
		if err := vi.systemd.Stop(); err != nil {
			vi.logger.Warn("Failed to stop Vault service", zap.Error(err))
		}
	}

	// Remove data directory
	if err := os.RemoveAll(vi.config.DataPath); err != nil {
		vi.logger.Warn("Failed to remove data directory", zap.Error(err))
	}

	// Remove log directory
	if err := os.RemoveAll(vi.config.LogPath); err != nil {
		vi.logger.Warn("Failed to remove log directory", zap.Error(err))
	}

	return nil
}

// getLatestVersion fetches the latest Vault version from HashiCorp
func (vi *VaultInstaller) getLatestVersion() (string, error) {
	// Query HashiCorp checkpoint API
	resp, err := vi.httpGet("https://checkpoint-api.hashicorp.com/v1/check/vault")
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

func (vi *VaultInstaller) checkMemory() error {
	// BUG FIX: Read SYSTEM memory, not Go runtime memory
	// runtime.MemStats.Sys only shows Go runtime heap, not total RAM

	// Read /proc/meminfo on Linux for actual system memory
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		// If we can't read meminfo, don't block installation
		vi.logger.Warn("Could not check system memory, proceeding anyway", zap.Error(err))
		return nil
	}

	// Parse MemTotal from /proc/meminfo
	// Format: "MemTotal:       16384000 kB"
	lines := strings.Split(string(data), "\n")
	var totalKB int64
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, _ = strconv.ParseInt(fields[1], 10, 64)
				break
			}
		}
	}

	totalMB := totalKB / 1024
	vi.logger.Info("System memory detected",
		zap.Int64("total_mb", totalMB),
		zap.Int64("required_mb", 256))

	if totalMB < 256 {
		return fmt.Errorf("insufficient memory: %dMB (minimum 256MB required)", totalMB)
	}

	return nil
}

func (vi *VaultInstaller) checkDiskSpace(path string, requiredMB int64) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		vi.logger.Warn("Could not check disk space", zap.Error(err))
		return nil
	}

	availableMB := int64(stat.Bavail) * int64(stat.Bsize) / 1024 / 1024
	if availableMB < requiredMB {
		return fmt.Errorf("insufficient disk space in %s: %dMB available (minimum %dMB required)",
			path, availableMB, requiredMB)
	}

	return nil
}

func (vi *VaultInstaller) checkPortAvailable(port int) error {
	// Use lsof to check what's using the port
	output, err := vi.runner.RunOutput("sh", "-c", fmt.Sprintf("lsof -i :%d 2>/dev/null | grep LISTEN | awk '{print $1}' | head -1", port))
	if err != nil || output == "" {
		// Port is available
		return nil
	}

	processName := strings.TrimSpace(output)

	// If it's Vault already using the port, that's fine for idempotency
	if processName == "vault" {
		vi.logger.Debug("Port already in use by Vault", zap.Int("port", port))
		// Check if this is our Vault or another instance
		if vi.systemd.IsActive() {
			// It's our managed Vault, that's OK
			return nil
		}
		// It's another Vault instance
		return fmt.Errorf("port %d is already in use by another Vault instance", port)
	}

	// Some other process is using the port
	return fmt.Errorf("port %d is already in use by %s", port, processName)
}

func (vi *VaultInstaller) createDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return nil
}

func (vi *VaultInstaller) writeFile(path string, content []byte, mode os.FileMode) error {
	return os.WriteFile(path, content, mode)
}

func (vi *VaultInstaller) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (vi *VaultInstaller) downloadFile(url, dest string) error {
	// Download using wget
	if err := vi.runner.Run("wget", "-O", dest, url); err != nil {
		return err
	}
	return nil
}

func (vi *VaultInstaller) httpGet(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(vi.rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := vi.network.client.Do(req)
	if err != nil {
		return nil, err
	}
	// SECURITY P2 #8: Check defer Body.Close() error
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			vi.logger.Warn("Failed to close HTTP response body", zap.Error(closeErr))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
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

// generateSelfSignedCert generates a self-signed TLS certificate for Vault
func (vi *VaultInstaller) generateSelfSignedCert() error {
	vi.logger.Info("Generating self-signed TLS certificate for Vault")

	// Create TLS directory
	tlsDir := filepath.Join(vi.config.ConfigPath, "tls")
	if err := vi.createDirectory(tlsDir, 0755); err != nil {
		return fmt.Errorf("failed to create TLS directory: %w", err)
	}

	certPath := filepath.Join(tlsDir, "vault.crt")
	keyPath := filepath.Join(tlsDir, "vault.key")

	// Check if certificate already exists
	if vi.fileExists(certPath) && vi.fileExists(keyPath) {
		vi.logger.Info("TLS certificate already exists, skipping generation")
		return nil
	}

	// Get hostname and FQDN for certificate
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "vault-server"
		vi.logger.Warn("Failed to get hostname, using default", zap.Error(err))
	}

	// Build list of DNS names for SAN
	dnsNames := []string{hostname, "localhost", "vault"}

	// Try to get FQDN (may be different from hostname)
	if fqdnOutput, err := exec.Command("hostname", "-f").Output(); err == nil {
		fqdn := strings.TrimSpace(string(fqdnOutput))
		// Only add if different from hostname
		if fqdn != "" && fqdn != hostname && !strings.EqualFold(fqdn, hostname) {
			dnsNames = append(dnsNames, fqdn)
			vi.logger.Info("Adding FQDN to certificate SAN",
				zap.String("hostname", hostname),
				zap.String("fqdn", fqdn))
		}
	}

	// Also try to resolve hostname to get canonical name
	if addrs, err := net.LookupHost(hostname); err == nil && len(addrs) > 0 {
		// Get reverse DNS for first address
		if names, err := net.LookupAddr(addrs[0]); err == nil {
			for _, name := range names {
				// Remove trailing dot and check if different
				canonicalName := strings.TrimSuffix(name, ".")
				if canonicalName != hostname && canonicalName != "" {
					// Check if not already in list
					found := false
					for _, existing := range dnsNames {
						if existing == canonicalName {
							found = true
							break
						}
					}
					if !found {
						dnsNames = append(dnsNames, canonicalName)
						vi.logger.Debug("Adding canonical name to certificate SAN",
							zap.String("canonical_name", canonicalName))
					}
				}
			}
		}
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Eos Vault"},
			Country:      []string{"AU"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Write certificate file
	if err := vi.writeFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write key file with restricted permissions
	if err := vi.writeFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Set ownership
	if err := vi.runner.Run("chown", vi.config.ServiceUser+":"+vi.config.ServiceGroup, certPath); err != nil {
		return fmt.Errorf("failed to set certificate ownership: %w", err)
	}
	if err := vi.runner.Run("chown", vi.config.ServiceUser+":"+vi.config.ServiceGroup, keyPath); err != nil {
		return fmt.Errorf("failed to set key ownership: %w", err)
	}

	vi.logger.Info("TLS certificate generated successfully",
		zap.String("cert_path", certPath),
		zap.String("key_path", keyPath))

	// Store certificate metadata in Consul KV
	if err := vi.storeCertMetadataInConsul(certPath, keyPath, dnsNames, template.NotAfter); err != nil {
		// Log warning but don't fail - Consul may not be available yet
		vi.logger.Warn("Failed to store certificate metadata in Consul KV",
			zap.Error(err),
			zap.String("note", "This is not critical - metadata is advisory only"))
	}

	return nil
}

// storeCertMetadataInConsul stores TLS certificate metadata in Consul KV
func (vi *VaultInstaller) storeCertMetadataInConsul(certPath, keyPath string, dnsNames []string, expiryTime time.Time) error {
	vi.logger.Debug("Storing certificate metadata in Consul KV")

	// Check if Consul is available
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	if consulAddr == "" {
		consulAddr = "127.0.0.1:8500"
	}

	// Create Consul client
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = consulAddr
	client, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Prepare metadata
	metadata := map[string]interface{}{
		"service":      "vault",
		"cert_path":    certPath,
		"key_path":     keyPath,
		"dns_names":    dnsNames,
		"expiry":       expiryTime.Format(time.RFC3339),
		"generated_at": time.Now().Format(time.RFC3339),
		"generated_by": "eos",
		"hostname":     vi.config.ServiceUser,
	}

	// Convert to JSON
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Store in Consul KV under vault/tls/certificate
	kv := client.KV()
	p := &consulapi.KVPair{
		Key:   "vault/tls/certificate/metadata",
		Value: metadataJSON,
	}

	// Put to Consul KV
	_, err = kv.Put(p, nil)
	if err != nil {
		return fmt.Errorf("failed to write to Consul KV: %w", err)
	}

	vi.logger.Info("Certificate metadata stored in Consul KV",
		zap.String("key", "vault/tls/certificate/metadata"),
		zap.Strings("dns_names", dnsNames),
		zap.String("expiry", expiryTime.Format(time.RFC3339)))

	return nil
}
