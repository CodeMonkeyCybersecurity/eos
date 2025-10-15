// pkg/vault/install.go

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
	AutoUnseal        bool
	AutoUnsealType    string // "awskms", "azurekeyvault", "gcpckms"
	KMSKeyID          string // For AWS KMS auto-unseal
	KMSRegion         string // AWS region or Azure location
	AzureTenantID     string // Azure tenant ID
	AzureClientID     string // Azure client ID
	AzureClientSecret string // Azure client secret
	AzureVaultName    string // Azure Key Vault name
	AzureKeyName      string // Azure Key Vault key name
	GCPProject        string // GCP project ID
	GCPLocation       string // GCP location
	GCPKeyRing        string // GCP KMS keyring
	GCPCryptoKey      string // GCP KMS crypto key
	GCPCredentials    string // Path to GCP credentials file

	LogLevel   string
	Datacenter string // Consul datacenter for service registration

	// Multi-node Raft cluster configuration
	RaftMode       string // "create" (default) or "join" - determines if this is a new cluster or joining existing
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
	if config.NodeID == "" {
		// Default node ID to hostname
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "vault-node-1"
		}
		config.NodeID = hostname
	}
	if config.RaftMode == "" {
		// Default to create mode (new cluster)
		config.RaftMode = "create"
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

// PreflightChecks performs pre-creation validation to prevent race conditions
// between deletion and creation. This ensures the system is in a clean state
// before attempting installation.
func (vi *VaultInstaller) PreflightChecks() error {
	vi.logger.Info("Running preflight checks to prevent race conditions")

	// Check if Vault service is already running
	vi.logger.Debug("Checking if Vault service is active")
	if output, err := exec.Command("systemctl", "is-active", "vault").Output(); err == nil {
		status := strings.TrimSpace(string(output))
		if status == "active" {
			vi.logger.Error("Vault service is already running",
				zap.String("status", status))
			return fmt.Errorf("Vault service is already running. Delete first: sudo eos delete vault")
		}
		vi.logger.Debug("Vault service exists but not active",
			zap.String("status", status))
	} else {
		vi.logger.Debug("Vault service not found (expected for clean install)")
	}

	// Check if vault user exists
	vi.logger.Debug("Checking if vault user exists")
	if err := exec.Command("id", "vault").Run(); err == nil {
		vi.logger.Error("Vault user already exists - deletion may not be complete")
		return fmt.Errorf("Vault user already exists. Deletion may not be complete. Wait 10 seconds and retry")
	} else {
		vi.logger.Debug("Vault user does not exist (expected for clean install)")
	}

	// Check if vault binary exists
	vi.logger.Debug("Checking if vault binary exists")
	if binaryPath, err := exec.LookPath("vault"); err == nil {
		vi.logger.Error("Vault binary still exists",
			zap.String("path", binaryPath))
		return fmt.Errorf("Vault binary still exists at %s. Delete first: sudo eos delete vault", binaryPath)
	} else {
		vi.logger.Debug("Vault binary does not exist (expected for clean install)")
	}

	vi.logger.Info("Preflight checks passed - system is ready for installation")
	return nil
}

// Install performs the complete Vault installation (Phases 1-4)
//
// This handles the base installation infrastructure. After Install() completes,
// call EnableVault() to perform Phases 5-15 (initialization, auth, secrets, hardening).
//
// Phase Breakdown:
//
//	Phase 1: Binary installation (via repository or direct download)
//	Phase 2: Environment setup (VAULT_ADDR, VAULT_CACERT, directories)
//	Phase 3: TLS certificate generation
//	Phase 4: Configuration file generation (vault.hcl)
//
// After this method completes, the Vault service is installed and ready to start,
// but NOT initialized. Call EnableVault() for Phases 5-15.
func (vi *VaultInstaller) Install() error {
	vi.logger.Info("Starting Vault installation (Phases 1-4)",
		zap.String("version", vi.config.Version),
		zap.String("storage_backend", vi.config.StorageBackend),
		zap.Bool("use_repository", vi.config.UseRepository))

	// Pre-Phase: Run preflight checks to prevent race conditions
	vi.progress.Update("[7%] Running preflight checks")
	if err := vi.PreflightChecks(); err != nil {
		return fmt.Errorf("preflight checks failed: %w", err)
	}

	// Pre-Phase: ASSESS - Check if already installed
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

	// Pre-Phase: Validate prerequisites
	vi.progress.Update("[28%] Validating prerequisites")
	if err := vi.validatePrerequisites(); err != nil {
		return fmt.Errorf("prerequisite validation failed: %w", err)
	}

	// Phase 1: Install Vault binary
	vi.progress.Update("[42%] [Phase 1] Installing Vault binary")
	if err := vi.installBinary(); err != nil {
		return fmt.Errorf("binary installation failed: %w", err)
	}

	// Cleanup duplicate binaries (non-fatal)
	vi.logger.Debug("Checking for duplicate Vault binaries")
	if err := CleanupDuplicateBinaries(vi.rc, vi.config.BinaryPath); err != nil {
		vi.logger.Warn("Could not cleanup duplicate binaries (non-fatal)", zap.Error(err))
	}

	// Phase 1 (continued): Create vault user and directories
	vi.progress.Update("[56%] [Phase 1] Creating user and directories")
	if err := vi.setupUserAndDirectories(); err != nil {
		return fmt.Errorf("user/directory setup failed: %w", err)
	}

	// Phase 1.5: Prompt for Raft cluster configuration (if using Raft storage)
	if vi.config.StorageBackend == "raft" {
		vi.progress.Update("[60%] Configuring Raft cluster mode")
		if err := vi.promptRaftClusterConfig(); err != nil {
			return fmt.Errorf("raft cluster configuration failed: %w", err)
		}
	}

	// Phases 2-4: Configure (environment, TLS, config file)
	vi.progress.Update("[70%] [Phases 2-4] Configuring Vault")
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

	// Post-Phase: Setup systemd service
	vi.progress.Update("[84%] Setting up systemd service")
	if err := vi.setupService(); err != nil {
		return fmt.Errorf("service setup failed: %w", err)
	}

	// Post-Phase: EVALUATE - Verify installation
	vi.progress.Update("[92%] Verifying installation")
	if err := vi.verify(); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Display post-installation security checklist
	vi.logger.Info(" Displaying security guidance")
	DisplayPostInstallSecurityChecklist(vi.rc)

	// Post-Phase: Register with Consul (if available)
	vi.progress.Update("[100%] Registering with Consul")
	if err := vi.registerWithConsul(); err != nil {
		vi.logger.Warn("Failed to register with Consul (non-critical)",
			zap.Error(err))
		// Don't fail installation if Consul registration fails
	}

	vi.progress.Complete("Vault installation completed successfully (Phases 1-4 complete)")
	vi.logger.Info("Next step: Call EnableVault() for Phases 5-15 (initialization, auth, secrets, hardening)")
	return nil
}

// promptRaftClusterConfig prompts user for Raft cluster configuration (join vs create)
func (vi *VaultInstaller) promptRaftClusterConfig() error {
	// Only prompt if storage backend is raft and mode is not already set
	if vi.config.StorageBackend != "raft" {
		vi.logger.Debug("Skipping Raft cluster prompts - storage backend is not raft",
			zap.String("backend", vi.config.StorageBackend))
		return nil
	}

	if vi.config.RaftMode != "" {
		vi.logger.Debug("Raft mode already configured",
			zap.String("mode", vi.config.RaftMode))
		return nil
	}

	vi.logger.Info("Configuring Raft cluster mode")
	vi.logger.Info("terminal prompt: ")
	vi.logger.Info("terminal prompt: Raft Cluster Configuration")
	vi.logger.Info("terminal prompt: ===========================")
	vi.logger.Info("terminal prompt: ")
	vi.logger.Info("terminal prompt: Choose how this Vault node should operate:")
	vi.logger.Info("terminal prompt:   1. Join existing Raft cluster (default)")
	vi.logger.Info("terminal prompt:   2. Create new Raft cluster")
	vi.logger.Info("terminal prompt: ")

	mode, err := eos_io.PromptInput(vi.rc, "Select mode [1-2]", "1")
	if err != nil {
		return fmt.Errorf("failed to read cluster mode selection: %w", err)
	}

	switch mode {
	case "1", "":
		vi.config.RaftMode = "join"
		vi.logger.Info("Selected mode: Join existing cluster")

		// Prompt for leader node address
		vi.logger.Info("terminal prompt: ")
		vi.logger.Info("terminal prompt: To join an existing cluster, provide the API address of a cluster leader.")
		vi.logger.Info("terminal prompt: Example: https://vault-leader.example.com:8200")
		vi.logger.Info("terminal prompt: ")

		leaderAddr, err := eos_io.PromptInput(vi.rc, "Leader API address", "")
		if err != nil {
			return fmt.Errorf("failed to read leader address: %w", err)
		}
		if leaderAddr == "" {
			return fmt.Errorf("leader API address is required when joining a cluster")
		}

		// Add to retry_join configuration
		vi.config.RetryJoinNodes = []shared.RetryJoinNode{
			{
				APIAddr:  leaderAddr,
				Hostname: "", // Will be resolved from API address
			},
		}

		vi.logger.Info("Configured to join existing cluster",
			zap.String("leader_api_addr", leaderAddr))

	case "2":
		vi.config.RaftMode = "create"
		vi.logger.Info("Selected mode: Create new cluster")
		vi.logger.Info("terminal prompt: ")
		vi.logger.Info("terminal prompt: This node will initialize as the first member of a new Raft cluster.")
		vi.logger.Info("terminal prompt: Additional nodes can be added later by joining this cluster.")
		vi.logger.Info("terminal prompt: ")

	default:
		return fmt.Errorf("invalid selection: %s (must be 1 or 2)", mode)
	}

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

	// CRITICAL FIX: Ensure parent directories exist with correct permissions FIRST
	// os.MkdirAll creates parent directories with the SAME mode as the target,
	// which causes permission issues when the parent is mode 0700 but owned by root
	// while the child needs to be accessed by the vault user.
	//
	// Root cause: When creating /opt/vault/data with mode 0700, MkdirAll creates
	// /opt/vault with mode 0700 too. Then chown -R only changes /opt/vault/data
	// ownership, leaving /opt/vault owned by root with 0700, which the vault user
	// cannot traverse.
	//
	// Solution: Create parent with 0755 (traversable) and proper ownership first.
	parentDirs := []struct {
		path  string
		mode  os.FileMode
		owner string
	}{
		{"/opt/vault", 0755, vi.config.ServiceUser}, // Parent must be traversable (0755)
	}

	for _, dir := range parentDirs {
		// Log what we're about to do
		vi.logger.Info("Setting up parent directory",
			zap.String("path", dir.path),
			zap.String("target_mode", fmt.Sprintf("%04o", dir.mode)),
			zap.String("target_owner", dir.owner+":"+dir.owner))

		// Check if directory already exists
		existingInfo, existsErr := os.Stat(dir.path)
		if existsErr == nil {
			vi.logger.Info("Parent directory already exists, will fix permissions",
				zap.String("path", dir.path),
				zap.String("current_mode", fmt.Sprintf("%04o", existingInfo.Mode().Perm())))
		}

		// Lookup vault user for atomic operations
		vaultUser, err := user.Lookup(dir.owner)
		if err != nil {
			vi.logger.Error("Failed to lookup vault user",
				zap.String("user", dir.owner),
				zap.Error(err))
			return fmt.Errorf("failed to lookup user %s: %w", dir.owner, err)
		}

		uid, err := strconv.Atoi(vaultUser.Uid)
		if err != nil {
			vi.logger.Error("Failed to parse UID",
				zap.String("user", dir.owner),
				zap.String("uid_string", vaultUser.Uid),
				zap.Error(err))
			return fmt.Errorf("failed to parse UID for user %s: %w", dir.owner, err)
		}

		gid, err := strconv.Atoi(vaultUser.Gid)
		if err != nil {
			vi.logger.Error("Failed to parse GID",
				zap.String("user", dir.owner),
				zap.String("gid_string", vaultUser.Gid),
				zap.Error(err))
			return fmt.Errorf("failed to parse GID for user %s: %w", dir.owner, err)
		}

		vi.logger.Debug("User lookup successful",
			zap.String("user", dir.owner),
			zap.Int("uid", uid),
			zap.Int("gid", gid))

		// ATOMIC APPROACH: Create directory with restrictive permissions, then chown, then chmod
		// NOTE: We don't use umask because it's process-global and racy in multi-threaded programs.
		// Instead we use: create restrictive (0700) → chown → chmod to desired mode
		restrictiveMode := os.FileMode(0700)

		vi.logger.Debug("Creating directory with restrictive→chown→chmod pattern",
			zap.String("path", dir.path),
			zap.String("initial_mode", fmt.Sprintf("%04o", restrictiveMode)),
			zap.String("final_mode", fmt.Sprintf("%04o", dir.mode)))

		// Step 1: Create directory with restrictive permissions (0700)
		if err := os.MkdirAll(dir.path, restrictiveMode); err != nil && !os.IsExist(err) {
			vi.logger.Error("Failed to create parent directory",
				zap.String("path", dir.path),
				zap.String("mode", fmt.Sprintf("%04o", restrictiveMode)),
				zap.Error(err))
			return fmt.Errorf("failed to create parent directory %s: %w", dir.path, err)
		}

		// Step 2: Set ownership BEFORE loosening permissions (security-critical order)
		vi.logger.Debug("Setting ownership (step 2 of 3)",
			zap.String("path", dir.path),
			zap.Int("uid", uid),
			zap.Int("gid", gid))

		if err := syscall.Chown(dir.path, uid, gid); err != nil {
			vi.logger.Error("Failed to set ownership",
				zap.String("path", dir.path),
				zap.Int("uid", uid),
				zap.Int("gid", gid),
				zap.Error(err))
			return fmt.Errorf("failed to change ownership of %s to %s:%s: %w",
				dir.path, dir.owner, dir.owner, err)
		}

		// Step 3: Now set desired permissions (loosening from 0700 to target mode)
		vi.logger.Debug("Setting final permissions (step 3 of 3)",
			zap.String("path", dir.path),
			zap.String("mode", fmt.Sprintf("%04o", dir.mode)))

		if err := syscall.Chmod(dir.path, uint32(dir.mode)); err != nil {
			vi.logger.Error("Failed to set permissions",
				zap.String("path", dir.path),
				zap.String("mode", fmt.Sprintf("%04o", dir.mode)),
				zap.Error(err))
			return fmt.Errorf("failed to set permissions on %s: %w", dir.path, err)
		}

		// Verify permissions were set correctly
		verifyInfo, err := os.Stat(dir.path)
		if err != nil {
			return fmt.Errorf("failed to verify parent directory %s: %w", dir.path, err)
		}

		actualMode := verifyInfo.Mode().Perm()
		if actualMode != dir.mode {
			vi.logger.Warn("Parent directory permissions mismatch",
				zap.String("path", dir.path),
				zap.String("expected", fmt.Sprintf("%04o", dir.mode)),
				zap.String("actual", fmt.Sprintf("%04o", actualMode)))

			// Try one more time to fix it
			if err := vi.runner.Run("chmod", fmt.Sprintf("%04o", dir.mode), dir.path); err != nil {
				return fmt.Errorf("failed to correct permissions for %s: %w", dir.path, err)
			}

			// VERIFY AGAIN after second attempt
			verifyInfo2, err := os.Stat(dir.path)
			if err != nil {
				return fmt.Errorf("failed to verify parent directory after retry %s: %w", dir.path, err)
			}

			actualMode2 := verifyInfo2.Mode().Perm()
			if actualMode2 != dir.mode {
				vi.logger.Error("Permissions still incorrect after retry",
					zap.String("path", dir.path),
					zap.String("expected", fmt.Sprintf("%04o", dir.mode)),
					zap.String("actual_after_retry", fmt.Sprintf("%04o", actualMode2)))
				return fmt.Errorf("permissions still incorrect after retry for %s: expected %04o, got %04o (may be SELinux/AppArmor interference)",
					dir.path, dir.mode, actualMode2)
			}

			vi.logger.Info("Permissions corrected successfully on retry",
				zap.String("path", dir.path),
				zap.String("mode", fmt.Sprintf("%04o", dir.mode)))
		}

		vi.logger.Info("Parent directory configured successfully",
			zap.String("path", dir.path),
			zap.String("mode", fmt.Sprintf("%04o", dir.mode)),
			zap.String("owner", dir.owner+":"+dir.owner))
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
		vi.logger.Info("Creating service directory",
			zap.String("path", dir.path),
			zap.String("target_mode", fmt.Sprintf("%04o", dir.mode)),
			zap.String("target_owner", dir.owner+":"+dir.owner))

		if err := vi.createDirectory(dir.path, dir.mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir.path, err)
		}

		if err := vi.runner.Run("chown", "-R", dir.owner+":"+dir.owner, dir.path); err != nil {
			return fmt.Errorf("failed to set ownership for %s: %w", dir.path, err)
		}

		vi.logger.Info("Service directory configured successfully",
			zap.String("path", dir.path),
			zap.String("mode", fmt.Sprintf("%04o", dir.mode)),
			zap.String("owner", dir.owner+":"+dir.owner))
	}

	return nil
}

// configure sets up Vault configuration (Phases 2-4)
//
// Phase 2: Environment setup (VAULT_ADDR, VAULT_CACERT, agent directories)
// Phase 3: TLS certificate generation
// Phase 4: Configuration file generation (vault.hcl)
func (vi *VaultInstaller) configure() error {
	vi.logger.Info("Configuring Vault (Phases 2-4)")

	// Phase 2: Set up Vault environment variables (VAULT_ADDR, VAULT_CACERT)
	vi.logger.Info("[Phase 2] Setting up Vault environment variables")
	if _, err := EnsureVaultEnv(vi.rc); err != nil {
		vi.logger.Warn("Failed to set VAULT_ADDR (non-fatal)", zap.Error(err))
		// Don't fail installation if env setup fails - user can set manually
	}

	// Phase 3: Generate TLS certificates if TLS is enabled
	vi.logger.Info("[Phase 3] Generating TLS certificates")
	if vi.config.TLSEnabled {
		if err := vi.generateTLSCertificate(); err != nil {
			return fmt.Errorf("failed to generate TLS certificate: %w", err)
		}
	}

	// Phase 4: Generate Vault configuration file (vault.hcl)
	vi.logger.Info("[Phase 4] Generating Vault configuration")

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
		// Build Raft configuration based on cluster mode
		var raftConfig string
		if vi.config.RaftMode == "join" && len(vi.config.RetryJoinNodes) > 0 {
			// Joining existing cluster - add retry_join configuration
			raftConfig = fmt.Sprintf(`storage "raft" {
  path    = "%s/raft"
  node_id = "%s"
`, vi.config.DataPath, vi.config.NodeID)

			// Add retry_join blocks for each leader node
			for _, node := range vi.config.RetryJoinNodes {
				raftConfig += fmt.Sprintf(`
  retry_join {
    leader_api_addr = "%s"
  }
`, node.APIAddr)
			}
			raftConfig += "}"

			vi.logger.Info("Configured Raft to join existing cluster",
				zap.Int("retry_join_nodes", len(vi.config.RetryJoinNodes)))
		} else {
			// Creating new cluster - standalone configuration
			raftConfig = fmt.Sprintf(`storage "raft" {
  path    = "%s/raft"
  node_id = "%s"
}`, vi.config.DataPath, vi.config.NodeID)

			vi.logger.Info("Configured Raft as new cluster leader")
		}
		storageConfig = raftConfig
	default:
		return fmt.Errorf("unsupported storage backend: %s (supported: raft, consul)", vi.config.StorageBackend)
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

	// Phase 2 (continued): Prepare Vault Agent environment
	vi.logger.Info("Preparing Vault Agent environment")
	if err := PrepareVaultAgentEnvironment(vi.rc); err != nil {
		vi.logger.Warn("Failed to prepare Vault Agent environment (non-fatal)", zap.Error(err))
		// Don't fail installation - agent setup happens in phase 14
	}

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

	// Wait for Vault to be ready (with granular status checks)
	vi.logger.Info("Waiting for Vault to become responsive")
	ctx, cancel := context.WithTimeout(vi.rc.Ctx, 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	attempt := 0
	for {
		select {
		case <-ctx.Done():
			// Timeout occurred - provide detailed feedback
			vi.logger.Warn("Timeout waiting for Vault, checking current state")

			// Even though we timed out, check if vault is actually running
			readiness := vi.checkVaultReadiness()

			if readiness.ProcessRunning && readiness.PortListening {
				// Vault IS running, just sealed/uninitialized (this is NORMAL)
				vi.logger.Info("Vault process is running and listening",
					zap.Bool("sealed", readiness.Sealed),
					zap.Bool("initialized", readiness.Initialized))

				if readiness.Sealed && !readiness.Initialized {
					vi.logger.Info("Vault is sealed and uninitialized (this is expected for new installations)")
					return nil // Success! This is the normal state for a fresh install
				} else if readiness.Sealed {
					vi.logger.Info("Vault is sealed but initialized (normal state after restart)")
					return nil // Success! Just needs unsealing
				}

				// Process running but not responding correctly
				vi.logger.Warn("Vault process is running but not responding as expected",
					zap.String("details", readiness.Message))
				return fmt.Errorf("vault is running but not responding properly: %s", readiness.Message)
			}

			// Process not running or not listening
			vi.logger.Error("Vault failed to become ready",
				zap.Bool("process_running", readiness.ProcessRunning),
				zap.Bool("port_listening", readiness.PortListening),
				zap.String("error", readiness.Message))
			return fmt.Errorf("vault failed to start properly: %s", readiness.Message)

		case <-ticker.C:
			attempt++
			readiness := vi.checkVaultReadiness()

			vi.logger.Debug("Checking vault readiness",
				zap.Int("attempt", attempt),
				zap.Bool("process_running", readiness.ProcessRunning),
				zap.Bool("port_listening", readiness.PortListening),
				zap.Bool("responding", readiness.Responding),
				zap.String("status", readiness.Message))

			if readiness.Ready {
				vi.logger.Info("Vault is ready",
					zap.Bool("sealed", readiness.Sealed),
					zap.Bool("initialized", readiness.Initialized))
				return nil
			}

			// If vault is running and responding (even if sealed), that's good enough
			if readiness.ProcessRunning && readiness.PortListening && readiness.Responding {
				vi.logger.Info("Vault is responding",
					zap.Bool("sealed", readiness.Sealed),
					zap.Bool("initialized", readiness.Initialized))
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

	// Check Vault status using RunWithExitCode to properly handle exit code 2 (sealed)
	// Vault returns different exit codes:
	// - 0: unsealed and ready
	// - 1: error occurred
	// - 2: sealed (expected for new installation)
	output, exitCode, err := vi.runner.RunWithExitCode(vi.config.BinaryPath, "status")
	if err != nil {
		// This is an actual execution error (not just non-zero exit code)
		return fmt.Errorf("vault is not responding to commands: %w", err)
	}

	vi.logger.Debug("Vault status check completed",
		zap.Int("exit_code", exitCode),
		zap.String("output", output))

	switch exitCode {
	case 0:
		vi.logger.Info("Vault is installed and unsealed")
	case 2:
		vi.logger.Info("Vault is installed and sealed (expected for new installation)")
	default:
		return fmt.Errorf("vault status returned unexpected exit code %d: %s", exitCode, output)
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

// VaultReadiness contains detailed readiness information
type VaultReadiness struct {
	Ready          bool   // Overall ready status
	ProcessRunning bool   // Is vault process running
	PortListening  bool   // Is vault listening on port
	Responding     bool   // Is vault responding to API calls
	Sealed         bool   // Is vault sealed
	Initialized    bool   // Is vault initialized
	Message        string // Human-readable status message
}

// checkVaultReadiness performs comprehensive readiness checks
func (vi *VaultInstaller) checkVaultReadiness() *VaultReadiness {
	readiness := &VaultReadiness{}

	// Check 1: Is vault process running?
	cmd := exec.Command("pgrep", "-x", "vault")
	if err := cmd.Run(); err == nil {
		readiness.ProcessRunning = true
	} else {
		readiness.Message = "vault process not found"
		return readiness
	}

	// Check 2: Is vault listening on the port?
	portCmd := exec.Command("sh", "-c", fmt.Sprintf("lsof -i :%d 2>/dev/null | grep -q vault || ss -tlnp 2>/dev/null | grep -q ':%d'", vi.config.Port, vi.config.Port))
	if err := portCmd.Run(); err == nil {
		readiness.PortListening = true
	} else {
		readiness.Message = "vault not listening on port"
		return readiness
	}

	// Check 3: Is vault responding to status command?
	// For self-signed TLS certificates, we need to skip verification during health checks
	vaultAddr := fmt.Sprintf("https://127.0.0.1:%d", vi.config.Port)

	vi.logger.Debug("Running vault status health check",
		zap.String("binary_path", vi.config.BinaryPath),
		zap.String("vault_addr", vaultAddr),
		zap.Bool("tls_enabled", vi.config.TLSEnabled),
		zap.String("skip_verify", "true"))

	statusCmd := exec.CommandContext(vi.rc.Ctx, vi.config.BinaryPath, "status")

	// Build clean environment for health check:
	// - Copy parent environment
	// - Remove VAULT_CACERT (we're skipping TLS verification anyway)
	// - Set VAULT_SKIP_VERIFY=1 (skip TLS verification for self-signed certs)
	// - Set VAULT_ADDR explicitly
	cleanEnv := make([]string, 0, len(os.Environ())+2)
	for _, env := range os.Environ() {
		// Filter out VAULT_CACERT since we're using VAULT_SKIP_VERIFY
		if !strings.HasPrefix(env, "VAULT_CACERT=") {
			cleanEnv = append(cleanEnv, env)
		}
	}
	cleanEnv = append(cleanEnv,
		"VAULT_SKIP_VERIFY=1",
		fmt.Sprintf("VAULT_ADDR=%s", vaultAddr),
	)
	statusCmd.Env = cleanEnv

	statusOutputBytes, statusErr := statusCmd.CombinedOutput()
	statusOutput := string(statusOutputBytes)

	vi.logger.Debug("Vault status command completed",
		zap.Bool("has_error", statusErr != nil),
		zap.Int("output_length", len(statusOutput)),
		zap.String("output_preview", func() string {
			if len(statusOutput) > 200 {
				return statusOutput[:200] + "..."
			}
			return statusOutput
		}()))

	if statusErr != nil {
		if exitErr, ok := statusErr.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			vi.logger.Debug("Vault status returned non-zero exit code",
				zap.Int("exit_code", exitCode),
				zap.String("stderr", string(exitErr.Stderr)))

			// Exit code 2 means sealed (this is NORMAL for new installs)
			if exitCode == 2 {
				vi.logger.Info("Vault is sealed (normal for new installations)",
					zap.Int("exit_code", exitCode))
				readiness.Responding = true
				readiness.Sealed = true

				// Parse output to check if initialized
				if strings.Contains(statusOutput, "Initialized") {
					if strings.Contains(statusOutput, "Initialized    true") ||
						strings.Contains(statusOutput, "Initialized: true") {
						readiness.Initialized = true
						readiness.Message = "vault is sealed but initialized (needs unsealing)"
						readiness.Ready = true // Sealed + initialized = ready to unseal
						vi.logger.Info("Vault is sealed but initialized - ready for unsealing")
					} else {
						readiness.Initialized = false
						readiness.Message = "vault is sealed and uninitialized (needs 'vault operator init')"
						readiness.Ready = true // Sealed + uninitialized = ready to initialize (normal for fresh install)
						vi.logger.Info("Vault is sealed and uninitialized - ready for init")
					}
				} else {
					// Couldn't parse initialization status, but vault is responding
					readiness.Message = "vault is responding but sealed"
					readiness.Ready = true
					vi.logger.Warn("Could not parse initialization status from vault output")
				}
				return readiness
			} else if exitCode == 1 {
				// Exit code 1 typically means vault is having issues or TLS problems
				vi.logger.Error("Vault status returned exit code 1",
					zap.Int("exit_code", exitCode),
					zap.String("output", statusOutput))
				readiness.Responding = false
				readiness.Message = fmt.Sprintf("vault returned error (exit code 1): %s", statusOutput)
				return readiness
			} else {
				// Unexpected exit code
				vi.logger.Error("Vault status returned unexpected exit code",
					zap.Int("exit_code", exitCode),
					zap.String("output", statusOutput))
				readiness.Responding = false
				readiness.Message = fmt.Sprintf("vault returned unexpected exit code %d: %s", exitCode, statusOutput)
				return readiness
			}
		}

		// Not an ExitError - something else went wrong
		vi.logger.Error("Vault status command failed with non-exit error",
			zap.Error(statusErr),
			zap.String("error_type", fmt.Sprintf("%T", statusErr)))
		readiness.Responding = false
		readiness.Message = fmt.Sprintf("vault status command failed: %v", statusErr)
		return readiness
	}

	// Exit code 0 means vault is unsealed and ready
	readiness.Responding = true
	readiness.Sealed = false
	readiness.Initialized = true
	readiness.Ready = true
	readiness.Message = "vault is unsealed and ready"

	return readiness
}

// isVaultReady checks if Vault is ready to accept requests (simplified version)
func (vi *VaultInstaller) isVaultReady() bool {
	readiness := vi.checkVaultReadiness()
	return readiness.Ready
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

// generateTLSCertificate generates a self-signed TLS certificate using the consolidated module
func (vi *VaultInstaller) generateTLSCertificate() error {
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
		if vi.config.ForceReinstall {
			vi.logger.Info("Force flag set, regenerating TLS certificate")
			// Backup existing certificate before regenerating
			backupPath := certPath + ".backup." + time.Now().Format("20060102-150405")
			if err := os.Rename(certPath, backupPath); err != nil {
				vi.logger.Warn("Failed to backup existing certificate", zap.Error(err))
			} else {
				vi.logger.Info("Backed up existing certificate", zap.String("backup", backupPath))
			}
			if err := os.Rename(keyPath, keyPath+".backup."+time.Now().Format("20060102-150405")); err != nil {
				vi.logger.Warn("Failed to backup existing key", zap.Error(err))
			}
			// Continue to regenerate
		} else {
			vi.logger.Info("TLS certificate already exists, skipping generation")
			vi.logger.Info("Use --force flag to regenerate certificate with updated SANs")
			return nil
		}
	}

	// Get hostname for certificate
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "vault-server"
		vi.logger.Warn("Failed to get hostname, using default", zap.Error(err))
	}

	// Create certificate configuration using consolidated module
	config := &CertificateConfig{
		Country:      "AU",
		State:        "WA",
		Locality:     "Fremantle",
		Organization: "Code Monkey Cybersecurity",
		CommonName:   hostname,
		ValidityDays: 3650, // 10 years for self-signed
		KeySize:      4096, // Strong security
		CertPath:     certPath,
		KeyPath:      keyPath,
		Owner:        vi.config.ServiceUser,
		Group:        vi.config.ServiceGroup,
		// Initial SANs - enrichSANs() will add comprehensive list automatically
		DNSNames:    []string{hostname, "localhost", "vault"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Generate certificate using consolidated module
	// This will automatically enrich SANs with all network interfaces, FQDN, wildcards, etc.
	if err := GenerateSelfSignedCertificate(vi.rc, config); err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	vi.logger.Info("TLS certificate generated successfully",
		zap.String("cert_path", certPath),
		zap.String("key_path", keyPath))

	// Store certificate metadata in Consul KV (if available)
	if err := vi.storeCertMetadataInConsul(certPath, keyPath, config.DNSNames, time.Now().Add(time.Duration(config.ValidityDays)*24*time.Hour)); err != nil {
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
