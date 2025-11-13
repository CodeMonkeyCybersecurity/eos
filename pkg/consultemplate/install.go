// pkg/consultemplate/install.go
//
// Consul Template Installation
//
// Provides installation functionality for HashiCorp Consul Template,
// following EOS patterns for HashiCorp product installations.
//
// Pattern: Assess → Intervene → Evaluate

package consultemplate

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallConfig contains configuration for Consul Template installation
type InstallConfig struct {
	Version        string // Version to install (e.g., "0.37.4")
	BinaryPath     string // Where to install binary (default: /usr/local/bin/consul-template)
	ConfigDir      string // Config directory (default: /etc/consul-template.d)
	TemplateDir    string // Template directory (default: /etc/consul-template.d/templates)
	DataDir        string // Data directory (default: /opt/consul-template)
	LogDir         string // Log directory (default: /var/log/consul-template)
	SystemUser     string // System user (default: consul-template)
	SystemGroup    string // System group (default: consul-template)
	ConsulAddr     string // Consul address (default: http://localhost:8500)
	VaultAddr      string // Vault address (default: https://localhost:8200)
	VaultTokenPath string // Vault token path (default: /run/eos/vault_agent_eos.token)
	SkipVerify     bool   // Skip GPG signature verification
	ForceReinstall bool   // Force reinstallation even if already installed
}

// DefaultInstallConfig returns default installation configuration
func DefaultInstallConfig() *InstallConfig {
	return &InstallConfig{
		Version:        DefaultVersion,
		BinaryPath:     BinaryPath,
		ConfigDir:      ConfigDir,
		TemplateDir:    TemplateDir,
		DataDir:        DataDir,
		LogDir:         LogDir,
		SystemUser:     SystemUser,
		SystemGroup:    SystemGroup,
		ConsulAddr:     DefaultConsulAddr,
		VaultAddr:      DefaultVaultAddr,
		VaultTokenPath: DefaultVaultTokenPath,
		SkipVerify:     false,
		ForceReinstall: false,
	}
}

// Installer manages Consul Template installation
type Installer struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewInstaller creates a new Consul Template installer
func NewInstaller(rc *eos_io.RuntimeContext) *Installer {
	return &Installer{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// Install installs Consul Template following the Assess → Intervene → Evaluate pattern
func (i *Installer) Install(config *InstallConfig) error {
	i.logger.Info("Starting Consul Template installation",
		zap.String("version", config.Version))

	// ASSESS - Check current state
	if err := i.assess(config); err != nil {
		return fmt.Errorf("pre-installation assessment failed: %w", err)
	}

	// INTERVENE - Perform installation
	if err := i.intervene(config); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	// EVALUATE - Verify installation
	if err := i.evaluate(config); err != nil {
		return fmt.Errorf("post-installation verification failed: %w", err)
	}

	i.logger.Info("Consul Template installation completed successfully",
		zap.String("version", config.Version),
		zap.String("binary", config.BinaryPath))

	return nil
}

// assess checks if installation is needed and validates prerequisites
func (i *Installer) assess(config *InstallConfig) error {
	i.logger.Info("Assessing system for Consul Template installation")

	// Check if already installed
	if _, err := os.Stat(config.BinaryPath); err == nil {
		version, err := i.getInstalledVersion(config.BinaryPath)
		if err == nil {
			i.logger.Info("Consul Template already installed",
				zap.String("version", version),
				zap.String("path", config.BinaryPath))

			if !config.ForceReinstall {
				if version == config.Version {
					i.logger.Info("Requested version already installed, skipping")
					return fmt.Errorf("consul-template %s already installed at %s (use ForceReinstall to override)",
						version, config.BinaryPath)
				}
				i.logger.Info("Different version requested, will upgrade/downgrade",
					zap.String("current", version),
					zap.String("requested", config.Version))
			}
		}
	}

	// Validate we're running as root (needed for system user creation)
	if os.Geteuid() != 0 {
		return fmt.Errorf("consul-template installation requires root privileges (current UID: %d)", os.Geteuid())
	}

	// Check required directories exist (parent directories)
	if err := i.checkParentDirectories(config); err != nil {
		return fmt.Errorf("parent directory check failed: %w", err)
	}

	i.logger.Info("Pre-installation assessment passed")
	return nil
}

// intervene performs the actual installation steps
func (i *Installer) intervene(config *InstallConfig) error {
	i.logger.Info("Performing Consul Template installation")

	// Step 1: Create system user and group
	if err := i.createSystemUser(config); err != nil {
		return fmt.Errorf("failed to create system user: %w", err)
	}

	// Step 2: Create directories
	if err := i.createDirectories(config); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Step 3: Download and install binary
	if err := i.downloadAndInstallBinary(config); err != nil {
		return fmt.Errorf("failed to download/install binary: %w", err)
	}

	// Step 4: Set ownership and permissions
	if err := i.setPermissions(config); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	i.logger.Info("Installation steps completed successfully")
	return nil
}

// evaluate verifies the installation was successful
func (i *Installer) evaluate(config *InstallConfig) error {
	i.logger.Info("Verifying Consul Template installation")

	// Check binary exists and is executable
	if _, err := os.Stat(config.BinaryPath); err != nil {
		return fmt.Errorf("binary not found at %s: %w", config.BinaryPath, err)
	}

	// Check binary is executable
	fileInfo, err := os.Stat(config.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to stat binary: %w", err)
	}
	if fileInfo.Mode()&0111 == 0 {
		return fmt.Errorf("binary is not executable: %s", config.BinaryPath)
	}

	// Verify version
	installedVersion, err := i.getInstalledVersion(config.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to get installed version: %w", err)
	}

	if !strings.Contains(installedVersion, config.Version) {
		return fmt.Errorf("version mismatch: expected %s, got %s", config.Version, installedVersion)
	}

	// Check directories exist
	requiredDirs := []string{
		config.ConfigDir,
		config.TemplateDir,
		config.DataDir,
	}
	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("required directory missing: %s: %w", dir, err)
		}
	}

	// Check system user exists
	if _, err := user.Lookup(config.SystemUser); err != nil {
		return fmt.Errorf("system user not found: %s: %w", config.SystemUser, err)
	}

	i.logger.Info("Installation verification passed",
		zap.String("version", installedVersion),
		zap.String("binary", config.BinaryPath))

	return nil
}

// createSystemUser creates the system user and group for consul-template
func (i *Installer) createSystemUser(config *InstallConfig) error {
	i.logger.Info("Creating system user and group",
		zap.String("user", config.SystemUser),
		zap.String("group", config.SystemGroup))

	// Check if user already exists
	if _, err := user.Lookup(config.SystemUser); err == nil {
		i.logger.Info("System user already exists",
			zap.String("user", config.SystemUser))
		return nil
	}

	// Create group first
	groupaddOutput, err := execute.Run(i.rc.Ctx, execute.Options{
		Command: "groupadd",
		Args:    []string{"--system", config.SystemGroup},
		Capture: true,
	})
	if err != nil && !strings.Contains(groupaddOutput, "already exists") {
		return fmt.Errorf("failed to create system group: %s: %w", groupaddOutput, err)
	}

	// Create user
	useraddOutput, err := execute.Run(i.rc.Ctx, execute.Options{
		Command: "useradd",
		Args: []string{
			"--system",
			"--no-create-home",
			"--shell", "/bin/false",
			"--gid", config.SystemGroup,
			"--comment", "Consul Template service account",
			config.SystemUser,
		},
		Capture: true,
	})
	if err != nil && !strings.Contains(useraddOutput, "already exists") {
		return fmt.Errorf("failed to create system user: %s: %w", useraddOutput, err)
	}

	i.logger.Info("System user created successfully",
		zap.String("user", config.SystemUser))

	return nil
}

// createDirectories creates all required directories
func (i *Installer) createDirectories(config *InstallConfig) error {
	i.logger.Info("Creating required directories")

	directories := []struct {
		path string
		perm os.FileMode
	}{
		{config.ConfigDir, ConfigDirPerm},
		{config.TemplateDir, TemplateDirPerm},
		{config.DataDir, DataDirPerm},
		{config.LogDir, ConfigDirPerm}, // Logs use same perm as config
	}

	for _, dir := range directories {
		i.logger.Debug("Creating directory",
			zap.String("path", dir.path),
			zap.String("perm", fmt.Sprintf("%o", dir.perm)))

		if err := os.MkdirAll(dir.path, dir.perm); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir.path, err)
		}
	}

	i.logger.Info("Directories created successfully")
	return nil
}

// downloadAndInstallBinary downloads and installs the consul-template binary
func (i *Installer) downloadAndInstallBinary(config *InstallConfig) error {
	i.logger.Info("Downloading Consul Template binary",
		zap.String("version", config.Version))

	// Determine OS and architecture
	osName := runtime.GOOS
	archName := runtime.GOARCH

	// Map Go arch to HashiCorp naming
	switch archName {
	case "amd64", "arm64":
		// Already correct
	default:
		return fmt.Errorf("unsupported architecture: %s", archName)
	}

	// Build download URL
	downloadURL := strings.ReplaceAll(DownloadURLTemplate, "{version}", config.Version)
	downloadURL = strings.ReplaceAll(downloadURL, "{os}", osName)
	downloadURL = strings.ReplaceAll(downloadURL, "{arch}", archName)

	i.logger.Info("Download URL constructed",
		zap.String("url", downloadURL))

	// Download to temporary directory
	tmpDir, err := os.MkdirTemp("", "consul-template-install-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	zipFile := filepath.Join(tmpDir, "consul-template.zip")

	// Download binary
	if err := i.downloadFile(downloadURL, zipFile); err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}

	// Extract binary
	if err := i.extractBinary(zipFile, config.BinaryPath); err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}

	i.logger.Info("Binary downloaded and installed successfully",
		zap.String("path", config.BinaryPath))

	return nil
}

// extractBinary extracts the consul-template binary from the zip file
func (i *Installer) extractBinary(zipPath, destPath string) error {
	i.logger.Debug("Extracting binary",
		zap.String("zip", zipPath),
		zap.String("dest", destPath))

	// Use unzip command
	extractDir := filepath.Dir(zipPath)
	output, err := execute.Run(i.rc.Ctx, execute.Options{
		Command: "unzip",
		Args:    []string{"-o", zipPath, "-d", extractDir},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to unzip: %s: %w", output, err)
	}

	// Move binary to destination
	extractedBinary := filepath.Join(extractDir, "consul-template")
	output, err = execute.Run(i.rc.Ctx, execute.Options{
		Command: "mv",
		Args:    []string{extractedBinary, destPath},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to move binary: %s: %w", output, err)
	}

	// Make executable
	if err := os.Chmod(destPath, shared.ExecutablePerm); err != nil {
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	return nil
}

// setPermissions sets ownership and permissions on all directories and files
func (i *Installer) setPermissions(config *InstallConfig) error {
	i.logger.Info("Setting ownership and permissions")

	// Lookup user/group IDs
	u, err := user.Lookup(config.SystemUser)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", config.SystemUser, err)
	}

	// Set ownership on directories
	directories := []string{
		config.ConfigDir,
		config.TemplateDir,
		config.DataDir,
		config.LogDir,
	}

	for _, dir := range directories {
		output, err := execute.Run(i.rc.Ctx, execute.Options{
			Command: "chown",
			Args:    []string{"-R", fmt.Sprintf("%s:%s", u.Uid, u.Gid), dir},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("failed to chown %s: %s: %w", dir, output, err)
		}
	}

	i.logger.Info("Permissions set successfully")
	return nil
}

// checkParentDirectories validates that parent directories exist
func (i *Installer) checkParentDirectories(config *InstallConfig) error {
	parentDirs := []string{
		filepath.Dir(config.BinaryPath), // /usr/local/bin
		filepath.Dir(config.ConfigDir),  // /etc
		filepath.Dir(config.DataDir),    // /opt
		filepath.Dir(config.LogDir),     // /var/log
	}

	for _, dir := range parentDirs {
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("parent directory does not exist: %s: %w", dir, err)
		}
	}

	return nil
}

// getInstalledVersion returns the installed version of consul-template
func (i *Installer) getInstalledVersion(binaryPath string) (string, error) {
	output, err := execute.Run(i.rc.Ctx, execute.Options{
		Command: binaryPath,
		Args:    []string{"-version"},
		Capture: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get version: %w", err)
	}

	// Parse version from output
	// Example: "consul-template v0.37.4 (1234abcd)"
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0]), nil
	}

	return output, nil
}

// Uninstall removes Consul Template from the system
func (i *Installer) Uninstall(config *InstallConfig) error {
	i.logger.Info("Uninstalling Consul Template")

	// Stop all consul-template services first
	i.logger.Info("Stopping consul-template services")
	output, err := execute.Run(i.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", "consul-template-*.service"},
		Capture: true,
	})
	if err != nil {
		i.logger.Warn("Failed to stop services (may not exist)",
			zap.Error(err),
			zap.String("output", output))
	}

	// Remove binary
	if err := os.Remove(config.BinaryPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove binary: %w", err)
	}

	// Remove directories
	directories := []string{
		config.ConfigDir,
		config.DataDir,
		config.LogDir,
	}
	for _, dir := range directories {
		if err := os.RemoveAll(dir); err != nil {
			i.logger.Warn("Failed to remove directory",
				zap.String("dir", dir),
				zap.Error(err))
		}
	}

	// Remove system user
	output, err = execute.Run(i.rc.Ctx, execute.Options{
		Command: "userdel",
		Args:    []string{config.SystemUser},
		Capture: true,
	})
	if err != nil {
		i.logger.Warn("Failed to remove system user",
			zap.String("user", config.SystemUser),
			zap.String("output", output),
			zap.Error(err))
	}

	// Remove system group
	output, err = execute.Run(i.rc.Ctx, execute.Options{
		Command: "groupdel",
		Args:    []string{config.SystemGroup},
		Capture: true,
	})
	if err != nil {
		i.logger.Warn("Failed to remove system group",
			zap.String("group", config.SystemGroup),
			zap.String("output", output),
			zap.Error(err))
	}

	i.logger.Info("Consul Template uninstalled successfully")
	return nil
}

// downloadFile downloads a file from URL to destination
func (i *Installer) downloadFile(url, dest string) error {
	i.logger.Debug("Downloading file",
		zap.String("url", url),
		zap.String("dest", dest))

	output, err := execute.Run(i.rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-sL", "-o", dest, url},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to download %s: %s: %w", url, output, err)
	}

	return nil
}
