package hashicorp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Product represents a HashiCorp product
type Product string

const (
	ProductConsul    Product = "consul"
	ProductVault     Product = "vault"
	ProductNomad     Product = "nomad"
	ProductTerraform Product = "terraform"
	ProductPacker    Product = "packer"
	ProductBoundary  Product = "boundary"
	ProductWaypoint  Product = "waypoint"
	ProductVagrant   Product = "vagrant"
)

// InstallMethod represents how to install the product
type InstallMethod string

const (
	MethodBinary     InstallMethod = "binary"     // Direct binary download
	MethodRepository InstallMethod = "repository" // APT/YUM repository
	MethodDocker     InstallMethod = "docker"     // Docker container
)

// BaseInstaller provides common functionality for all HashiCorp product installers
type BaseInstaller struct {
	rc       *eos_io.RuntimeContext
	product  Product
	runner   *CommandRunner
	systemd  *SystemdManager
	dirMgr   *DirectoryManager
	fileMgr  *FileManager
	userMgr  *UserManager
	progress *ProgressReporter
	network  *NetworkHelper
}

// InstallConfig contains common configuration for HashiCorp product installation
type InstallConfig struct {
	Product         Product
	Version         string
	InstallMethod   InstallMethod
	BinaryPath      string
	ConfigPath      string
	DataPath        string
	LogPath         string
	ServiceName     string
	ServiceUser     string
	ServiceGroup    string
	Port            int
	TLSEnabled      bool
	CleanInstall    bool
	ForceReinstall  bool
	SkipVerify      bool
	CustomBinaryURL string // For custom/enterprise binaries
}

// ProductStatus represents the current status of a HashiCorp product
type ProductStatus struct {
	Installed     bool
	Running       bool
	Version       string
	ConfigValid   bool
	ServiceStatus string
	BinaryPath    string
	ConfigPath    string
	DataPath      string
	LastError     string
}

// NewBaseInstaller creates a new base installer for HashiCorp products
func NewBaseInstaller(rc *eos_io.RuntimeContext, product Product) *BaseInstaller {
	runner := NewCommandRunner(rc)

	return &BaseInstaller{
		rc:      rc,
		product: product,
		runner:  runner,
		systemd: NewSystemdManager(runner),
		dirMgr:  NewDirectoryManager(runner),
		fileMgr: NewFileManager(runner),
		userMgr: NewUserManager(runner),
		network: NewNetworkHelper(otelzap.Ctx(rc.Ctx)),
	}
}

// CheckStatus checks the current status of the product
func (b *BaseInstaller) CheckStatus(config *InstallConfig) (*ProductStatus, error) {
	logger := otelzap.Ctx(b.rc.Ctx)
	status := &ProductStatus{
		BinaryPath: config.BinaryPath,
		ConfigPath: config.ConfigPath,
		DataPath:   config.DataPath,
	}

	// Check if binary exists
	if _, err := os.Stat(config.BinaryPath); err == nil {
		status.Installed = true

		// Get version
		if output, err := b.runner.RunOutput(config.BinaryPath, "version"); err == nil {
			// Parse version from output (format varies by product)
			status.Version = b.parseVersion(output)
		}
	}

	// Check service status
	if b.systemd.IsServiceActive(config.ServiceName) {
		status.Running = true
		status.ServiceStatus = "active"
	} else if b.systemd.IsServiceFailed(config.ServiceName) {
		status.ServiceStatus = "failed"
	}

	// Validate configuration if exists
	if _, err := os.Stat(config.ConfigPath); err == nil {
		status.ConfigValid = b.validateConfig(config)
	}

	logger.Debug("Product status check completed",
		zap.String("product", string(b.product)),
		zap.Bool("installed", status.Installed),
		zap.Bool("running", status.Running),
		zap.String("version", status.Version))

	return status, nil
}

// PreInstallValidation performs common pre-installation checks
func (b *BaseInstaller) PreInstallValidation(config *InstallConfig) error {
	validator := NewValidator(otelzap.Ctx(b.rc.Ctx))

	// Check permissions
	validator.RequireRoot()

	// Check port availability
	if config.Port > 0 {
		validator.CheckPort(config.Port)
	}

	// Check disk space (minimum 500MB)
	validator.CheckDiskSpace(filepath.Dir(config.BinaryPath), 500)

	// Check required commands
	validator.RequireCommand("unzip")
	validator.RequireCommand("systemctl")

	if validator.HasErrors() {
		return validator.GetError()
	}

	return nil
}

// CleanExistingInstallation removes existing installation
func (b *BaseInstaller) CleanExistingInstallation(config *InstallConfig) error {
	logger := otelzap.Ctx(b.rc.Ctx)
	logger.Info("Cleaning existing installation",
		zap.String("product", string(b.product)))

	// Stop and disable service
	b.systemd.StopService(config.ServiceName)
	b.systemd.DisableService(config.ServiceName)

	// Kill any remaining processes
	b.runner.RunQuiet("pkill", "-f", string(b.product))

	// Remove directories
	dirs := []string{
		config.ConfigPath,
		config.DataPath,
		config.LogPath,
	}

	for _, dir := range dirs {
		if err := b.dirMgr.RemoveIfExists(dir); err != nil {
			logger.Warn("Failed to remove directory",
				zap.String("dir", dir),
				zap.Error(err))
		}
	}

	// Remove binary
	if err := os.Remove(config.BinaryPath); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove binary",
			zap.String("path", config.BinaryPath),
			zap.Error(err))
	}

	// Remove systemd service file
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", config.ServiceName)
	os.Remove(servicePath)

	// Reload systemd
	b.systemd.ReloadDaemon()

	return nil
}

// InstallBinary downloads and installs the HashiCorp binary
func (b *BaseInstaller) InstallBinary(config *InstallConfig) error {
	logger := otelzap.Ctx(b.rc.Ctx)

	// Resolve version if "latest"
	version := config.Version
	if version == "latest" || version == "" {
		resolvedVersion, err := b.resolveLatestVersion()
		if err != nil {
			logger.Warn("Failed to resolve latest version, using fallback",
				zap.Error(err))
			version = b.getFallbackVersion()
		} else {
			version = resolvedVersion
		}
	}

	logger.Info("Installing HashiCorp product binary",
		zap.String("product", string(b.product)),
		zap.String("version", version))

	// Determine download URL
	downloadURL := config.CustomBinaryURL
	if downloadURL == "" {
		downloadURL = b.getDownloadURL(version)
	}

	// Download binary
	tempDir := "/tmp"
	zipPath := filepath.Join(tempDir, fmt.Sprintf("%s_%s.zip", b.product, version))

	logger.Info("Downloading binary", zap.String("url", downloadURL))
	if err := b.network.DownloadFile(downloadURL, zipPath); err != nil {
		return fmt.Errorf("failed to download %s: %w", b.product, err)
	}
	defer os.Remove(zipPath)

	// Verify checksum
	if !config.SkipVerify {
		logger.Info("Verifying checksum")
		if err := b.verifyChecksum(zipPath, version); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
	}

	// Extract binary
	logger.Info("Extracting binary")
	extractDir := filepath.Dir(config.BinaryPath)
	if err := b.runner.Run("unzip", "-o", zipPath, "-d", extractDir); err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}

	// Set permissions
	if err := os.Chmod(config.BinaryPath, 0755); err != nil {
		return fmt.Errorf("failed to set binary permissions: %w", err)
	}

	// Create symlink for compatibility
	symlink := fmt.Sprintf("/usr/bin/%s", b.product)
	os.Remove(symlink) // Remove if exists
	if err := os.Symlink(config.BinaryPath, symlink); err != nil {
		logger.Warn("Failed to create symlink", zap.Error(err))
	}

	return nil
}

// InstallViaRepository installs using the HashiCorp APT repository
func (b *BaseInstaller) InstallViaRepository(config *InstallConfig) error {
	logger := otelzap.Ctx(b.rc.Ctx)
	logger.Info("Installing via HashiCorp APT repository",
		zap.String("product", string(b.product)))

	// Add HashiCorp GPG key
	logger.Info("Adding HashiCorp GPG key")
	gpgCmd := `wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg`
	if err := b.runner.RunWithRetries("bash", []string{"-c", gpgCmd}, 3); err != nil {
		return fmt.Errorf("failed to add GPG key: %w", err)
	}

	// Add repository
	logger.Info("Adding HashiCorp repository")
	repoCmd := `echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list`
	if err := b.runner.Run("bash", "-c", repoCmd); err != nil {
		return fmt.Errorf("failed to add repository: %w", err)
	}

	// Update package list
	logger.Info("Updating package list")
	if err := b.runner.RunWithRetries("apt-get", []string{"update"}, 3); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}

	// Install package
	logger.Info("Installing package")
	installArgs := []string{"install", "-y"}
	if config.Version != "" && config.Version != "latest" {
		installArgs = append(installArgs, fmt.Sprintf("%s=%s", b.product, config.Version))
	} else {
		installArgs = append(installArgs, string(b.product))
	}

	if err := b.runner.RunWithRetries("apt-get", installArgs, 3); err != nil {
		return fmt.Errorf("failed to install %s: %w", b.product, err)
	}

	return nil
}

// CreateUser creates the system user for the service
func (b *BaseInstaller) CreateUser(config *InstallConfig) error {
	return b.userMgr.CreateSystemUser(config.ServiceUser, config.DataPath)
}

// SetupDirectories creates and configures required directories
func (b *BaseInstaller) SetupDirectories(config *InstallConfig) error {
	logger := otelzap.Ctx(b.rc.Ctx)
	logger.Info("Setting up directories")

	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{config.ConfigPath, 0750},
		{config.DataPath, 0750},
		{config.LogPath, 0750},
	}

	for _, dir := range dirs {
		if err := b.dirMgr.CreateWithOwnership(
			dir.path,
			config.ServiceUser,
			config.ServiceGroup,
			dir.mode,
		); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir.path, err)
		}
	}

	return nil
}

// Helper methods

func (b *BaseInstaller) parseVersion(output string) string {
	// Most HashiCorp tools output version in first line
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		// Extract version number from output like "Consul v1.17.0"
		parts := strings.Fields(lines[0])
		for _, part := range parts {
			if strings.HasPrefix(part, "v") {
				return strings.TrimPrefix(part, "v")
			}
			// Check if it looks like a version number
			if strings.Contains(part, ".") && !strings.Contains(part, "/") {
				return part
			}
		}
	}
	return "unknown"
}

func (b *BaseInstaller) validateConfig(config *InstallConfig) bool {
	// Product-specific validation can be implemented by each product
	// This is a basic check
	if _, err := os.Stat(config.ConfigPath); err != nil {
		return false
	}
	return true
}

func (b *BaseInstaller) resolveLatestVersion() (string, error) {
	ctx, cancel := context.WithTimeout(b.rc.Ctx, 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.github.com/repos/hashicorp/%s/releases/latest", b.product)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Eos-HashiCorp-Installer/1.0")

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

	return strings.TrimPrefix(release.TagName, "v"), nil
}

func (b *BaseInstaller) getFallbackVersion() string {
	// Fallback versions for each product (as of 2024)
	fallbacks := map[Product]string{
		ProductConsul:    "1.17.1",
		ProductVault:     "1.15.4",
		ProductNomad:     "1.7.2",
		ProductTerraform: "1.6.6",
		ProductPacker:    "1.10.0",
		ProductBoundary:  "0.15.0",
		ProductWaypoint:  "0.11.4",
		ProductVagrant:   "2.4.0",
	}

	if version, ok := fallbacks[b.product]; ok {
		return version
	}
	return "1.0.0"
}

func (b *BaseInstaller) getDownloadURL(version string) string {
	arch := runtime.GOARCH
	if arch == "x86_64" {
		arch = "amd64"
	}

	return fmt.Sprintf(
		"https://releases.hashicorp.com/%s/%s/%s_%s_linux_%s.zip",
		b.product, version, b.product, version, arch,
	)
}

func (b *BaseInstaller) verifyChecksum(filepath, version string) error {
	// Download checksum file
	checksumURL := fmt.Sprintf(
		"https://releases.hashicorp.com/%s/%s/%s_%s_SHA256SUMS",
		b.product, version, b.product, version,
	)

	checksumPath := "/tmp/checksums.txt"
	if err := b.network.DownloadFile(checksumURL, checksumPath); err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}
	defer os.Remove(checksumPath)

	// Read checksum file
	checksumData, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}

	// Find the checksum for our file
	arch := runtime.GOARCH
	if arch == "x86_64" {
		arch = "amd64"
	}
	targetFile := fmt.Sprintf("%s_%s_linux_%s.zip", b.product, version, arch)

	var expectedChecksum string
	lines := strings.Split(string(checksumData), "\n")
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
		return fmt.Errorf("checksum mismatch: expected %s, got %s",
			expectedChecksum, actualChecksum)
	}

	return nil
}

// SetProgress sets the progress reporter for user feedback
func (b *BaseInstaller) SetProgress(reporter *ProgressReporter) {
	b.progress = reporter
}

// GetRunner returns the command runner for custom operations
func (b *BaseInstaller) GetRunner() *CommandRunner {
	return b.runner
}

// GetSystemd returns the systemd manager for service operations
func (b *BaseInstaller) GetSystemd() *SystemdManager {
	return b.systemd
}

// GetFileManager returns the file manager for file operations
func (b *BaseInstaller) GetFileManager() *FileManager {
	return b.fileMgr
}
