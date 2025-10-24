// Package install provides Consul installation utilities
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Binary installs the Consul binary from HashiCorp releases.
// It follows the Assess → Intervene → Evaluate pattern.
// DEPRECATED: This function is deprecated in favor of -based installation.
// Use 'eos create consul' command instead which uses  orchestration.
func Binary(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if Consul is already installed
	if err := execute.RunSimple(rc.Ctx, "which", "consul"); err == nil {
		log.Info("Consul binary already installed, checking version")
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "consul",
			Args:    []string{"version"},
			Capture: true,
		})
		if err == nil {
			log.Info("Current Consul version", zap.String("version", strings.TrimSpace(output)))
			return nil
		}
	}

	log.Info("Installing Consul binary")

	// INTERVENE - Download and install
	// Detect architecture
	arch := eos_unix.GetArchitecture()
	consulVersion := "1.17.1"

	log.Info("Downloading Consul",
		zap.String("version", consulVersion),
		zap.String("architecture", arch))

	steps := []execute.Options{
		{
			Command: "wget",
			Args: []string{
				"-O", "/tmp/consul.zip",
				fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_%s.zip",
					consulVersion, consulVersion, arch),
			},
		},
		{Command: "unzip", Args: []string{"-o", "/tmp/consul.zip", "-d", "/tmp/"}},
		{Command: "chmod", Args: []string{"+x", "/tmp/consul"}},
		{Command: "mv", Args: []string{"/tmp/consul", consul.ConsulBinaryPath}},
		{Command: "rm", Args: []string{"-f", "/tmp/consul.zip"}},
	}

	for i, step := range steps {
		log.Debug("Executing installation step",
			zap.Int("step", i+1),
			zap.String("command", step.Command))

		if _, err := execute.Run(rc.Ctx, step); err != nil {
			return fmt.Errorf("installation step %d failed: %w", i+1, err)
		}
	}

	// EVALUATE - Verify installation
	if err := execute.RunSimple(rc.Ctx, "consul", "version"); err != nil {
		return fmt.Errorf("consul verification failed: %w", err)
	}

	log.Info("Consul binary installed successfully")
	return nil
}

// Install downloads and installs Consul binary directly from HashiCorp releases
func (bi *BinaryInstaller) Install(version string) error {
	bi.logger.Info("Installing Consul via direct binary download",
		zap.String("version", version))

	// Determine architecture
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	default:
		return fmt.Errorf("unsupported architecture: %s", arch)
	}

	// Construct download URL
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_%s.zip",
		version, version, arch)

	bi.logger.Info("Downloading Consul binary",
		zap.String("version", version),
		zap.String("arch", arch),
		zap.String("url", downloadURL))

	// Create temporary directory
	tmpDir := "/tmp/consul-install"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Download binary
	zipPath := filepath.Join(tmpDir, "consul.zip")
	if err := bi.downloadFile(downloadURL, zipPath); err != nil {
		return fmt.Errorf("failed to download Consul: %w", err)
	}

	// Extract binary
	if err := bi.extractZip(zipPath, tmpDir); err != nil {
		return fmt.Errorf("failed to extract Consul: %w", err)
	}

	// Install binary
	binaryPath := filepath.Join(tmpDir, "consul")
	if err := bi.installBinary(binaryPath); err != nil {
		return fmt.Errorf("failed to install binary: %w", err)
	}

	bi.logger.Info("Consul binary installed successfully",
		zap.String("path", bi.binaryPath),
		zap.String("version", version))

	return nil
}

// downloadFile downloads a file using wget with timeout
func (bi *BinaryInstaller) downloadFile(url, dest string) error {
	ctx, cancel := context.WithTimeout(bi.rc.Ctx, 5*time.Minute)
	defer cancel()

	bi.logger.Info("Downloading file with wget",
		zap.String("url", url),
		zap.String("dest", dest))

	cmd := exec.CommandContext(ctx, "wget", "-O", dest, url)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wget failed for %s: %w", url, err)
	}

	return nil
}

// extractZip extracts a zip file to destination directory
func (bi *BinaryInstaller) extractZip(zipPath, destDir string) error {
	bi.logger.Info("Extracting zip file",
		zap.String("zip", zipPath),
		zap.String("dest", destDir))

	cmd := exec.Command("unzip", "-o", zipPath, "-d", destDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unzip failed: %w", err)
	}

	return nil
}

// installBinary installs the binary to the target location
func (bi *BinaryInstaller) installBinary(sourcePath string) error {
	bi.logger.Info("Installing binary",
		zap.String("source", sourcePath),
		zap.String("target", bi.binaryPath))

	cmd := exec.Command("install", "-m", "755", sourcePath, bi.binaryPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install command failed: %w", err)
	}

	return nil
}

// GetBinaryPath returns the configured binary path
func (bi *BinaryInstaller) GetBinaryPath() string {
	return bi.binaryPath
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

	// Add HashiCorp GPG key using proper shell pipeline
	ci.logger.Info("Adding HashiCorp GPG key")
	cmd := exec.Command("sh", "-c", "wget -qO- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add HashiCorp GPG key: %s\n%w", string(output), err)
	}

	// Add HashiCorp repository
	codename, err := getUbuntuCodename()
	if err != nil {
		return fmt.Errorf("failed to detect Ubuntu codename: %w", err)
	}

	repoLine := fmt.Sprintf("deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com %s main", codename)
	if err := ci.writeFile("/etc/apt/sources.list.d/hashicorp.list", []byte(repoLine), 0644); err != nil {
		return fmt.Errorf("failed to add HashiCorp repository: %w", err)
	}

	// Update package list
	ci.logger.Info("Updating package list")
	if err := ci.runner.Run("apt-get", "update"); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}

	// Install Consul
	ci.logger.Info("Installing Consul package")
	if ci.config.Version != "latest" {
		if err := ci.runner.Run("apt-get", "install", "-y", fmt.Sprintf("consul=%s", ci.config.Version)); err != nil {
			return fmt.Errorf("failed to install Consul: %w", err)
		}
	} else {
		if err := ci.runner.Run("apt-get", "install", "-y", "consul"); err != nil {
			return fmt.Errorf("failed to install Consul: %w", err)
		}
	}

	ci.logger.Info("Consul installed successfully via APT")

	// CRITICAL: Re-detect binary path after APT installation
	// APT installs to /usr/bin/consul, but constructor may have set /usr/local/bin/consul
	// This ensures validation uses the correct path
	oldPath := ci.config.BinaryPath
	ci.config.BinaryPath = consul.GetConsulBinaryPath()

	if oldPath != ci.config.BinaryPath {
		ci.logger.Info("Binary path updated after APT installation",
			zap.String("old_path", oldPath),
			zap.String("new_path", ci.config.BinaryPath))
	} else {
		ci.logger.Info("Binary path confirmed after APT installation",
			zap.String("binary_path", ci.config.BinaryPath))
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
			return fmt.Errorf("failed to get latest version: %w", err)
		}
		ci.logger.Info("Resolved latest version", zap.String("version", version))
	}

	// Construct download URL
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	}

	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_%s.zip", version, version, arch)
	zipPath := "/tmp/consul.zip"

	// Download binary
	ci.logger.Info("Downloading Consul binary",
		zap.String("url", downloadURL),
		zap.String("version", version))

	if err := ci.downloadFileWithWget(downloadURL, zipPath); err != nil {
		return fmt.Errorf("failed to download Consul: %w", err)
	}

	// Extract binary
	ci.logger.Info("Extracting Consul binary")
	if err := ci.runner.Run("unzip", "-o", zipPath, "-d", "/usr/local/bin"); err != nil {
		return fmt.Errorf("failed to extract Consul: %w", err)
	}

	// Set permissions
	if err := os.Chmod(consul.ConsulBinaryPath, 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Clean up
	_ = os.Remove(zipPath)

	ci.logger.Info("Consul binary installed successfully",
		zap.String("path", consul.ConsulBinaryPath),
		zap.String("version", version))

	return nil
}

// getLatestVersion fetches the latest Consul version from HashiCorp
func (ci *ConsulInstaller) getLatestVersion() (string, error) {
	// Query HashiCorp checkpoint API
	resp, err := ci.httpGet("https://checkpoint-api.hashicorp.com/v1/check/consul")
	if err != nil {
		return "", fmt.Errorf("failed to query version API: %w", err)
	}

	var result struct {
		CurrentVersion string `json:"current_version"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("failed to parse version response: %w", err)
	}

	return result.CurrentVersion, nil
}

// downloadFileWithWget downloads a file using wget with proper error handling
func (ci *ConsulInstaller) downloadFileWithWget(url, dest string) error {
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "wget", "-O", dest, url)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wget failed: %w", err)
	}

	return nil
}

// cleanExistingInstallation removes existing Consul installation with backup
func (ci *ConsulInstaller) cleanExistingInstallation() error {
	ci.logger.Info("Cleaning existing Consul installation")

	// CRITICAL: Backup data before deletion to prevent data loss
	backupDir := fmt.Sprintf("/var/lib/consul-backup-%d", time.Now().Unix())
	if ci.fileExists("/var/lib/consul") {
		ci.logger.Info("Backing up existing data", zap.String("backup_dir", backupDir))
		if err := ci.runner.Run("cp", "-r", "/var/lib/consul", backupDir); err != nil {
			ci.logger.Warn("Failed to backup data", zap.Error(err))
		}
	}

	// Stop service
	if ci.systemd.IsActive() {
		ci.logger.Info("Stopping Consul service")
		if err := ci.systemd.Stop(); err != nil {
			ci.logger.Warn("Failed to stop service", zap.Error(err))
		}
	}

	// Remove data directories
	dirsToRemove := []string{
		"/var/lib/consul",
		"/etc/consul.d",
		"/var/log/consul",
	}

	for _, dir := range dirsToRemove {
		if ci.fileExists(dir) {
			ci.logger.Info("Removing directory", zap.String("path", dir))
			if err := os.RemoveAll(dir); err != nil {
				ci.logger.Warn("Failed to remove directory",
					zap.String("path", dir),
					zap.Error(err))
			}
		}
	}

	// Remove binary if installed via direct download
	binaryPath := consul.ConsulBinaryPath
	if ci.fileExists(binaryPath) {
		ci.logger.Info("Removing binary", zap.String("path", binaryPath))
		if err := os.Remove(binaryPath); err != nil {
			ci.logger.Warn("Failed to remove binary", zap.Error(err))
		}
	}

	ci.logger.Info("Clean installation completed",
		zap.String("backup_location", backupDir))

	return nil
}

// BinaryInstaller handles direct binary download and installation
type BinaryInstaller struct {
	rc         *eos_io.RuntimeContext
	logger     otelzap.LoggerWithCtx
	binaryPath string
}

// NewBinaryInstaller creates a new binary installer instance
func NewBinaryInstaller(rc *eos_io.RuntimeContext, binaryPath string) *BinaryInstaller {
	if binaryPath == "" {
		binaryPath = consul.GetConsulBinaryPath()
	}

	return &BinaryInstaller{
		rc:         rc,
		logger:     otelzap.Ctx(rc.Ctx),
		binaryPath: binaryPath,
	}
}

// getUbuntuCodename returns the Ubuntu codename for APT repository
func getUbuntuCodename() (string, error) {
	cmd := exec.Command("lsb_release", "-cs")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to detect Ubuntu codename: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

