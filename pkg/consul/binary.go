// pkg/consul/binary.go
// Binary installation methods for Consul

package consul

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
)

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
	if err := ci.runner.Run("wget", "-O-", "https://apt.releases.hashicorp.com/gpg", "|", "gpg", "--dearmor", "-o", "/usr/share/keyrings/hashicorp-archive-keyring.gpg"); err != nil {
		return fmt.Errorf("failed to add HashiCorp GPG key: %w", err)
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
	if arch == "amd64" {
		arch = "amd64"
	} else if arch == "arm64" {
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
	if err := os.Chmod("/usr/local/bin/consul", 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Clean up
	os.Remove(zipPath)

	ci.logger.Info("Consul binary installed successfully",
		zap.String("path", "/usr/local/bin/consul"),
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

// getUbuntuCodename returns the Ubuntu codename for APT repository
func getUbuntuCodename() (string, error) {
	cmd := exec.Command("lsb_release", "-cs")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to detect Ubuntu codename: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// getConsulBinaryPath returns the path to the Consul binary
func getConsulBinaryPath() string {
	// Check common locations
	paths := []string{
		"/usr/bin/consul",
		"/usr/local/bin/consul",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Fallback to PATH lookup
	if path, err := exec.LookPath("consul"); err == nil {
		return path
	}

	return "/usr/bin/consul" // Default
}

// getBinaryVersion returns the version of the installed Consul binary
func (ci *ConsulInstaller) getBinaryVersion(binaryPath string) (string, error) {
	cmd := exec.Command(binaryPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse version from output (e.g., "Consul v1.17.1")
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			return strings.TrimPrefix(parts[1], "v"), nil
		}
	}

	return "", fmt.Errorf("could not parse version from output")
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
	binaryPath := "/usr/local/bin/consul"
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
