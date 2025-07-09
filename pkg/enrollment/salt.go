// pkg/enrollment/salt.go
package enrollment

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureSalt configures Salt based on the enrollment configuration
func ConfigureSalt(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Configuring Salt",
		zap.String("role", config.Role),
		zap.String("master_address", config.MasterAddress))
	
	// Ensure Salt is installed
	if err := ensureSaltInstalled(rc, config.Role); err != nil {
		return fmt.Errorf("failed to install Salt: %w", err)
	}
	
	// Configure based on role
	switch config.Role {
	case RoleMaster:
		return configureSaltMaster(rc, config)
	case RoleMinion:
		return configureSaltMinion(rc, config)
	default:
		return fmt.Errorf("unsupported Salt role: %s", config.Role)
	}
}

// ensureSaltInstalled ensures Salt is installed with the required components
func ensureSaltInstalled(rc *eos_io.RuntimeContext, role string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would install Salt", zap.String("role", role))
			return nil
		}
	}
	
	// Check what's already installed
	hasMinion := commandExists("salt-minion")
	hasMaster := commandExists("salt-master")
	
	packagesToInstall := []string{}
	
	// Always need minion
	if !hasMinion {
		packagesToInstall = append(packagesToInstall, "salt-minion")
	}
	
	// Master role needs salt-master
	if role == RoleMaster && !hasMaster {
		packagesToInstall = append(packagesToInstall, "salt-master")
	}
	
	if len(packagesToInstall) == 0 {
		logger.Info("Salt components already installed")
		return nil
	}
	
	logger.Info("Installing Salt packages", zap.Strings("packages", packagesToInstall))
	
	// Try different package managers
	if err := installPackagesAPT(rc, packagesToInstall); err == nil {
		return nil
	}
	
	if err := installPackagesYUM(rc, packagesToInstall); err == nil {
		return nil
	}

	if err := installPackagesPacman(rc, packagesToInstall); err == nil {
		return nil
	}

	if err := installPackagesZypper(rc, packagesToInstall); err == nil {
		return nil
	}

	if err := installPackagesPkg(rc, packagesToInstall); err == nil {
		return nil
	}

	if err := installPackagesHomebrew(rc, packagesToInstall); err == nil {
		return nil
	}
	
	
	return fmt.Errorf("failed to install Salt packages using available package managers")
}

// installPackagesAPT installs packages using apt (Debian/Ubuntu)
func installPackagesAPT(rc *eos_io.RuntimeContext, packages []string) error {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return fmt.Errorf("apt-get not found")
	}
	
	// Update package list
	cmd := exec.Command("apt-get", "update")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apt-get update failed: %s", string(output))
	}
	
	// Install packages
	args := append([]string{"install", "-y"}, packages...)
	cmd = exec.Command("apt-get", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apt-get install failed: %s", string(output))
	}
	
	return nil
}

// installPackagesYUM installs packages using yum/dnf (RHEL/CentOS/Fedora)
func installPackagesYUM(rc *eos_io.RuntimeContext, packages []string) error {
	// Try dnf first (newer), then yum
	packageManager := "dnf"
	if _, err := exec.LookPath("dnf"); err != nil {
		packageManager = "yum"
		if _, err := exec.LookPath("yum"); err != nil {
			return fmt.Errorf("neither dnf nor yum found")
		}
	}
	
	// Install packages
	args := append([]string{"install", "-y"}, packages...)
	cmd := exec.Command(packageManager, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s install failed: %s", packageManager, string(output))
	}
	
	return nil
}

// configureSaltMaster configures Salt master
func configureSaltMaster(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Configuring Salt master")
	
	// Create master configuration
	masterConfig := &SaltConfiguration{
		Mode:       SaltModeMaster,
		MinionID:   config.Datacenter + "-master",
		LogLevel:   "warning",
		FileRoots:  []string{"/srv/salt"},
		PillarRoots: []string{"/srv/pillar"},
		Extensions: map[string]string{
			"fileserver_backend": "git",
			"gitfs_provider":     "pygit2",
		},
		CustomConfig: map[string]interface{}{
			"interface":        "0.0.0.0",
			"auto_accept":      true,
			"keep_jobs":        24,
			"timeout":          5,
			"gather_job_timeout": 10,
			"worker_threads":   5,
		},
	}
	
	// Write master configuration
	if err := writeSaltConfiguration(rc, "/etc/salt/master", masterConfig, true); err != nil {
		return fmt.Errorf("failed to write master configuration: %w", err)
	}
	
	// Create directories
	dirs := []string{"/srv/salt", "/srv/pillar", "/var/log/salt"}
	for _, dir := range dirs {
		if err := createDirectoryIfNotExists(rc, dir); err != nil {
			logger.Warn("Failed to create directory", zap.String("dir", dir), zap.Error(err))
		}
	}
	
	// Configure minion on master (for local execution)
	minionConfig := &SaltConfiguration{
		Mode:     SaltModeMinion,
		MinionID: config.Datacenter + "-master",
		LogLevel: "warning",
		CustomConfig: map[string]interface{}{
			"master": "localhost",
		},
	}
	
	if err := writeSaltConfiguration(rc, "/etc/salt/minion", minionConfig, false); err != nil {
		return fmt.Errorf("failed to write minion configuration: %w", err)
	}
	
	// Start and enable services
	if err := manageSaltServices(rc, []string{"salt-master", "salt-minion"}, "start"); err != nil {
		return fmt.Errorf("failed to start Salt services: %w", err)
	}
	
	return nil
}

// configureSaltMinion configures Salt minion
func configureSaltMinion(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Configuring Salt minion", zap.String("master", config.MasterAddress))
	
	// Create minion configuration
	minionConfig := &SaltConfiguration{
		Mode:     SaltModeMinion,
		MinionID: config.Datacenter + "-" + getShortHostname(),
		LogLevel: "warning",
		CustomConfig: map[string]interface{}{
			"master": config.MasterAddress,
		},
	}
	
	// Write minion configuration
	if err := writeSaltConfiguration(rc, "/etc/salt/minion", minionConfig, false); err != nil {
		return fmt.Errorf("failed to write minion configuration: %w", err)
	}
	
	// Start and enable service
	if err := manageSaltServices(rc, []string{"salt-minion"}, "start"); err != nil {
		return fmt.Errorf("failed to start Salt minion: %w", err)
	}
	
	return nil
}

// writeSaltConfiguration writes Salt configuration to file
func writeSaltConfiguration(rc *eos_io.RuntimeContext, configPath string, config *SaltConfiguration, isMaster bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would write Salt configuration", zap.String("path", configPath))
			return nil
		}
	}
	
	// Backup existing configuration
	if err := backupExistingConfig(rc, configPath); err != nil {
		logger.Warn("Failed to backup existing configuration", zap.Error(err))
	}
	
	// Build configuration content
	var content strings.Builder
	
	// Header
	content.WriteString("# Salt configuration generated by eos self enroll\n")
	content.WriteString(fmt.Sprintf("# Generated at: %s\n", time.Now().Format(time.RFC3339)))
	content.WriteString("\n")
	
	// Basic configuration
	if config.MinionID != "" {
		content.WriteString(fmt.Sprintf("id: %s\n", config.MinionID))
	}
	
	if config.LogLevel != "" {
		content.WriteString(fmt.Sprintf("log_level: %s\n", config.LogLevel))
	}
	
	// Master-specific configuration
	if isMaster {
		content.WriteString("\n# Master configuration\n")
		content.WriteString("file_roots:\n")
		content.WriteString("  base:\n")
		for _, root := range config.FileRoots {
			content.WriteString(fmt.Sprintf("    - %s\n", root))
		}
		
		content.WriteString("\npillar_roots:\n")
		content.WriteString("  base:\n")
		for _, root := range config.PillarRoots {
			content.WriteString(fmt.Sprintf("    - %s\n", root))
		}
		
		// Git fileserver configuration
		if config.Extensions["fileserver_backend"] == "git" {
			content.WriteString("\n# Git fileserver configuration\n")
			content.WriteString("fileserver_backend:\n")
			content.WriteString("  - git\n")
			content.WriteString("  - roots\n")
			content.WriteString("\n")
			content.WriteString("gitfs_provider: pygit2\n")
			content.WriteString("gitfs_base: main\n")
			content.WriteString("\n")
			content.WriteString("# TODO: 2025-01-09T21:56:00Z - Configure gitfs_remotes with actual repositories\n")
			content.WriteString("# gitfs_remotes:\n")
			content.WriteString("#   - https://github.com/your-org/salt-states.git\n")
		}
	}
	
	// Custom configuration
	if len(config.CustomConfig) > 0 {
		content.WriteString("\n# Custom configuration\n")
		for key, value := range config.CustomConfig {
			content.WriteString(fmt.Sprintf("%s: %v\n", key, value))
		}
	}
	
	// Write configuration file
	if err := os.WriteFile(configPath, []byte(content.String()), 0640); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}
	
	logger.Info("Salt configuration written", zap.String("path", configPath))
	return nil
}

// backupExistingConfig creates a backup of existing configuration
func backupExistingConfig(rc *eos_io.RuntimeContext, configPath string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil // No existing config to backup
	}
	
	backupPath := configPath + BackupSuffix + "." + time.Now().Format("20060102-150405")
	
	// Read existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read existing config: %w", err)
	}
	
	// Write backup
	if err := os.WriteFile(backupPath, data, 0640); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}
	
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuration backed up", zap.String("backup_path", backupPath))
	
	return nil
}

// manageSaltServices manages Salt services (start/stop/restart/enable)
func manageSaltServices(rc *eos_io.RuntimeContext, services []string, action string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would manage Salt services", 
				zap.Strings("services", services),
				zap.String("action", action))
			return nil
		}
	}
	
	for _, service := range services {
		logger.Info("Managing Salt service", 
			zap.String("service", service),
			zap.String("action", action))
		
		// Try systemctl first
		if err := manageSystemdService(service, action); err == nil {
			// Also enable the service to start at boot
			if action == "start" {
				if err := manageSystemdService(service, "enable"); err != nil {
					logger.Warn("Failed to enable service", 
						zap.String("service", service),
						zap.Error(err))
				}
			}
			continue
		}
		
		// TODO: 2025-01-09T21:56:00Z - Add support for other init systems
		// - sysvinit
		// - upstart
		// - OpenRC
		
		return fmt.Errorf("failed to manage service %s", service)
	}
	
	return nil
}

// manageSystemdService manages a systemd service
func manageSystemdService(service, action string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found")
	}
	
	cmd := exec.Command("systemctl", action, service)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s %s failed: %s", action, service, string(output))
	}
	
	return nil
}

// createDirectoryIfNotExists creates a directory if it doesn't exist
func createDirectoryIfNotExists(rc *eos_io.RuntimeContext, path string) error {
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			return nil
		}
	}
	
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}
	
	return nil
}

// commandExists checks if a command exists in PATH
func commandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// getShortHostname returns a short hostname for minion ID
func getShortHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	
	// Remove domain part if present
	if idx := strings.Index(hostname, "."); idx != -1 {
		hostname = hostname[:idx]
	}
	
	return hostname
}

// GenerateMinionID generates a unique minion ID
func GenerateMinionID(datacenter, role string) string {
	hostname := getShortHostname()
	
	if datacenter != "" {
		return fmt.Sprintf("%s-%s-%s", datacenter, role, hostname)
	}
	
	return fmt.Sprintf("%s-%s", role, hostname)
}

// TestSaltConnectivity tests connectivity to Salt master
func TestSaltConnectivity(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test salt-minion connectivity
	if commandExists("salt-minion") {
		cmd := exec.Command("salt-minion", "--version")
		if output, err := cmd.Output(); err != nil {
			return fmt.Errorf("salt-minion not working: %w", err)
		} else {
			logger.Debug("Salt minion version", zap.String("output", string(output)))
		}
	}
	
	// Test network connectivity to master
	if masterAddr != "" {
		// Test both Salt ports
		for _, port := range []int{SaltPublisherPort, SaltRequestPort} {
			address := fmt.Sprintf("%s:%d", masterAddr, port)
			if err := testNetworkConnectivity(address); err != nil {
				return fmt.Errorf("cannot connect to master port %d: %w", port, err)
			}
		}
	}
	
	return nil
}

// testNetworkConnectivity tests network connectivity to an address
func testNetworkConnectivity(address string) error {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			// Log error but don't return it as this is just a connectivity test
		}
	}()
	return nil
}

// GetSaltKeyFingerprint gets the Salt key fingerprint for verification
func GetSaltKeyFingerprint(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Try to get minion key fingerprint
	cmd := exec.Command("salt-call", "--local", "key.finger")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get salt key fingerprint: %w", err)
	}
	
	fingerprint := strings.TrimSpace(string(output))
	logger.Info("Salt key fingerprint", zap.String("fingerprint", fingerprint))
	
	return fingerprint, nil
}

// installPackagesPacman installs packages using pacman (Arch Linux)
func installPackagesPacman(rc *eos_io.RuntimeContext, packages []string) error {
	if _, err := exec.LookPath("pacman"); err != nil {
		return fmt.Errorf("pacman not found")
	}

	// Update package database
	cmd := exec.Command("pacman", "-Sy")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pacman update failed: %s", string(output))
	}

	// Install packages
	args := append([]string{"-S", "--noconfirm"}, packages...)
	cmd = exec.Command("pacman", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pacman install failed: %s", string(output))
	}

	return nil
}

// installPackagesZypper installs packages using zypper (openSUSE)
func installPackagesZypper(rc *eos_io.RuntimeContext, packages []string) error {
	if _, err := exec.LookPath("zypper"); err != nil {
		return fmt.Errorf("zypper not found")
	}

	// Refresh repositories
	cmd := exec.Command("zypper", "refresh")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("zypper refresh failed: %s", string(output))
	}

	// Install packages
	args := append([]string{"install", "-y"}, packages...)
	cmd = exec.Command("zypper", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("zypper install failed: %s", string(output))
	}

	return nil
}

// installPackagesPkg installs packages using pkg (FreeBSD)
func installPackagesPkg(rc *eos_io.RuntimeContext, packages []string) error {
	if _, err := exec.LookPath("pkg"); err != nil {
		return fmt.Errorf("pkg not found")
	}

	// Update package repository
	cmd := exec.Command("pkg", "update")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pkg update failed: %s", string(output))
	}

	// Install packages
	args := append([]string{"install", "-y"}, packages...)
	cmd = exec.Command("pkg", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pkg install failed: %s", string(output))
	}

	return nil
}

// installPackagesHomebrew installs packages using homebrew (macOS)
func installPackagesHomebrew(rc *eos_io.RuntimeContext, packages []string) error {
	if _, err := exec.LookPath("brew"); err != nil {
		return fmt.Errorf("brew not found")
	}

	// Update homebrew
	cmd := exec.Command("brew", "update")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("brew update failed: %s", string(output))
	}

	// Install packages (homebrew uses different package names for salt)
	homebrewPackages := make([]string, len(packages))
	for i, pkg := range packages {
		switch pkg {
		case "salt-master":
			homebrewPackages[i] = "saltstack"
		case "salt-minion":
			homebrewPackages[i] = "saltstack"
		default:
			homebrewPackages[i] = pkg
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniquePackages []string
	for _, pkg := range homebrewPackages {
		if !seen[pkg] {
			uniquePackages = append(uniquePackages, pkg)
			seen[pkg] = true
		}
	}

	args := append([]string{"install"}, uniquePackages...)
	cmd = exec.Command("brew", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("brew install failed: %s", string(output))
	}

	return nil
}