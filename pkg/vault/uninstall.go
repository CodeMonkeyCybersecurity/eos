// pkg/vault/uninstall.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UninstallConfig contains configuration for Vault uninstallation
type UninstallConfig struct {
	Force          bool   // Skip confirmation prompts
	RemoveData     bool   // Remove data directories
	RemoveUser     bool   // Remove vault user/group
	Distro         string // Distribution type (debian, rhel)
	PreserveLogs   bool   // Keep log files
	PreserveBackup bool   // Keep backup files
}

// UninstallState represents the current state of Vault installation
type UninstallState struct {
	BinaryInstalled  bool
	ServiceRunning   bool
	ServiceEnabled   bool
	ConfigExists     bool
	DataExists       bool
	UserExists       bool
	Version          string
	ExistingPaths    []string
	PackageInstalled bool
}

// VaultUninstaller handles safe removal of Vault
type VaultUninstaller struct {
	rc     *eos_io.RuntimeContext
	config *UninstallConfig
	logger otelzap.LoggerWithCtx
	state  *UninstallState
}

// NewVaultUninstaller creates a new Vault uninstaller
func NewVaultUninstaller(rc *eos_io.RuntimeContext, config *UninstallConfig) *VaultUninstaller {
	if config == nil {
		config = &UninstallConfig{
			Force:      false,
			RemoveData: true,
			RemoveUser: true,
		}
	}

	// Auto-detect distribution if not specified
	if config.Distro == "" {
		config.Distro = detectDistro()
	}

	return &VaultUninstaller{
		rc:     rc,
		config: config,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// Assess checks the current state of Vault installation
func (vu *VaultUninstaller) Assess() (*UninstallState, error) {
	vu.logger.Info("Assessing Vault installation state")

	state := &UninstallState{
		ExistingPaths: []string{},
	}

	// Check if binary is installed
	if binaryPath, err := exec.LookPath("vault"); err == nil {
		state.BinaryInstalled = true
		vu.logger.Info("Vault binary found", zap.String("path", binaryPath))

		// Get version
		if output, err := exec.Command("vault", "version").Output(); err == nil {
			state.Version = strings.TrimSpace(string(output))
			vu.logger.Info("Current Vault version", zap.String("version", state.Version))
		}
	}

	// Check if service is running
	if output, err := exec.Command("systemctl", "is-active", "vault").Output(); err == nil {
		status := strings.TrimSpace(string(output))
		state.ServiceRunning = (status == "active")
		if state.ServiceRunning {
			vu.logger.Info("Vault service is currently active")
		}
	}

	// Check if service is enabled
	if err := exec.Command("systemctl", "is-enabled", "vault").Run(); err == nil {
		state.ServiceEnabled = true
	}

	// Check for configuration and data directories
	checkPaths := map[string]*bool{
		"/etc/vault.d":   &state.ConfigExists,
		"/opt/vault":     &state.DataExists,
		"/var/lib/vault": nil, // Just track existence
		"/var/log/vault": nil,
	}

	for path, stateFlag := range checkPaths {
		if _, err := os.Stat(path); err == nil {
			state.ExistingPaths = append(state.ExistingPaths, path)
			if stateFlag != nil {
				*stateFlag = true
			}
		}
	}

	// Check if vault user exists
	if err := exec.Command("id", "vault").Run(); err == nil {
		state.UserExists = true
		vu.logger.Info("Vault user exists")
	}

	// Check if installed via package manager
	var checkCmd *exec.Cmd
	if vu.config.Distro == "debian" {
		checkCmd = exec.Command("dpkg", "-l", "vault")
	} else if vu.config.Distro == "rhel" {
		checkCmd = exec.Command("rpm", "-q", "vault")
	}
	if checkCmd != nil && checkCmd.Run() == nil {
		state.PackageInstalled = true
	}

	vu.state = state
	vu.logger.Info("Assessment complete",
		zap.Bool("binary_installed", state.BinaryInstalled),
		zap.Bool("service_running", state.ServiceRunning),
		zap.Bool("config_exists", state.ConfigExists),
		zap.Bool("data_exists", state.DataExists),
		zap.Int("existing_paths", len(state.ExistingPaths)))

	return state, nil
}

// Stop stops all Vault services and removes systemd service files
func (vu *VaultUninstaller) Stop() error {
	vu.logger.Info("Stopping Vault services")

	// Stop vault service
	if err := exec.Command("systemctl", "stop", "vault").Run(); err != nil {
		vu.logger.Warn("Failed to stop vault service (may not be running)", zap.Error(err))
	}

	// Stop vault-agent if present
	if err := exec.Command("systemctl", "stop", "vault-agent").Run(); err != nil {
		vu.logger.Debug("vault-agent not running or doesn't exist")
	}

	// Disable services
	if vu.state != nil && vu.state.ServiceEnabled {
		exec.Command("systemctl", "disable", "vault").Run()
		exec.Command("systemctl", "disable", "vault-agent").Run()
	}

	// Kill any remaining vault processes
	if err := exec.Command("pkill", "-f", "vault").Run(); err != nil {
		vu.logger.Debug("No vault processes to kill")
	}

	// Remove systemd service files
	vu.logger.Info("Removing systemd service files")
	serviceFiles := []string{
		"/etc/systemd/system/vault.service",
		"/etc/systemd/system/vault-agent.service",
		"/lib/systemd/system/vault.service",
		"/usr/lib/systemd/system/vault.service",
	}

	for _, serviceFile := range serviceFiles {
		if err := os.Remove(serviceFile); err != nil {
			if !os.IsNotExist(err) {
				vu.logger.Debug("Failed to remove service file",
					zap.String("file", serviceFile),
					zap.Error(err))
			}
		} else {
			vu.logger.Debug("Removed service file", zap.String("file", serviceFile))
		}
	}

	// Reset failed state to clean up systemd completely
	exec.Command("systemctl", "reset-failed", "vault.service").Run()
	exec.Command("systemctl", "reset-failed", "vault-agent.service").Run()

	vu.logger.Info("Vault services stopped and cleaned")
	return nil
}

// RemovePackage removes Vault package via package manager
func (vu *VaultUninstaller) RemovePackage() error {
	if vu.state != nil && !vu.state.PackageInstalled {
		vu.logger.Debug("Vault not installed via package manager, skipping package removal")
		return nil
	}

	vu.logger.Info("Removing Vault package",
		zap.String("distro", vu.config.Distro))

	var cmd *exec.Cmd
	if vu.config.Distro == "debian" {
		cmd = exec.Command("apt-get", "remove", "--purge", "-y", "vault")
	} else if vu.config.Distro == "rhel" {
		cmd = exec.Command("dnf", "remove", "-y", "vault")
	} else {
		vu.logger.Warn("Unknown distribution, skipping package removal",
			zap.String("distro", vu.config.Distro))
		return nil
	}

	if err := cmd.Run(); err != nil {
		vu.logger.Warn("Failed to remove package", zap.Error(err))
		return fmt.Errorf("package removal failed: %w", err)
	}

	// Autoremove on Debian-based systems
	if vu.config.Distro == "debian" {
		exec.Command("apt-get", "autoremove", "-y").Run()
	}

	return nil
}

// CleanFiles removes all Vault files and directories
func (vu *VaultUninstaller) CleanFiles() ([]string, map[string]error) {
	vu.logger.Info("Purging all Vault files and configurations")

	removed, errs := Purge(vu.rc, vu.config.Distro)

	if len(removed) > 0 {
		vu.logger.Info("Removed Vault files",
			zap.Int("count", len(removed)),
			zap.Strings("files", removed))
	}

	if len(errs) > 0 {
		vu.logger.Warn("Some files could not be removed",
			zap.Int("error_count", len(errs)))
		for path, err := range errs {
			vu.logger.Debug("Failed to remove path",
				zap.String("path", path),
				zap.Error(err))
		}
	}

	return removed, errs
}

// RemoveUser removes the vault system user and group
func (vu *VaultUninstaller) RemoveUser() error {
	if !vu.config.RemoveUser {
		vu.logger.Debug("Skipping user removal (disabled in config)")
		return nil
	}

	if vu.state != nil && !vu.state.UserExists {
		vu.logger.Debug("Vault user does not exist, skipping removal")
		return nil
	}

	vu.logger.Info("Removing vault user and group")

	// Remove user (will also remove home directory with -r)
	if err := exec.Command("userdel", "-r", "vault").Run(); err != nil {
		vu.logger.Warn("Failed to remove vault user", zap.Error(err))
	}

	// Remove group
	if err := exec.Command("groupdel", "vault").Run(); err != nil {
		vu.logger.Debug("Failed to remove vault group (may not exist or still in use)")
	}

	return nil
}

// CleanEnvironmentVariables removes Vault-related environment variables
func (vu *VaultUninstaller) CleanEnvironmentVariables() error {
	vu.logger.Info("Cleaning Vault environment variables")

	// Files to clean
	envFiles := []string{
		"/etc/environment",
		"/etc/profile.d/vault.sh",
	}

	// Environment variables to remove
	vaultVars := []string{
		"VAULT_ADDR",
		"VAULT_CACERT",
		"VAULT_CLIENT_CERT",
		"VAULT_CLIENT_KEY",
		"VAULT_SKIP_VERIFY",
		"VAULT_TOKEN",
	}

	for _, envFile := range envFiles {
		// Check if file exists
		if _, err := os.Stat(envFile); os.IsNotExist(err) {
			continue
		}

		// For /etc/profile.d/vault.sh, just remove the whole file
		if envFile == "/etc/profile.d/vault.sh" {
			if err := os.Remove(envFile); err != nil {
				if !os.IsNotExist(err) {
					vu.logger.Debug("Failed to remove vault profile",
						zap.String("file", envFile),
						zap.Error(err))
				}
			} else {
				vu.logger.Debug("Removed vault profile", zap.String("file", envFile))
			}
			continue
		}

		// For /etc/environment, use sed to remove lines
		for _, varName := range vaultVars {
			cmd := exec.Command("sed", "-i", fmt.Sprintf("/%s/d", varName), envFile)
			if err := cmd.Run(); err != nil {
				vu.logger.Debug("Failed to remove env var from file",
					zap.String("var", varName),
					zap.String("file", envFile),
					zap.Error(err))
			}
		}
	}

	vu.logger.Info("Environment variables cleaned")
	return nil
}

// ReloadSystemd reloads systemd daemon configuration
func (vu *VaultUninstaller) ReloadSystemd() error {
	vu.logger.Debug("Reloading systemd daemon")
	return exec.Command("systemctl", "daemon-reload").Run()
}

// Verify checks if Vault was completely removed
func (vu *VaultUninstaller) Verify() ([]string, error) {
	vu.logger.Info("Verifying Vault removal")

	stillPresent := []string{}

	// Check if binary still in PATH
	if _, err := exec.LookPath("vault"); err == nil {
		stillPresent = append(stillPresent, "vault binary still in PATH")
	}

	// Check directories
	checkDirs := map[string]string{
		"/etc/vault.d":                            "config directory",
		"/opt/vault":                              "data directory",
		"/var/lib/vault":                          "data directory",
		"/var/log/vault":                          "log directory",
		"/etc/systemd/system/vault.service":       "systemd service",
		"/etc/systemd/system/vault-agent.service": "vault-agent service",
	}

	for dir, desc := range checkDirs {
		if _, err := os.Stat(dir); err == nil {
			stillPresent = append(stillPresent, fmt.Sprintf("%s (%s)", desc, dir))
		}
	}

	if len(stillPresent) > 0 {
		vu.logger.Warn("Some Vault components still present",
			zap.Strings("remaining", stillPresent))
		return stillPresent, nil
	}

	vu.logger.Info(" Vault removal completed successfully - all components removed")
	return stillPresent, nil
}

// Uninstall performs the complete uninstallation process
// Follows Assess → Intervene → Evaluate pattern
func (vu *VaultUninstaller) Uninstall() error {
	// ASSESS - Check current state
	state, err := vu.Assess()
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// If nothing is installed, return early
	if !state.BinaryInstalled && !state.ServiceRunning && len(state.ExistingPaths) == 0 {
		vu.logger.Info("Vault is not installed and no data directories found")
		return nil
	}

	// INTERVENE - Remove Vault
	vu.logger.Info("Beginning Vault uninstallation")

	// Stop services first (also removes systemd service files)
	if err := vu.Stop(); err != nil {
		vu.logger.Warn("Error stopping services", zap.Error(err))
		// Continue anyway
	}

	// Remove package if installed
	if err := vu.RemovePackage(); err != nil {
		vu.logger.Warn("Error removing package", zap.Error(err))
		// Continue anyway
	}

	// Clean files and directories
	removed, errs := vu.CleanFiles()

	// Remove user
	if err := vu.RemoveUser(); err != nil {
		vu.logger.Warn("Error removing user", zap.Error(err))
	}

	// Clean environment variables
	if err := vu.CleanEnvironmentVariables(); err != nil {
		vu.logger.Warn("Error cleaning environment variables", zap.Error(err))
	}

	// Reload systemd
	if err := vu.ReloadSystemd(); err != nil {
		vu.logger.Debug("Error reloading systemd", zap.Error(err))
	}

	// EVALUATE - Verify removal
	stillPresent, err := vu.Verify()

	vu.logger.Info("Vault uninstallation process finished",
		zap.Int("files_removed", len(removed)),
		zap.Int("errors", len(errs)),
		zap.Int("remaining_components", len(stillPresent)))

	return err
}

// detectDistro attempts to detect the Linux distribution
func detectDistro() string {
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "rhel"
	}
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian"
	}
	return "unknown"
}
