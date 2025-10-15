// Package connectors provides service connector implementations
package connectors

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/synctypes"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulVaultConnector implements bidirectional Consul ↔ Vault integration
type ConsulVaultConnector struct{}

// NewConsulVaultConnector creates a new Consul-Vault connector
func NewConsulVaultConnector() *ConsulVaultConnector {
	return &ConsulVaultConnector{}
}

// Name returns the connector name
func (c *ConsulVaultConnector) Name() string {
	return "ConsulVaultConnector"
}

// Description returns a human-readable description
func (c *ConsulVaultConnector) Description() string {
	return "Connects Consul and Vault: configures Vault to use Consul as storage backend and registers Vault in Consul service catalog"
}

// ServicePair returns the normalized service pair identifier
func (c *ConsulVaultConnector) ServicePair() string {
	return "consul-vault"
}

// PreflightCheck verifies both services are installed and running
func (c *ConsulVaultConnector) PreflightCheck(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running pre-flight checks for Consul and Vault")

	// Check Consul status
	logger.Debug("Checking Consul status")
	consulStatus, err := consul.CheckStatus(rc)
	if err != nil {
		return fmt.Errorf("failed to check Consul status: %w", err)
	}

	if !consulStatus.Installed {
		return eos_err.NewUserError(
			"Consul is not installed. Please install Consul first:\n" +
				"  sudo eos create consul")
	}

	if !consulStatus.Running {
		return eos_err.NewUserError(
			"Consul is not running. Please start Consul:\n" +
				"  sudo systemctl start consul")
	}

	logger.Info("Consul pre-flight check passed",
		zap.String("version", consulStatus.Version),
		zap.String("status", consulStatus.ServiceStatus))

	// Check Vault status
	logger.Debug("Checking Vault status")

	// Check if Vault binary exists
	vaultBinary, err := exec.LookPath("vault")
	if err != nil {
		return eos_err.NewUserError(
			"Vault is not installed. Please install Vault first:\n" +
				"  sudo eos create vault")
	}
	logger.Debug("Vault binary found", zap.String("path", vaultBinary))

	// Check if Vault service exists and is running
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "vault"},
		Capture: true,
	})

	vaultRunning := (err == nil && strings.TrimSpace(output) == "active")
	if !vaultRunning {
		return eos_err.NewUserError(
			"Vault is not running. Please start Vault:\n" +
				"  sudo systemctl start vault")
	}

	logger.Info("Vault pre-flight check passed")

	return nil
}

// CheckConnection returns the current connection state
func (c *ConsulVaultConnector) CheckConnection(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.SyncState, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Consul-Vault connection state")

	state := &synctypes.SyncState{}

	// Check Consul status
	consulStatus, err := consul.CheckStatus(rc)
	if err != nil {
		return state, fmt.Errorf("failed to check Consul status: %w", err)
	}
	state.Service1Installed = consulStatus.Installed
	state.Service1Running = consulStatus.Running
	state.Service1Healthy = consulStatus.Running && consulStatus.ConfigValid

	// Check Vault status
	vaultBinary, err := exec.LookPath("vault")
	state.Service2Installed = (err == nil && vaultBinary != "")

	if state.Service2Installed {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", "vault"},
			Capture: true,
		})
		state.Service2Running = (err == nil && strings.TrimSpace(output) == "active")
		state.Service2Healthy = state.Service2Running
	}

	// Check if Vault config uses Consul storage
	vaultConfigPath := "/etc/vault.d/vault.hcl"
	configContent, err := os.ReadFile(vaultConfigPath)
	if err != nil {
		logger.Warn("Could not read Vault config",
			zap.String("path", vaultConfigPath),
			zap.Error(err))
		state.ConfigurationComplete = false
		state.ConfigurationValid = false
		state.Connected = false
		state.Reason = "Cannot read Vault configuration"
		return state, nil
	}

	// Check for Consul storage backend in config
	hasConsulStorage := strings.Contains(string(configContent), `storage "consul"`)

	// Extract Consul address from config if present
	var consulAddr string
	if hasConsulStorage {
		addrRegex := regexp.MustCompile(`address\s*=\s*"([^"]+)"`)
		if matches := addrRegex.FindStringSubmatch(string(configContent)); len(matches) > 1 {
			consulAddr = matches[1]
		}
	}

	expectedAddr := shared.ConsulDefaultAddr
	correctAddress := (consulAddr == expectedAddr)

	state.ConfigurationComplete = hasConsulStorage
	state.ConfigurationValid = hasConsulStorage && correctAddress
	state.Connected = state.ConfigurationComplete && state.ConfigurationValid && state.Service1Healthy && state.Service2Healthy

	if state.Connected {
		state.Healthy = true
		state.Reason = fmt.Sprintf("Vault configured to use Consul storage at %s", expectedAddr)
	} else if hasConsulStorage && !correctAddress {
		state.Reason = fmt.Sprintf("Vault uses Consul storage but incorrect address (found: %s, expected: %s)", consulAddr, expectedAddr)
	} else if !hasConsulStorage {
		state.Reason = "Vault is not configured to use Consul storage"
	} else {
		state.Reason = "Configuration incomplete or services unhealthy"
	}

	logger.Info("Connection state checked",
		zap.Bool("connected", state.Connected),
		zap.Bool("healthy", state.Healthy),
		zap.String("reason", state.Reason))

	return state, nil
}

// Backup creates backups of service configurations
func (c *ConsulVaultConnector) Backup(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.BackupMetadata, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating configuration backups")

	// Create backup directory
	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Join("/opt/eos/backups/sync", fmt.Sprintf("consul-vault-%s", timestamp))

	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	metadata := &synctypes.BackupMetadata{
		BackupDir:   backupDir,
		BackupTime:  timestamp,
		BackupFiles: make(map[string]string),
	}

	// Backup Vault configuration
	vaultConfigPath := "/etc/vault.d/vault.hcl"
	vaultBackupPath := filepath.Join(backupDir, "vault.hcl.backup")

	if err := copyFile(vaultConfigPath, vaultBackupPath); err != nil {
		logger.Warn("Could not backup Vault config (may not exist)",
			zap.String("source", vaultConfigPath),
			zap.Error(err))
	} else {
		metadata.BackupFiles[vaultConfigPath] = vaultBackupPath
		metadata.Service2ConfigPath = vaultConfigPath
		logger.Info("Backed up Vault configuration",
			zap.String("backup_path", vaultBackupPath))
	}

	// Note: Consul config typically doesn't need modification for Vault integration
	// But we'll note the path for completeness
	metadata.Service1ConfigPath = "/etc/consul.d/consul.hcl"

	logger.Info("Configuration backup completed",
		zap.String("backup_dir", backupDir),
		zap.Int("files_backed_up", len(metadata.BackupFiles)))

	return metadata, nil
}

// Connect establishes the connection between Consul and Vault
func (c *ConsulVaultConnector) Connect(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Connecting Consul and Vault")

	// Read current Vault configuration
	vaultConfigPath := "/etc/vault.d/vault.hcl"
	configContent, err := os.ReadFile(vaultConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read Vault config at %s: %w", vaultConfigPath, err)
	}

	configStr := string(configContent)

	// Check if already using Consul storage
	if strings.Contains(configStr, `storage "consul"`) {
		logger.Info("Vault config already contains Consul storage, updating address")

		// Update the address to use correct port
		addrRegex := regexp.MustCompile(`(storage "consul"\s*\{[^}]*address\s*=\s*)"[^"]*"`)
		updatedConfig := addrRegex.ReplaceAllString(configStr, fmt.Sprintf(`${1}"%s"`, shared.ConsulDefaultAddr))

		if updatedConfig == configStr {
			logger.Debug("No address change needed, config already correct")
		} else {
			if err := os.WriteFile(vaultConfigPath, []byte(updatedConfig), 0640); err != nil {
				return fmt.Errorf("failed to update Vault config: %w", err)
			}
			logger.Info("Updated Consul address in Vault config",
				zap.String("address", shared.ConsulDefaultAddr))
		}
	} else {
		logger.Info("Adding Consul storage backend to Vault config")

		// Find and replace storage backend
		// Look for existing storage block (raft, file, etc.)
		storageRegex := regexp.MustCompile(`(?s)storage "[^"]*"\s*\{[^}]*\}`)

		consulStorageBlock := fmt.Sprintf(`storage "consul" {
  address = "%s"
  path    = "vault/"
}`, shared.ConsulDefaultAddr)

		var updatedConfig string
		if storageRegex.MatchString(configStr) {
			// Replace existing storage backend
			updatedConfig = storageRegex.ReplaceAllString(configStr, consulStorageBlock)
			logger.Info("Replaced existing storage backend with Consul")
		} else {
			// Insert before listener block
			listenerRegex := regexp.MustCompile(`(listener "tcp"\s*\{)`)
			if listenerRegex.MatchString(configStr) {
				updatedConfig = listenerRegex.ReplaceAllString(configStr, consulStorageBlock+"\n\n${1}")
				logger.Info("Inserted Consul storage backend before listener")
			} else {
				// Just prepend if no listener found
				updatedConfig = consulStorageBlock + "\n\n" + configStr
				logger.Info("Prepended Consul storage backend to config")
			}
		}

		// Write updated config
		if err := os.WriteFile(vaultConfigPath, []byte(updatedConfig), 0640); err != nil {
			return fmt.Errorf("failed to write updated Vault config: %w", err)
		}
	}

	// Add service_registration block if not present
	if !strings.Contains(configStr, `service_registration "consul"`) {
		logger.Info("Adding Consul service registration to Vault config")

		configContent, _ := os.ReadFile(vaultConfigPath)
		configStr = string(configContent)

		serviceRegBlock := fmt.Sprintf(`
service_registration "consul" {
  address = "%s"
}`, shared.ConsulDefaultAddr)

		updatedConfig := configStr + "\n" + serviceRegBlock

		if err := os.WriteFile(vaultConfigPath, []byte(updatedConfig), 0640); err != nil {
			return fmt.Errorf("failed to add service registration: %w", err)
		}
		logger.Info("Added Consul service registration")
	}

	// Restart Vault service to apply changes
	logger.Info("Restarting Vault service to apply configuration changes")
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "vault"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart Vault service: %w", err)
	}

	// Wait for Vault to come back up
	logger.Info("Waiting for Vault to become ready")
	time.Sleep(3 * time.Second)

	return nil
}

// Verify validates the connection is working correctly
func (c *ConsulVaultConnector) Verify(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Consul-Vault connection")

	// Check Vault service is active
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "vault"},
		Capture: true,
	})
	if err != nil || strings.TrimSpace(output) != "active" {
		return fmt.Errorf("vault service is not active after restart")
	}
	logger.Info("Vault service is active")

	// Verify Vault health
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get Vault client: %w", err)
	}

	health, err := client.Sys().Health()
	if err != nil {
		logger.Warn("Vault health check returned error (may be sealed)", zap.Error(err))
		// Note: Sealed vault is expected if not yet initialized/unsealed
		// This is not necessarily a failure condition
	} else {
		logger.Info("Vault health check passed",
			zap.Bool("initialized", health.Initialized),
			zap.Bool("sealed", health.Sealed))
	}

	// Check that config actually has Consul storage
	vaultConfigPath := "/etc/vault.d/vault.hcl"
	configContent, err := os.ReadFile(vaultConfigPath)
	if err != nil {
		return fmt.Errorf("failed to verify config: %w", err)
	}

	if !strings.Contains(string(configContent), `storage "consul"`) {
		return fmt.Errorf("vault config does not contain Consul storage backend")
	}

	if !strings.Contains(string(configContent), shared.ConsulDefaultAddr) {
		return fmt.Errorf("vault config does not contain correct Consul address: %s", shared.ConsulDefaultAddr)
	}

	logger.Info("Connection verified successfully",
		zap.String("consul_addr", shared.ConsulDefaultAddr))

	return nil
}

// Rollback reverts configuration changes using backup metadata
func (c *ConsulVaultConnector) Rollback(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig, backup *synctypes.BackupMetadata) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Rolling back configuration changes",
		zap.String("backup_dir", backup.BackupDir))

	// Restore Vault configuration
	if vaultBackup, exists := backup.BackupFiles["/etc/vault.d/vault.hcl"]; exists {
		logger.Info("Restoring Vault configuration",
			zap.String("backup", vaultBackup))

		if err := copyFile(vaultBackup, "/etc/vault.d/vault.hcl"); err != nil {
			return fmt.Errorf("failed to restore Vault config: %w", err)
		}

		// Restart Vault to apply restored config
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"restart", "vault"},
			Capture: true,
		})
		if err != nil {
			logger.Warn("Failed to restart Vault after rollback", zap.Error(err))
			// Continue with rollback even if restart fails
		}
	}

	logger.Info("Rollback completed")
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	if err := os.WriteFile(dst, data, 0640); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	return nil
}
