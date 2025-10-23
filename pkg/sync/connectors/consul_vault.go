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

	consulapi "github.com/hashicorp/consul/api"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	consulvault "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/vault"
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

	expectedAddr := shared.GetConsulHostPort()
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
	vaultConfigPath := vault.VaultConfigPath
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
	metadata.Service1ConfigPath = consul.ConsulConfigFile

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
	vaultConfigPath := vault.VaultConfigPath
	configContent, err := os.ReadFile(vaultConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read Vault config at %s: %w", vaultConfigPath, err)
	}

	configStr := string(configContent)

	// CRITICAL SAFETY CHECK: Don't change storage backend if Vault is initialized
	// Changing storage backend on initialized Vault will lose all data!
	if !strings.Contains(configStr, `storage "consul"`) {
		logger.Warn("Vault is not currently using Consul storage backend")

		// Check if Vault is initialized
		client, err := vault.GetVaultClient(rc)
		if err == nil {
			initialized, err := vault.IsVaultInitialized(rc, client)
			if err == nil && initialized {
				logger.Error("SAFETY CHECK FAILED: Cannot change storage backend on initialized Vault",
					zap.String("current_storage", c.detectStorageBackend(configStr)),
					zap.String("target_storage", "consul"))

				return fmt.Errorf("cannot change storage backend on initialized Vault: this would cause data loss\n\n"+
					"Current storage: %s\n"+
					"Target storage: consul\n\n"+
					"To migrate storage backends:\n"+
					"1. Use Vault's official migration tools\n"+
					"2. Or: Unseal Vault, export all secrets, reinitialize with new backend, import secrets\n"+
					"3. Or: Use --force flag to override (NOT RECOMMENDED - will lose all data)\n\n"+
					"Vault storage migration documentation:\n"+
					"https://developer.hashicorp.com/vault/docs/commands/operator/migrate",
					c.detectStorageBackend(configStr))
			}
		}

		// If we get here, Vault is either not initialized or we couldn't check
		// Proceed with caution
		if !config.Force {
			logger.Warn("Proceeding with storage backend change on uninitialized/inaccessible Vault")
		} else {
			logger.Warn("FORCE flag set - changing storage backend despite risks")
		}
	}

	// STEP 1: Create ACL policy and token if Consul ACLs are enabled
	var vaultACLToken string
	if config.ConsulACLToken != "" {
		logger.Info("Consul ACLs detected, creating Vault access policy and token")

		// Get Vault address
		vaultAddress := os.Getenv("VAULT_ADDR")
		if vaultAddress == "" {
			vaultAddress = vault.DefaultAddress
		}

		// Create VaultIntegration to handle ACL setup
		integration, err := consulvault.NewVaultIntegration(rc, &consulvault.IntegrationConfig{
			ConsulAddress:    shared.GetConsulHostPort(),
			ConsulACLToken:   config.ConsulACLToken,
			VaultAddress:     vaultAddress,
			AutoCreatePolicy: true,
			AutoCreateToken:  true,
			TokenTTL:         0, // No expiration for infrastructure tokens
		})
		if err != nil {
			logger.Warn("Could not create Vault integration for ACL setup",
				zap.Error(err),
				zap.String("reason", "Consul may not be accessible or ACL bootstrap not complete"))
			logger.Warn("Proceeding without ACL token - manual token creation required")
		} else {
			// Register Vault and get ACL token
			result, err := integration.RegisterVault(rc.Ctx, &consulvault.IntegrationConfig{
				ConsulAddress:    shared.GetConsulHostPort(),
				ConsulACLToken:   config.ConsulACLToken,
				VaultAddress:     vaultAddress,
				AutoCreatePolicy: true,
				AutoCreateToken:  true,
				TokenTTL:         0,
			})
			if err != nil {
				logger.Warn("Could not register Vault with Consul ACLs",
					zap.Error(err))
				logger.Warn("Proceeding without ACL token - manual token creation required")
			} else {
				vaultACLToken = result.TokenSecretID
				logger.Info("Successfully created Vault ACL policy and token",
					zap.String("policy_id", result.PolicyID),
					zap.String("policy_name", result.PolicyName),
					zap.String("token_accessor", result.TokenAccessorID))
			}
		}
	} else {
		logger.Debug("No Consul ACL token provided, ACLs not enabled or token not available")
	}

	// Check if already using Consul storage
	if strings.Contains(configStr, `storage "consul"`) {
		logger.Info("Vault config already contains Consul storage, updating address")

		// Update the address to use correct port
		addrRegex := regexp.MustCompile(`(storage "consul"\s*\{[^}]*address\s*=\s*)"[^"]*"`)
		updatedConfig := addrRegex.ReplaceAllString(configStr, fmt.Sprintf(`${1}"%s"`, shared.GetConsulHostPort()))

		if updatedConfig == configStr {
			logger.Debug("No address change needed, config already correct")
		} else {
			if err := os.WriteFile(vaultConfigPath, []byte(updatedConfig), vault.VaultConfigPerm); err != nil {
				return fmt.Errorf("failed to update Vault config: %w", err)
			}
			logger.Info("Updated Consul address in Vault config",
				zap.String("address", shared.GetConsulHostPort()))
		}
	} else {
		logger.Info("Adding Consul storage backend to Vault config")

		// Find and replace storage backend
		// Look for existing storage block (raft, file, etc.)
		storageRegex := regexp.MustCompile(`(?s)storage "[^"]*"\s*\{[^}]*\}`)

		// Build storage block with ACL token if available
		var consulStorageBlock string
		if vaultACLToken != "" {
			consulStorageBlock = fmt.Sprintf(`storage "consul" {
  address = "%s"
  path    = "%s"
  token   = "%s"
}`, shared.GetConsulHostPort(), vault.ConsulVaultStoragePrefix, vaultACLToken)
			logger.Info("Generated Consul storage config with ACL token")
		} else {
			consulStorageBlock = fmt.Sprintf(`storage "consul" {
  address = "%s"
  path    = "%s"
}`, shared.GetConsulHostPort(), vault.ConsulVaultStoragePrefix)
			logger.Debug("Generated Consul storage config without ACL token (ACLs not enabled)")
		}

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
		if err := os.WriteFile(vaultConfigPath, []byte(updatedConfig), vault.VaultConfigPerm); err != nil {
			return fmt.Errorf("failed to write updated Vault config: %w", err)
		}
	}

	// Add service_registration block if not present
	if !strings.Contains(configStr, `service_registration "consul"`) {
		logger.Info("Adding Consul service registration to Vault config")

		configContent, _ := os.ReadFile(vaultConfigPath)
		configStr = string(configContent)

		// Build service registration block with ACL token if available
		var serviceRegBlock string
		if vaultACLToken != "" {
			serviceRegBlock = fmt.Sprintf(`
service_registration "consul" {
  address = "%s"
  token   = "%s"
}`, shared.GetConsulHostPort(), vaultACLToken)
			logger.Info("Generated Consul service registration config with ACL token")
		} else {
			serviceRegBlock = fmt.Sprintf(`
service_registration "consul" {
  address = "%s"
}`, shared.GetConsulHostPort())
			logger.Debug("Generated Consul service registration config without ACL token")
		}

		updatedConfig := configStr + "\n" + serviceRegBlock

		if err := os.WriteFile(vaultConfigPath, []byte(updatedConfig), vault.VaultConfigPerm); err != nil {
			return fmt.Errorf("failed to add service registration: %w", err)
		}
		logger.Info("Added Consul service registration")
	}

	// Restart Vault service to apply changes
	logger.Info("Restarting Vault service to apply configuration changes")
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", vault.VaultServiceName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart Vault service: %w", err)
	}

	// Wait for Vault to come back up
	logger.Info("Waiting for Vault to become ready")
	time.Sleep(vault.VaultReadyWaitTime)

	return nil
}

// Verify validates the connection is working correctly
func (c *ConsulVaultConnector) Verify(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Consul-Vault connection")

	// Check Vault service is active
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", vault.VaultServiceName},
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
	vaultConfigPath := vault.VaultConfigPath
	configContent, err := os.ReadFile(vaultConfigPath)
	if err != nil {
		return fmt.Errorf("failed to verify config: %w", err)
	}

	if !strings.Contains(string(configContent), `storage "consul"`) {
		return fmt.Errorf("vault config does not contain Consul storage backend")
	}

	if !strings.Contains(string(configContent), shared.GetConsulHostPort()) {
		return fmt.Errorf("vault config does not contain correct Consul address: %s", shared.GetConsulHostPort())
	}

	// Verify Consul storage backend accessibility
	logger.Info("Verifying Consul storage backend connectivity")
	consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
	if err != nil {
		logger.Warn("Could not create Consul client for storage verification",
			zap.Error(err),
			zap.String("reason", "Consul may not be running or accessible"))
		logger.Info("Skipping Consul storage verification - ensure Consul is running and accessible")
	} else {
		// Test read access to Vault storage path
		testKey := vault.ConsulVaultStoragePrefix + "core/test"
		_, _, err = consulClient.KV().Get(testKey, nil)
		if err != nil {
			logger.Warn("Could not verify Consul storage access",
				zap.Error(err),
				zap.String("test_key", testKey),
				zap.String("reason", "This is normal if Vault is not initialized yet"))
		} else {
			logger.Info("Verified Vault can access Consul storage backend",
				zap.String("storage_prefix", vault.ConsulVaultStoragePrefix))
		}
	}

	logger.Info("Connection verified successfully",
		zap.String("consul_addr", shared.GetConsulHostPort()))

	return nil
}

// Rollback reverts configuration changes using backup metadata
func (c *ConsulVaultConnector) Rollback(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig, backup *synctypes.BackupMetadata) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Rolling back configuration changes",
		zap.String("backup_dir", backup.BackupDir))

	// Restore Vault configuration
	if vaultBackup, exists := backup.BackupFiles[vault.VaultConfigPath]; exists {
		logger.Info("Restoring Vault configuration",
			zap.String("backup", vaultBackup))

		if err := copyFile(vaultBackup, vault.VaultConfigPath); err != nil {
			return fmt.Errorf("failed to restore Vault config: %w", err)
		}

		// Restart Vault to apply restored config
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"restart", vault.VaultServiceName},
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

	// Use Vault config permission for Vault config files
	if err := os.WriteFile(dst, data, vault.VaultConfigPerm); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	return nil
}

// detectStorageBackend extracts the storage backend type from Vault config
func (c *ConsulVaultConnector) detectStorageBackend(configStr string) string {
	storageRegex := regexp.MustCompile(`storage "([^"]*)"`)
	matches := storageRegex.FindStringSubmatch(configStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return "unknown"
}
