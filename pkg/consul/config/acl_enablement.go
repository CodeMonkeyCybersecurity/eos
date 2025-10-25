// pkg/consul/config/acl_enablement.go
// Automated ACL enablement for Consul configuration

package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// ConsulServiceName is the systemd service name
	// NOTE: Duplicates consul.ConsulServiceName to avoid circular import
	// (pkg/consul/config cannot import pkg/consul)
	ConsulServiceName = "consul"
)

// ACLEnablementConfig holds configuration for ACL enablement operation
type ACLEnablementConfig struct {
	ConfigPath    string // Path to consul.hcl (usually /etc/consul.d/consul.hcl)
	BackupEnabled bool   // Create backup before modification
	ValidateSyntax bool  // Validate HCL syntax after modification
	DefaultPolicy string // ACL default policy ("allow" or "deny")
}

// ACLEnablementResult contains the result of ACL enablement operation
type ACLEnablementResult struct {
	Success       bool      // True if ACLs were enabled successfully
	BackupPath    string    // Path to backup file (if created)
	ModifiedTime  time.Time // When modification occurred
	ConfigChanged bool      // True if config file was actually modified
	Message       string    // Human-readable result message
}

// EnableACLsInConfig modifies Consul configuration to enable ACLs
//
// This function:
// 1. Reads current Consul configuration
// 2. Creates backup (if enabled)
// 3. Modifies ACL block to set enabled = true
// 4. Validates HCL syntax (if enabled)
// 5. Writes modified configuration
//
// Parameters:
//   - rc: Runtime context for logging
//   - config: ACL enablement configuration
//
// Returns:
//   - ACLEnablementResult with operation details
//   - Error if enablement fails
//
// Example:
//
//	config := &ACLEnablementConfig{
//	    ConfigPath: "/etc/consul.d/consul.hcl",
//	    BackupEnabled: true,
//	    ValidateSyntax: true,
//	    DefaultPolicy: "deny",
//	}
//	result, err := EnableACLsInConfig(rc, config)
func EnableACLsInConfig(rc *eos_io.RuntimeContext, config *ACLEnablementConfig) (*ACLEnablementResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Enabling ACLs in Consul configuration",
		zap.String("config_path", config.ConfigPath),
		zap.Bool("backup_enabled", config.BackupEnabled),
		zap.String("default_policy", config.DefaultPolicy))

	result := &ACLEnablementResult{
		ModifiedTime: time.Now(),
	}

	// ASSESS - Read current configuration
	logger.Debug("Reading current Consul configuration")

	configData, err := os.ReadFile(config.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Consul config at %s: %w", config.ConfigPath, err)
	}

	originalConfig := string(configData)

	// Check if ACLs are already enabled
	if isACLAlreadyEnabled(originalConfig) {
		logger.Info("ACLs are already enabled in configuration")
		result.Success = true
		result.ConfigChanged = false
		result.Message = "ACLs already enabled in configuration"
		return result, nil
	}

	// INTERVENE - Create backup if enabled
	if config.BackupEnabled {
		backupPath, err := BackupConfig(rc, config.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create backup: %w", err)
		}
		result.BackupPath = backupPath
		logger.Info("Configuration backup created",
			zap.String("backup_path", backupPath))
	}

	// INTERVENE - Modify ACL block
	logger.Debug("Modifying ACL configuration block")

	modifiedConfig, err := modifyACLBlock(originalConfig, config.DefaultPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to modify ACL block: %w", err)
	}

	// INTERVENE - Write modified configuration
	logger.Debug("Writing modified configuration",
		zap.String("path", config.ConfigPath))

	// Use same permissions as original file
	fileInfo, err := os.Stat(config.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat config file: %w", err)
	}

	if err := os.WriteFile(config.ConfigPath, []byte(modifiedConfig), fileInfo.Mode()); err != nil {
		return nil, fmt.Errorf("failed to write modified config: %w", err)
	}

	result.ConfigChanged = true

	// EVALUATE - Validate HCL syntax if enabled
	if config.ValidateSyntax {
		logger.Debug("Validating HCL syntax")

		if err := ValidateConfigSyntax(rc, config.ConfigPath); err != nil {
			// Syntax validation failed - restore backup
			logger.Error("HCL syntax validation failed, restoring backup",
				zap.Error(err))

			if config.BackupEnabled && result.BackupPath != "" {
				if restoreErr := restoreBackup(rc, result.BackupPath, config.ConfigPath); restoreErr != nil {
					return nil, fmt.Errorf("syntax validation failed AND backup restore failed: validation error: %w, restore error: %v", err, restoreErr)
				}
				logger.Info("Backup restored successfully after syntax validation failure")
			}

			return nil, fmt.Errorf("HCL syntax validation failed: %w", err)
		}

		logger.Info("HCL syntax validation passed")
	}

	// EVALUATE - Success
	result.Success = true
	result.Message = "ACLs enabled successfully in configuration"

	logger.Info("ACL enablement completed successfully",
		zap.Bool("config_changed", result.ConfigChanged),
		zap.String("backup_path", result.BackupPath))

	return result, nil
}

// BackupConfig creates a timestamped backup of Consul configuration
func BackupConfig(rc *eos_io.RuntimeContext, configPath string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.backup.%s", configPath, timestamp)

	logger.Debug("Creating configuration backup",
		zap.String("source", configPath),
		zap.String("backup", backupPath))

	// Read original config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config for backup: %w", err)
	}

	// Write backup with same permissions as original
	fileInfo, err := os.Stat(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat config file: %w", err)
	}

	if err := os.WriteFile(backupPath, data, fileInfo.Mode()); err != nil {
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	logger.Info("Configuration backup created successfully",
		zap.String("backup_path", backupPath))

	return backupPath, nil
}

// ValidateConfigSyntax validates Consul HCL configuration syntax
func ValidateConfigSyntax(rc *eos_io.RuntimeContext, configPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating Consul configuration syntax",
		zap.String("config_path", configPath))

	// Use 'consul validate' command
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"validate", configPath},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("configuration validation failed: %s\nOutput: %s", err, output)
	}

	logger.Debug("Configuration syntax is valid")
	return nil
}

// restoreBackup restores configuration from backup file
func restoreBackup(rc *eos_io.RuntimeContext, backupPath, configPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restoring configuration from backup",
		zap.String("backup_path", backupPath),
		zap.String("config_path", configPath))

	// Read backup
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Write to config location
	fileInfo, err := os.Stat(configPath)
	if err != nil {
		// Config file might not exist, use default permissions
		fileInfo, _ = os.Stat(backupPath)
	}

	if err := os.WriteFile(configPath, data, fileInfo.Mode()); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	logger.Info("Configuration restored from backup successfully")
	return nil
}

// isACLAlreadyEnabled checks if ACLs are already enabled in config
func isACLAlreadyEnabled(configContent string) bool {
	// Look for acl block with enabled = true
	// Handle both formats:
	//   acl { enabled = true }
	//   acl = { enabled = true }

	// Match "enabled = true" within acl block
	aclBlockRegex := regexp.MustCompile(`(?s)acl\s*=?\s*\{[^}]*enabled\s*=\s*true[^}]*\}`)
	return aclBlockRegex.MatchString(configContent)
}

// modifyACLBlock modifies the ACL configuration block
func modifyACLBlock(configContent string, defaultPolicy string) (string, error) {
	// Find existing ACL block
	aclBlockRegex := regexp.MustCompile(`(?s)(acl\s*=?\s*\{)([^}]*)\}`)

	if !aclBlockRegex.MatchString(configContent) {
		// No ACL block found - should not happen with default Eos configs
		return "", fmt.Errorf("no ACL block found in configuration")
	}

	// Replace the ACL block
	newACLBlock := fmt.Sprintf(`acl = {
  enabled = true
  default_policy = "%s"  # Modified by eos sync --vault --consul
  enable_token_persistence = true
}`, defaultPolicy)

	modifiedConfig := aclBlockRegex.ReplaceAllString(configContent, newACLBlock)

	return modifiedConfig, nil
}

// RestartConsulService restarts Consul service and waits for it to be ready
func RestartConsulService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restarting Consul service")

	// Restart service
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", ConsulServiceName},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to restart Consul: %s\nOutput: %s", err, output)
	}

	logger.Info("Consul service restart command issued, waiting for service to be ready...")

	// Wait for Consul to be ready (max 30 seconds)
	maxWait := 30 * time.Second
	checkInterval := 1 * time.Second
	deadline := time.Now().Add(maxWait)

	for time.Now().Before(deadline) {
		// Check if service is active
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", ConsulServiceName},
			Capture: true,
		})

		if err == nil && strings.TrimSpace(output) == "active" {
			logger.Info("Consul service is active")

			// Additional check: try to query Consul API
			membersOutput, membersErr := execute.Run(rc.Ctx, execute.Options{
				Command: "consul",
				Args:    []string{"members"},
				Capture: true,
			})

			if membersErr == nil && strings.Contains(membersOutput, "alive") {
				logger.Info("Consul API is responding")
				return nil
			}

			logger.Debug("Consul service active but API not ready yet, continuing to wait...")
		}

		time.Sleep(checkInterval)
	}

	return fmt.Errorf("Consul did not become ready within %v after restart", maxWait)
}
