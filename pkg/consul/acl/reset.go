// pkg/consul/acl/reset.go
//
// Consul ACL Bootstrap Reset and Recovery
//
// This package provides SDK-based ACL bootstrap reset functionality for
// recovering from lost bootstrap tokens. Uses only Consul Go SDK methods,
// no shell command execution.
//
// Use Case: When Consul ACLs are already bootstrapped but the bootstrap
// token is lost or not stored in Vault. This allows re-bootstrapping
// without destroying cluster data.
//
// Last Updated: 2025-01-25

package acl

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/process"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/validation"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// ConsulACLResetFilename is the ACL bootstrap reset index file
	// NOTE: Duplicates consul.ConsulACLResetFilename to avoid circular import
	// This constant MUST match the value in pkg/consul/constants.go
	consulACLResetFilename = "acl-bootstrap-reset"

	// ConsulOptDir is the optional data directory
	// NOTE: Duplicates consul.ConsulOptDir to avoid circular import
	// This constant MUST match the value in pkg/consul/constants.go
	consulOptDir = "/opt/consul"

	// ConsulDataDir is the persistent data directory
	// NOTE: Duplicates consul.ConsulDataDir to avoid circular import
	// This constant MUST match the value in pkg/consul/constants.go
	consulDataDir = "/var/lib/consul"
)

// ResetConfig holds configuration for ACL bootstrap reset operation
type ResetConfig struct {
	// VaultClient is required for storing the new bootstrap token
	VaultClient *vaultapi.Client

	// Force skips confirmation prompts (for automation)
	Force bool

	// DryRun shows what would be done without making changes
	DryRun bool

	// DataDir is the user-provided Consul data directory override
	// If empty, auto-detection via multiple methods is attempted
	// If specified, this path is validated and used (highest priority)
	DataDir string
}

// ResetACLBootstrap performs ACL bootstrap reset and token recovery
//
// This function implements the official Consul ACL reset procedure using
// only the Consul Go SDK (no shell commands). It:
//
//  1. ASSESS: Checks if ACLs are already bootstrapped
//  2. ASSESS: Finds the cluster leader and determines reset index
//  3. ASSESS: Gets Consul data directory from running config
//  4. INTERVENE: Writes reset index file to data directory
//  5. INTERVENE: Re-bootstraps ACL system via SDK
//  6. INTERVENE: Stores new token in Vault
//  7. EVALUATE: Verifies token works and is retrievable from Vault
//
// Reference: https://developer.hashicorp.com/consul/docs/secure/acl/troubleshoot
//
// Parameters:
//   - rc: Runtime context for logging and cancellation
//   - config: Reset configuration including Vault client
//
// Returns:
//   - BootstrapResult with new token and metadata
//   - Error if reset fails
//
// Example:
//
//	config := &acl.ResetConfig{
//	    VaultClient: vaultClient,
//	    Force:       false,
//	    DryRun:      false,
//	}
//	result, err := acl.ResetACLBootstrap(rc, config)
//	if err != nil {
//	    return fmt.Errorf("failed to reset ACL bootstrap: %w", err)
//	}
//	logger.Info("Bootstrap token recovered", zap.String("accessor", result.Accessor))
func ResetACLBootstrap(rc *eos_io.RuntimeContext, config *ResetConfig) (*BootstrapResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul ACL bootstrap reset and token recovery")

	// Validate prerequisites
	if config.VaultClient == nil {
		return nil, eos_err.NewUserError(
			"Vault client is required for ACL bootstrap reset.\n\n" +
				"The bootstrap token must be stored securely in Vault.\n\n" +
				"Remediation:\n" +
				"  - Ensure Vault is installed: eos create vault\n" +
				"  - Ensure Vault is unsealed: vault status\n" +
				"  - Authenticate to Vault: vault login")
	}

	// ========================================================================
	// ASSESS - Check current ACL bootstrap state
	// ========================================================================

	logger.Info("Phase 1: ASSESS - Checking current ACL bootstrap state")

	// Create unauthenticated Consul client (we don't have a token yet)
	consulConfig := consulapi.DefaultConfig()
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w\n"+
			"Remediation:\n"+
			"  - Check Consul is running: systemctl status consul\n"+
			"  - Verify Consul API is accessible: curl http://localhost:8500/v1/status/leader",
			err)
	}

	// Try to bootstrap first - this tells us if it's already done
	logger.Info("Attempting initial bootstrap to determine state")
	bootstrapToken, _, bootstrapErr := consulClient.ACL().Bootstrap()

	if bootstrapErr == nil {
		// Bootstrap succeeded! ACLs were not bootstrapped yet
		logger.Info("ACL bootstrap succeeded - this was the first bootstrap",
			zap.String("accessor", bootstrapToken.AccessorID))

		// Store token in Vault immediately
		result := &BootstrapResult{
			MasterToken:   bootstrapToken.SecretID,
			Accessor:      bootstrapToken.AccessorID,
			AlreadyDone:   false,
			StoredInVault: false,
		}

		if !config.DryRun {
			if err := storeBootstrapTokenInVault(rc, config.VaultClient, result); err != nil {
				logger.Warn("Bootstrap succeeded but failed to store token in Vault",
					zap.Error(err),
					zap.String("note", "Token is available in result, but not persisted"))
				// Don't fail - token is still in result
			} else {
				result.StoredInVault = true
			}
		}

		logger.Info("First-time ACL bootstrap completed successfully")
		return result, nil
	}

	// Bootstrap failed - check if it's because already bootstrapped
	if !strings.Contains(bootstrapErr.Error(), "ACL bootstrap no longer allowed") &&
		!strings.Contains(bootstrapErr.Error(), "Permission denied") {
		// Some other error occurred
		return nil, fmt.Errorf("unexpected error during bootstrap check: %w\n"+
			"Remediation:\n"+
			"  - Check Consul logs: journalctl -u consul -n 50\n"+
			"  - Verify ACLs are enabled in /etc/consul.d/consul.hcl\n"+
			"  - Check Consul cluster health: consul members",
			bootstrapErr)
	}

	logger.Info("ACLs are already bootstrapped, reset is required")

	// ========================================================================
	// ASSESS - Extract reset index from error message
	// ========================================================================

	logger.Info("Extracting reset index from bootstrap error")

	resetIndex, err := extractResetIndex(bootstrapErr.Error())
	if err != nil {
		return nil, fmt.Errorf("failed to extract reset index from error: %w\n"+
			"Error message: %s\n"+
			"Remediation:\n"+
			"  - This may indicate Consul version incompatibility\n"+
			"  - Check Consul version: consul version\n"+
			"  - Ensure Consul >= 1.4.0 (reset feature introduced in 1.4)",
			err, bootstrapErr.Error())
	}

	logger.Info("Reset index detected",
		zap.Int("reset_index", resetIndex))

	// ========================================================================
	// ASSESS - Check if token already exists in Vault
	// ========================================================================

	logger.Info("Checking if bootstrap token already exists in Vault")

	existingToken, err := GetBootstrapTokenFromVault(rc, config.VaultClient)
	if err == nil && existingToken != "" {
		logger.Info("Bootstrap token found in Vault - no reset needed",
			zap.String("vault_path", "secret/consul/bootstrap-token"))

		// Verify token still works
		testConfig := consulapi.DefaultConfig()
		testConfig.Token = existingToken
		testClient, err := consulapi.NewClient(testConfig)
		if err != nil {
			logger.Warn("Failed to create test client with existing token", zap.Error(err))
		} else {
			selfToken, _, err := testClient.ACL().TokenReadSelf(nil)
			if err == nil && selfToken != nil {
				logger.Info("Existing token verified successfully",
					zap.String("accessor", selfToken.AccessorID))

				return &BootstrapResult{
					MasterToken:   existingToken,
					Accessor:      selfToken.AccessorID,
					AlreadyDone:   true,
					StoredInVault: true,
					VaultPath:     "secret/consul/bootstrap-token",
				}, nil
			}
			logger.Warn("Existing token in Vault is invalid, proceeding with reset",
				zap.Error(err))
		}
	} else {
		logger.Info("Bootstrap token not found in Vault or retrieval failed",
			zap.NamedError("vault_error", err))
	}

	// ========================================================================
	// ASSESS - Find cluster leader
	// ========================================================================

	logger.Info("Finding Consul cluster leader (reset must be performed on leader)")

	leaderAddr, err := consulClient.Status().Leader()
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster leader: %w\n"+
			"Remediation:\n"+
			"  - Check Consul cluster health: consul members\n"+
			"  - Verify this node is part of the cluster\n"+
			"  - Check network connectivity to other nodes",
			err)
	}

	if leaderAddr == "" {
		return nil, eos_err.NewUserError(
			"No cluster leader found\n\n" +
				"Consul cluster has no elected leader. ACL reset requires a healthy cluster.\n\n" +
				"Remediation:\n" +
				"  - Check cluster status: consul operator raft list-peers\n" +
				"  - Verify quorum: at least (n/2)+1 servers must be online\n" +
				"  - Check server logs: journalctl -u consul -n 100")
	}

	logger.Info("Cluster leader found",
		zap.String("leader", leaderAddr))

	// Note: We assume this node is the leader or can write to the leader's data dir
	// In a multi-node cluster, user may need to run this on the actual leader node
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ⚠️  ACL reset must be performed on the cluster leader")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Cluster leader: " + leaderAddr)
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: If this is not the leader, run this command on the leader node.")
	logger.Info("terminal prompt: ")

	// ========================================================================
	// ASSESS - Get Consul data directory (6-layer fallback)
	// ========================================================================

	logger.Info("Determining Consul data directory via multi-layer detection")

	dataDir, err := getConsulDataDir(rc, consulClient, config)
	if err != nil {
		return nil, err // Error already formatted by getConsulDataDir
	}

	logger.Info("Consul data directory identified",
		zap.String("data_dir", dataDir))

	resetFilePath := filepath.Join(dataDir, consulACLResetFilename)

	logger.Info("ACL reset file path determined",
		zap.String("reset_file", resetFilePath),
		zap.Int("reset_index", resetIndex))

	if config.DryRun {
		logger.Info("DRY RUN: Would write reset index to file",
			zap.String("file", resetFilePath),
			zap.Int("index", resetIndex))
		logger.Info("DRY RUN: Would re-bootstrap ACL system")
		logger.Info("DRY RUN: Would store new token in Vault")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: ✓ Dry run complete - no changes made")
		logger.Info("terminal prompt: ")
		return &BootstrapResult{
			AlreadyDone: true,
		}, nil
	}

	// ========================================================================
	// INTERVENE - Write reset index file
	// ========================================================================

	logger.Info("Phase 2: INTERVENE - Writing ACL bootstrap reset index file")

	resetIndexStr := fmt.Sprintf("%d", resetIndex)
	if err := os.WriteFile(resetFilePath, []byte(resetIndexStr), 0600); err != nil {
		return nil, fmt.Errorf("failed to write reset index file: %w\n"+
			"File: %s\n"+
			"Remediation:\n"+
			"  - Check file permissions on data directory: ls -la %s\n"+
			"  - Verify this process has write access\n"+
			"  - Ensure running as root or consul user",
			err, resetFilePath, dataDir)
	}

	logger.Info("Reset index file written successfully",
		zap.String("file", resetFilePath),
		zap.Int("index", resetIndex))

	// ========================================================================
	// INTERVENE - Re-bootstrap ACL system
	// ========================================================================

	logger.Info("Re-bootstrapping Consul ACL system via SDK")

	newBootstrapToken, _, err := consulClient.ACL().Bootstrap()
	if err != nil {
		// Clean up reset file on failure
		_ = os.Remove(resetFilePath)

		return nil, fmt.Errorf("failed to re-bootstrap ACL system: %w\n"+
			"Reset file was: %s\n"+
			"Remediation:\n"+
			"  - Check if this node is the cluster leader: consul operator raft list-peers\n"+
			"  - Verify reset index was correct: %d\n"+
			"  - Check Consul logs: journalctl -u consul -n 50\n"+
			"  - Try running again (reset file has been cleaned up)",
			err, resetFilePath, resetIndex)
	}

	logger.Info("ACL re-bootstrap successful",
		zap.String("accessor", newBootstrapToken.AccessorID),
		zap.String("note", "New bootstrap token generated"))

	// Clean up reset file after successful bootstrap
	if err := os.Remove(resetFilePath); err != nil {
		logger.Warn("Failed to remove reset file after successful bootstrap",
			zap.Error(err),
			zap.String("file", resetFilePath),
			zap.String("note", "This is non-fatal, file can be removed manually"))
	} else {
		logger.Debug("Reset file removed successfully")
	}

	result := &BootstrapResult{
		MasterToken:   newBootstrapToken.SecretID,
		Accessor:      newBootstrapToken.AccessorID,
		AlreadyDone:   false,
		StoredInVault: false,
	}

	// ========================================================================
	// INTERVENE - Store new token in Vault
	// ========================================================================

	logger.Info("Storing new bootstrap token in Vault for secure persistence")

	if err := storeBootstrapTokenInVault(rc, config.VaultClient, result); err != nil {
		logger.Error("Failed to store bootstrap token in Vault",
			zap.Error(err),
			zap.String("note", "Bootstrap succeeded, but token not persisted to Vault"))

		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: ⚠️  CRITICAL: Bootstrap token generated but NOT stored in Vault")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Bootstrap Token (save this securely):")
		logger.Info("terminal prompt: " + result.MasterToken)
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Accessor ID: " + result.Accessor)
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: To store manually in Vault:")
		logger.Info("terminal prompt:   vault kv put secret/consul/bootstrap-token token=" + result.MasterToken)
		logger.Info("terminal prompt: ")

		return result, fmt.Errorf("bootstrap succeeded but Vault storage failed: %w", err)
	}

	result.StoredInVault = true
	result.VaultPath = "secret/consul/bootstrap-token"

	// ========================================================================
	// EVALUATE - Verify token works
	// ========================================================================

	logger.Info("Phase 3: EVALUATE - Verifying new bootstrap token")

	testConfig := consulapi.DefaultConfig()
	testConfig.Token = result.MasterToken
	testClient, err := consulapi.NewClient(testConfig)
	if err != nil {
		logger.Warn("Failed to create test client for verification",
			zap.Error(err),
			zap.String("note", "Token may still be valid, verification failed"))
	} else {
		selfToken, _, err := testClient.ACL().TokenReadSelf(nil)
		if err != nil {
			logger.Warn("Failed to verify bootstrap token with Consul",
				zap.Error(err))
		} else {
			logger.Info("Bootstrap token verified successfully",
				zap.String("accessor", selfToken.AccessorID),
				zap.Int("policy_count", len(selfToken.Policies)))

			// Check for global-management policy
			hasGlobalManagement := false
			for _, policy := range selfToken.Policies {
				if policy.Name == "global-management" {
					hasGlobalManagement = true
					break
				}
			}

			if hasGlobalManagement {
				logger.Info("Token has global-management policy ✓")
			} else {
				logger.Warn("Token does not have global-management policy",
					zap.String("note", "This may not be the true bootstrap token"))
			}
		}
	}

	// Verify token is retrievable from Vault
	retrievedToken, err := GetBootstrapTokenFromVault(rc, config.VaultClient)
	if err != nil {
		logger.Warn("Failed to retrieve token from Vault for verification",
			zap.Error(err))
	} else if retrievedToken != result.MasterToken {
		logger.Warn("Retrieved token from Vault does not match generated token",
			zap.String("note", "This indicates a Vault storage issue"))
	} else {
		logger.Info("Token verified in Vault ✓")
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ ACL bootstrap reset completed successfully")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Bootstrap token stored in Vault at: secret/consul/bootstrap-token")
	logger.Info("terminal prompt: Token Accessor: " + result.Accessor)
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: You can now run 'eos sync --vault --consul' to complete Vault-Consul integration.")
	logger.Info("terminal prompt: ")

	return result, nil
}

// getConsulDataDir determines the Consul data directory using a 6-layer fallback strategy.
//
// This function implements defense-in-depth for data directory discovery, especially
// critical during ACL bootstrap token recovery when API access may be unavailable.
//
// Fallback layers (in priority order):
//  1. User-provided --data-dir flag (highest priority, manual override)
//  2. Running process inspection (ps aux, systemd service file)
//  3. Config file parsing (/etc/consul.d/*.hcl, *.json)
//  4. Consul API query (may fail with 403 if ACLs locked down)
//  5. Well-known paths (/opt/consul, /var/lib/consul)
//  6. Actionable error guidance (all methods exhausted)
//
// Each layer validates the discovered path contains a valid Consul data directory
// (must have raft/ subdirectory) before accepting it.
//
// Parameters:
//   - rc: Runtime context
//   - client: Consul API client (unauthenticated, may fail)
//   - resetConfig: Reset configuration including optional DataDir override
//
// Returns:
//   - string: Validated Consul data directory path
//   - error: If all detection methods fail (with actionable guidance)
func getConsulDataDir(rc *eos_io.RuntimeContext, client *consulapi.Client, resetConfig *ResetConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var detectionErrors []error

	// ========================================================================
	// Layer 1: User-provided --data-dir flag (HIGHEST PRIORITY)
	// ========================================================================

	if resetConfig.DataDir != "" {
		logger.Info("Using user-provided data directory",
			zap.String("data_dir", resetConfig.DataDir))

		if err := validation.ValidateConsulDataDir(rc, resetConfig.DataDir); err != nil {
			// User explicitly provided path, but it's invalid - fail with clear error
			return "", createDataDirValidationError(resetConfig.DataDir, err)
		}

		logger.Info("User-provided data directory validated successfully",
			zap.String("data_dir", resetConfig.DataDir))
		return resetConfig.DataDir, nil
	}

	logger.Debug("No user-provided data directory, attempting auto-detection")

	// ========================================================================
	// Layer 2: Running process inspection (no auth required, high reliability)
	// ========================================================================

	logger.Debug("Attempting data directory extraction from running process")

	processDataDir, err := process.GetDataDirFromRunningProcess(rc)
	if err == nil {
		if err := validation.ValidateConsulDataDir(rc, processDataDir); err == nil {
			logger.Info("Data directory extracted from running process",
				zap.String("data_dir", processDataDir),
				zap.String("method", "process_inspection"))
			return processDataDir, nil
		} else {
			detectionErrors = append(detectionErrors,
				fmt.Errorf("process inspection returned invalid path: %w", err))
		}
	} else {
		detectionErrors = append(detectionErrors,
			fmt.Errorf("process inspection failed: %w", err))
	}

	// ========================================================================
	// Layer 3: Config file parsing (no auth required, filesystem-based)
	// ========================================================================

	logger.Debug("Attempting data directory extraction from config files")

	configDataDir, err := config.ParseDataDirFromConfigFile(rc, nil) // nil = use defaults
	if err == nil {
		if err := validation.ValidateConsulDataDir(rc, configDataDir); err == nil {
			logger.Info("Data directory extracted from config file",
				zap.String("data_dir", configDataDir),
				zap.String("method", "config_file_parsing"))
			return configDataDir, nil
		} else {
			detectionErrors = append(detectionErrors,
				fmt.Errorf("config file parsing returned invalid path: %w", err))
		}
	} else {
		detectionErrors = append(detectionErrors,
			fmt.Errorf("config file parsing failed: %w", err))
	}

	// ========================================================================
	// Layer 4: Consul API query (may fail with 403 - that's expected)
	// ========================================================================

	logger.Debug("Attempting data directory extraction from Consul API")

	agentSelf, err := client.Agent().Self()
	if err == nil {
		if configMap, ok := agentSelf["Config"]; ok {
			if apiDataDir, ok := configMap["DataDir"].(string); ok && apiDataDir != "" {
				if err := validation.ValidateConsulDataDir(rc, apiDataDir); err == nil {
					logger.Info("Data directory extracted from Consul API",
						zap.String("data_dir", apiDataDir),
						zap.String("method", "api_query"))
					return apiDataDir, nil
				} else {
					detectionErrors = append(detectionErrors,
						fmt.Errorf("API query returned invalid path: %w", err))
				}
			} else {
				detectionErrors = append(detectionErrors,
					fmt.Errorf("API query succeeded but DataDir not found in response"))
			}
		} else {
			detectionErrors = append(detectionErrors,
				fmt.Errorf("API query succeeded but Config section missing"))
		}
	} else {
		// API failure is EXPECTED when ACLs are locked down (403)
		apiErr := createAPIAccessError(err)
		logger.Debug("Consul API query failed (expected during ACL recovery)",
			zap.Error(apiErr))
		detectionErrors = append(detectionErrors, apiErr)
	}

	// ========================================================================
	// Layer 5: Well-known paths (validate they contain Raft data)
	// ========================================================================

	logger.Debug("Attempting data directory detection from well-known paths")

	knownPaths := []string{
		consulOptDir,       // /opt/consul (Eos default)
		consulDataDir,      // /var/lib/consul (Consul default)
		"/var/consul/data", // Alternative location
	}

	for _, knownPath := range knownPaths {
		logger.Debug("Checking well-known path", zap.String("path", knownPath))

		if err := validation.ValidateConsulDataDir(rc, knownPath); err == nil {
			logger.Warn("Using well-known path fallback (auto-detection methods failed)",
				zap.String("data_dir", knownPath),
				zap.String("method", "well_known_paths"),
				zap.String("note", "Consider specifying --data-dir explicitly"))
			return knownPath, nil
		} else {
			logger.Debug("Well-known path validation failed",
				zap.String("path", knownPath),
				zap.Error(err))
		}
	}

	detectionErrors = append(detectionErrors,
		fmt.Errorf("no well-known paths contain valid Consul data directory"))

	// ========================================================================
	// Layer 6: All fallbacks exhausted - provide actionable guidance
	// ========================================================================

	logger.Error("All data directory detection methods failed",
		zap.Int("methods_attempted", len(detectionErrors)))

	return "", createDataDirNotFoundError(detectionErrors)
}

// extractResetIndex parses the reset index from Consul bootstrap error message
//
// Example error messages:
// - "Permission denied: ACL bootstrap no longer allowed (reset index: 13)"
// - "ACL bootstrap no longer allowed (reset index: 1)"
func extractResetIndex(errorMsg string) (int, error) {
	// Use regex to extract reset index number
	re := regexp.MustCompile(`reset index:\s*(\d+)`)
	matches := re.FindStringSubmatch(errorMsg)

	if len(matches) < 2 {
		return 0, fmt.Errorf("reset index not found in error message")
	}

	var resetIndex int
	_, err := fmt.Sscanf(matches[1], "%d", &resetIndex)
	if err != nil {
		return 0, fmt.Errorf("failed to parse reset index: %w", err)
	}

	return resetIndex, nil
}

// storeBootstrapTokenInVault stores the bootstrap token in Vault
func storeBootstrapTokenInVault(rc *eos_io.RuntimeContext, vaultClient *vaultapi.Client, result *BootstrapResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	vaultPath := "secret/consul/bootstrap-token"

	data := map[string]interface{}{
		"token":          result.MasterToken,
		"accessor":       result.Accessor,
		"description":    "Consul ACL bootstrap token (global-management)",
		"created_by":     "eos update consul --bootstrap-token",
		"policies":       []string{"global-management"},
		"warning":        "This is the Consul master token - protect it carefully!",
		"recovery_steps": "To retrieve: vault kv get -field=token secret/consul/bootstrap-token",
	}

	_, err := vaultClient.KVv2("secret").Put(rc.Ctx, "consul/bootstrap-token", data)
	if err != nil {
		return fmt.Errorf("failed to store bootstrap token in Vault: %w\n"+
			"Vault path: %s\n"+
			"Remediation:\n"+
			"  - Check Vault is unsealed: vault status\n"+
			"  - Verify Vault token has write permissions to secret/consul/*\n"+
			"  - Check Vault logs: journalctl -u vault -n 50",
			err, vaultPath)
	}

	logger.Info("Bootstrap token stored in Vault successfully",
		zap.String("vault_path", vaultPath))

	return nil
}
