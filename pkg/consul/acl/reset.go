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
)

// ResetConfig holds configuration for ACL bootstrap reset operation
type ResetConfig struct {
	// VaultClient is required for storing the new bootstrap token
	VaultClient *vaultapi.Client

	// Force skips confirmation prompts (for automation)
	Force bool

	// DryRun shows what would be done without making changes
	DryRun bool
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
	// ASSESS - Get Consul data directory from running config
	// ========================================================================

	logger.Info("Determining Consul data directory from running configuration")

	dataDir, err := getConsulDataDir(rc, consulClient)
	if err != nil {
		return nil, fmt.Errorf("failed to determine Consul data directory: %w", err)
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

// getConsulDataDir retrieves the Consul data directory from the running configuration
func getConsulDataDir(rc *eos_io.RuntimeContext, client *consulapi.Client) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Retrieving Consul agent configuration to determine data directory")

	// Get agent self information which includes configuration
	agentSelf, err := client.Agent().Self()
	if err != nil {
		return "", fmt.Errorf("failed to get agent configuration: %w", err)
	}

	// Extract data directory from config
	// The structure is: agentSelf["Config"]["DataDir"]
	configMap, ok := agentSelf["Config"]
	if !ok {
		return "", fmt.Errorf("no Config section in agent self response")
	}

	dataDir, ok := configMap["DataDir"].(string)
	if !ok || dataDir == "" {
		return "", fmt.Errorf("DataDir not found in agent configuration")
	}

	// Verify directory exists
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		return "", fmt.Errorf("data directory does not exist: %s", dataDir)
	}

	logger.Debug("Data directory retrieved from agent config",
		zap.String("data_dir", dataDir))

	return dataDir, nil
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
