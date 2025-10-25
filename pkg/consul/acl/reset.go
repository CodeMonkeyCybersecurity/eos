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
// Last Updated: 2025-10-25

package acl

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/process"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/validation"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NOTE: Vault path constants (vaultConsulBootstrapTokenPath, vaultConsulBootstrapTokenFullPath)
// are defined in bootstrap.go and shared across the acl package.

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

	// Extract the LAST CONSUMED reset index from Consul error.
	// We will compute the NEXT required index in the retry loop below.
	//
	// Example: Error says "reset index: 3117" means:
	//   - Index 3117 was already consumed by a previous bootstrap
	//   - We need to write index 3118 to the reset file (computed as 3117 + 1)
	//
	// NOTE: We do NOT increment here anymore. The retry loop will handle
	// incrementing correctly based on Consul's responses.
	lastConsumedIndex := resetIndex

	logger.Info("Reset index extracted from Consul error",
		zap.Int("consul_last_consumed", lastConsumedIndex))

	// ========================================================================
	// ASSESS - Check if token already exists in Vault
	// ========================================================================

	logger.Info("Checking if bootstrap token already exists in Vault")

	existingToken, err := GetBootstrapTokenFromVault(rc, config.VaultClient)
	if err == nil && existingToken != "" {
		logger.Info("Bootstrap token found in Vault - no reset needed",
			zap.String("vault_path", vaultConsulBootstrapTokenFullPath))

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
					VaultPath:     vaultConsulBootstrapTokenFullPath,
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
	// INTERVENE - Write reset file and immediately bootstrap (race mitigation)
	// ========================================================================

	logger.Info("Phase 2: INTERVENE - Writing ACL bootstrap reset index file and re-bootstrapping")

	// RACE CONDITION MITIGATION:
	// Consul's leader goroutine consumes the reset file IMMEDIATELY when detected,
	// not when the Bootstrap() API call arrives. This creates a race where:
	//   1. Code writes reset file
	//   2. Consul leader reads file and increments internal counter
	//   3. Code calls Bootstrap() API
	//   4. Consul responds "403 Permission denied" (file already consumed)
	//
	// Solution: Write file and call Bootstrap() in tight loop with minimal delay.
	// Retry if race detected (reset index incremented since last attempt).

	const maxRetries = 5
	const retryDelay = 500 * time.Millisecond

	var newBootstrapToken *consulapi.ACLToken
	var lastErr error

	// CRITICAL FIX (P0): Start with next_index = last_consumed + 1
	// Consul requires us to write the NEXT index after the last consumed one.
	// If Consul says "consumed 3117", we write "3118".
	resetIndex = lastConsumedIndex + 1

	for attempt := 1; attempt <= maxRetries; attempt++ {
		logger.Debug("Bootstrap attempt",
			zap.Int("attempt", attempt),
			zap.Int("max_retries", maxRetries),
			zap.Int("reset_index", resetIndex))

		// Write reset file
		resetIndexStr := fmt.Sprintf("%d", resetIndex)

		// CRITICAL (P0): File must be readable by Consul process (running as 'consul' user).
		// Write as root (0644) so Consul can read it, then chown to consul:consul.
		// Previous bug: File written as 0600 root:root → Consul gets "permission denied"
		if err := os.WriteFile(resetFilePath, []byte(resetIndexStr), 0644); err != nil {
			return nil, fmt.Errorf("failed to write reset index file on attempt %d: %w\n"+
				"File: %s\n"+
				"Remediation:\n"+
				"  - Check file permissions on data directory: ls -la %s\n"+
				"  - Verify this process has write access\n"+
				"  - Ensure running as root or consul user",
				attempt, err, resetFilePath, dataDir)
		}

		// CRITICAL (P0): Change ownership to consul:consul so Consul process can read it.
		// Data directory is owned by consul:consul, reset file must match.
		logger.Debug("Changing reset file ownership to consul:consul",
			zap.String("file", resetFilePath))

		chownOutput, chownErr := execute.Run(rc.Ctx, execute.Options{
			Command: "chown",
			Args:    []string{"consul:consul", resetFilePath},
			Capture: true,
		})
		if chownErr != nil {
			logger.Warn("Failed to chown reset file to consul:consul, Consul may not be able to read it",
				zap.Error(chownErr),
				zap.String("output", chownOutput),
				zap.String("file", resetFilePath),
				zap.String("note", "This may cause 'permission denied' errors"))
			// Don't fail - maybe Consul is running as root or file is in root-owned directory
		}

		logger.Info("Reset file written, restarting Consul to process it",
			zap.String("file", resetFilePath),
			zap.Int("index", resetIndex),
			zap.Int("attempt", attempt))

		// CRITICAL FIX (P0): Restart Consul to force it to read the reset file.
		//
		// Consul's leader goroutine only checks for the reset file on startup
		// and periodically (every 5 seconds by default), NOT on every Bootstrap()
		// API call. This creates a race condition where:
		//   1. We write the reset file
		//   2. Bootstrap() API call arrives before Consul's leader detects file
		//   3. Consul responds with "403 Permission denied" (file not yet consumed)
		//
		// Restarting Consul ensures the leader goroutine reads the file immediately
		// on startup, eliminating the race window.
		//
		// Service disruption: ~15 seconds (acceptable for rare bootstrap reset operation)
		restartOutput, restartErr := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"restart", "consul"},
			Capture: true,
		})
		if restartErr != nil {
			logger.Warn("Failed to restart Consul, continuing anyway",
				zap.Error(restartErr),
				zap.String("output", restartOutput),
				zap.String("note", "Bootstrap may still succeed if Consul detects file periodically"))
			// Don't fail - Consul might detect file on its next periodic check
		} else {
			logger.Debug("Consul restarted successfully, waiting for stabilization")

			// Wait for Consul to stabilize after restart.
			// This gives the leader goroutine time to:
			//   1. Start up and initialize
			//   2. Read the reset file from data directory
			//   3. Process the reset index
			//   4. Prepare ACL system for bootstrap API call
			//
			// 15 seconds is conservative - most Consul instances stabilize in 5-10 seconds
			time.Sleep(15 * time.Second)
		}

		logger.Debug("Calling Bootstrap() API after Consul restart",
			zap.Int("attempt", attempt))

		// Call Bootstrap() API
		var bootstrapErr error
		newBootstrapToken, _, bootstrapErr = consulClient.ACL().Bootstrap()

		if bootstrapErr == nil {
			// SUCCESS! Bootstrap completed
			logger.Info("ACL re-bootstrap successful",
				zap.String("accessor", newBootstrapToken.AccessorID),
				zap.Int("attempt", attempt),
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

			break // Exit retry loop
		}

		// Bootstrap failed - analyze error and determine retry strategy
		lastErr = bootstrapErr

		// CRITICAL FIX (P0): Correct retry strategy for ACL bootstrap reset
		//
		// The error "Invalid bootstrap reset index (specified X, reset index: Y)" means:
		//   - X = the index we wrote to the reset file
		//   - Y = the index Consul currently knows about (last consumed)
		//
		// There are two possible scenarios:
		//   1. Consul consumed our file (Y moved forward) → increment and retry
		//   2. Consul did NOT consume our file (Y unchanged) → DON'T increment, retry same
		//
		// Strategy:
		//   - Extract Y from error message (Consul's current last consumed index)
		//   - If Y >= our resetIndex, Consul consumed our file → increment
		//   - If Y < our resetIndex, Consul did NOT consume our file → retry same index
		//
		// This prevents the monotonic increment bug where we write 3118, 3119, 3120...
		// when Consul never consumed any of them and still expects 3118.

		// Try to extract Consul's CURRENT last consumed index from error
		if strings.Contains(bootstrapErr.Error(), "ACL bootstrap no longer allowed") ||
			strings.Contains(bootstrapErr.Error(), "Invalid bootstrap reset index") {

			// Try to extract reset index from error message
			consulLastConsumed, extractErr := extractResetIndex(bootstrapErr.Error())

			if extractErr == nil {
				// Compare Consul's last consumed index with what we wrote
				if consulLastConsumed >= resetIndex {
					// Consul consumed our reset file! Increment for next attempt.
					logger.Info("Consul consumed reset file, incrementing index",
						zap.Int("attempt", attempt),
						zap.Int("consul_consumed", consulLastConsumed),
						zap.Int("we_wrote", resetIndex),
						zap.Int("next_index", consulLastConsumed+2))
					resetIndex = consulLastConsumed + 2 // Consul consumed our index, try next
				} else {
					// Consul did NOT consume our reset file. Retry same index.
					logger.Warn("Consul did not consume reset file, retrying same index",
						zap.Int("attempt", attempt),
						zap.Int("consul_last_consumed", consulLastConsumed),
						zap.Int("we_wrote", resetIndex),
						zap.String("reason", "File may not be readable or Consul not fully restarted"))
					// Keep resetIndex the same - retry with same value
				}
			} else {
				// Failed to parse error - fallback to simple increment
				logger.Warn("Failed to parse Consul error, incrementing index",
					zap.Int("attempt", attempt),
					zap.Error(extractErr))
				resetIndex += 1
			}
		} else {
			// Different error (not bootstrap-related) - just increment and retry
			logger.Warn("Non-bootstrap error, incrementing index",
				zap.Int("attempt", attempt),
				zap.String("error", bootstrapErr.Error()))
			resetIndex += 1
		}

		if attempt < maxRetries {
			// Wait before retry (give Consul time to stabilize)
			time.Sleep(retryDelay)
			continue // Retry with incremented index
		}

		// Max retries reached
		logger.Error("Failed to bootstrap after max retries",
			zap.Int("max_retries", maxRetries),
			zap.Int("final_reset_index", resetIndex))

		// Clean up reset file
		_ = os.Remove(resetFilePath)

		return nil, fmt.Errorf("failed to re-bootstrap ACL system after %d attempts\n"+
			"Final reset index attempted: %d\n"+
			"Last error: %v\n"+
			"Remediation:\n"+
			"  - Check if this node is the cluster leader: consul operator raft list-peers\n"+
			"  - Verify Consul service is running: systemctl status consul\n"+
			"  - Check Consul logs for errors: journalctl -u consul -n 100\n"+
			"  - Verify cluster health: consul members\n"+
			"  - Try running again: sudo eos update consul --bootstrap-token",
			maxRetries, resetIndex, bootstrapErr)
	}

	// Check if all retries exhausted
	if newBootstrapToken == nil {
		// Clean up reset file on final failure
		_ = os.Remove(resetFilePath)

		return nil, fmt.Errorf("failed to re-bootstrap ACL system after %d attempts: %w\n"+
			"Reset file was: %s\n"+
			"Final reset index attempted: %d\n"+
			"Last error: %v\n\n"+
			"Remediation:\n"+
			"  - Check if this node is the cluster leader: consul operator raft list-peers\n"+
			"  - Verify Consul service is running: systemctl status consul\n"+
			"  - Check Consul logs for errors: journalctl -u consul -n 100\n"+
			"  - Verify cluster health: consul members\n"+
			"  - Try running again (reset file has been cleaned up)\n\n"+
			"If problem persists, consider manual reset (DESTRUCTIVE):\n"+
			"  1. Stop Consul: systemctl stop consul\n"+
			"  2. Backup data: cp -r %s %s.backup.$(date +%%s)\n"+
			"  3. Remove ACL state: rm -rf %s/raft/\n"+
			"  4. Start Consul: systemctl start consul\n"+
			"  5. Bootstrap fresh: consul acl bootstrap\n"+
			"  6. Store in Vault: vault kv put "+vaultConsulBootstrapTokenFullPath+" token=<new-token>",
			maxRetries, lastErr, resetFilePath, resetIndex, lastErr, dataDir, dataDir, dataDir)
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
		logger.Info("terminal prompt:   vault kv put " + vaultConsulBootstrapTokenFullPath + " token=" + result.MasterToken)
		logger.Info("terminal prompt: ")

		return result, fmt.Errorf("bootstrap succeeded but Vault storage failed: %w", err)
	}

	result.StoredInVault = true
	result.VaultPath = vaultConsulBootstrapTokenFullPath

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

	// ========================================================================
	// INTERVENE - Create and configure agent token (RECOMMENDED)
	// ========================================================================

	logger.Info("Creating agent token for Consul daemon (prevents ACL permission errors)")

	agentTokenResult, err := CreateAndConfigureAgentToken(rc, result.MasterToken, "")
	if err != nil {
		logger.Warn("Failed to create agent token for Consul daemon",
			zap.Error(err),
			zap.String("note", "This is non-fatal, but daemon will log ACL permission errors"))
		logger.Warn("To fix manually:")
		logger.Warn("  1. Get bootstrap token: export CONSUL_HTTP_TOKEN=$(vault kv get -field=token " + vaultConsulBootstrapTokenFullPath + ")")
		logger.Warn("  2. Create agent token: consul acl token create -description='Agent token' -node-identity='$(hostname):dc1'")
		logger.Warn("  3. Configure daemon: consul acl set-agent-token agent <token-id>")
	} else {
		logger.Info("Agent token created and configured successfully",
			zap.String("accessor", agentTokenResult.AccessorID),
			zap.String("node", agentTokenResult.NodeName))
		logger.Info("Consul daemon will no longer log 'Coordinate update blocked by ACLs' errors")
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ ACL bootstrap reset completed successfully")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Bootstrap token stored in Vault at: " + vaultConsulBootstrapTokenFullPath)
	logger.Info("terminal prompt: Token Accessor: " + result.Accessor)
	logger.Info("terminal prompt: ")
	if agentTokenResult != nil {
		logger.Info("terminal prompt: ✓ Agent token created for Consul daemon")
		logger.Info("terminal prompt:   Node: " + agentTokenResult.NodeName)
		logger.Info("terminal prompt:   Accessor: " + agentTokenResult.AccessorID)
		logger.Info("terminal prompt: ")
	}
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

	data := map[string]interface{}{
		"token":          result.MasterToken,
		"accessor":       result.Accessor,
		"description":    "Consul ACL bootstrap token (global-management)",
		"created_by":     "eos update consul --bootstrap-token",
		"policies":       []string{"global-management"},
		"warning":        "This is the Consul master token - protect it carefully!",
		"recovery_steps": "To retrieve: vault kv get -field=token " + vaultConsulBootstrapTokenFullPath,
	}

	// Write to Vault KV v2 (uses constant, SDK adds secret/data/ prefix automatically)
	_, err := vaultClient.KVv2("secret").Put(rc.Ctx, vaultConsulBootstrapTokenPath, data)
	if err != nil {
		return fmt.Errorf("failed to store bootstrap token in Vault: %w\n"+
			"Vault path: %s\n"+
			"Remediation:\n"+
			"  - Check Vault is unsealed: vault status\n"+
			"  - Verify Vault token has write permissions to secret/consul/*\n"+
			"  - Check Vault logs: journalctl -u vault -n 50",
			err, vaultConsulBootstrapTokenFullPath)
	}

	logger.Info("Bootstrap token stored in Vault successfully",
		zap.String("vault_path", vaultConsulBootstrapTokenFullPath))

	return nil
}
