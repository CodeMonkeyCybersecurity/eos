// pkg/consul/acl/bootstrap.go
//
// Consul ACL Bootstrap and Management
//
// This package provides helpers for managing Consul ACL system:
// - Bootstrapping ACLs for first-time setup
// - Creating management tokens for Vault
// - Storing bootstrap tokens securely in Vault
//
// Part of Consul + Vault integration (Phase 1 implementation)

package acl

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	sharedvault "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ============================================================================
// Vault Path Functions
// ============================================================================
// NOTE: Path functions are defined in reset.go and shared across the acl package.
// They use environment-aware paths from pkg/shared/vault to support multi-environment deployments.
//
// Functions available:
// - getConsulBootstrapTokenPath(env) - Returns KV v2 path without secret/data/ prefix
// - getConsulBootstrapTokenFullPath(env) - Returns full path with secret/data/ prefix

// BootstrapResult contains the result of ACL bootstrap operation
type BootstrapResult struct {
	MasterToken   string    // The bootstrap/master token (global-management)
	Accessor      string    // Token accessor ID
	AlreadyDone   bool      // True if ACLs were already bootstrapped
	BootstrapTime time.Time // When bootstrap occurred
	StoredInVault bool      // True if token was stored in Vault
	VaultPath     string    // Path where token is stored in Vault
}

// BootstrapConsulACLs initializes the Consul ACL system
//
// This function:
// 1. Checks if ACLs are already bootstrapped
// 2. If not, performs ACL bootstrap (creates master token)
// 3. Optionally stores master token in Vault for safekeeping
//
// Parameters:
//   - rc: Runtime context for logging and cancellation
//   - consulClient: Consul API client (must have permissions to bootstrap)
//   - vaultClient: Optional Vault client to store bootstrap token (can be nil)
//   - storeInVault: If true, stores master token in Vault at secret/consul/bootstrap-token
//
// Returns:
//   - BootstrapResult with master token and metadata
//   - Error if bootstrap fails
//
// Example:
//
//	result, err := acl.BootstrapConsulACLs(rc, consulClient, vaultClient, true)
//	if err != nil {
//	    return fmt.Errorf("failed to bootstrap Consul ACLs: %w", err)
//	}
//	if result.AlreadyDone {
//	    logger.Info("Consul ACLs already bootstrapped")
//	} else {
//	    logger.Info("Consul ACLs bootstrapped successfully",
//	        zap.String("master_token", result.MasterToken))
//	}
func BootstrapConsulACLs(
	rc *eos_io.RuntimeContext,
	consulClient *consulapi.Client,
	vaultClient *vaultapi.Client,
	env sharedvault.Environment,
	storeInVault bool,
) (*BootstrapResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Bootstrapping Consul ACL system")

	// ASSESS - Check if already bootstrapped
	logger.Debug("Checking if Consul ACLs are already bootstrapped")

	// Attempt bootstrap - this will fail if already done
	bootstrapToken, _, err := consulClient.ACL().Bootstrap()

	if err != nil {
		// Check if error is because already bootstrapped
		// P0 FIX: Use strings.Contains() instead of exact match to handle ANY reset index
		// Reset index can be 1, 3117, or any number depending on how many operations occurred
		errMsg := err.Error()
		if strings.Contains(errMsg, "ACL bootstrap no longer allowed") ||
			strings.Contains(errMsg, "ACL system already initialized") {

			logger.Info("Consul ACLs already bootstrapped",
				zap.String("note", "This is expected if ACLs were previously initialized"))

			return &BootstrapResult{
				AlreadyDone: true,
			}, nil
		}

		// Some other error occurred
		return nil, fmt.Errorf("failed to bootstrap Consul ACLs: %w\n"+
			"Remediation:\n"+
			"  - Check Consul logs: journalctl -u consul -n 50\n"+
			"  - Verify Consul is running: consul members\n"+
			"  - Check ACL configuration in /etc/consul.d/consul.hcl",
			err)
	}

	// INTERVENE - Bootstrap succeeded, we have a master token
	logger.Info("Consul ACL bootstrap successful",
		zap.String("accessor", bootstrapToken.AccessorID),
		zap.String("note", "Master token has global-management permissions"))

	result := &BootstrapResult{
		MasterToken:   bootstrapToken.SecretID,
		Accessor:      bootstrapToken.AccessorID,
		AlreadyDone:   false,
		BootstrapTime: time.Now(),
		StoredInVault: false,
	}

	// INTERVENE - Store master token in Vault (if requested and client provided)
	if storeInVault && vaultClient != nil {
		logger.Info("Storing Consul master token in Vault",
			zap.String("environment", string(env)))

		// Get environment-aware paths
		kvPath := getConsulBootstrapTokenPath(env)
		fullPath := getConsulBootstrapTokenFullPath(env)

		data := map[string]interface{}{
			"token":          bootstrapToken.SecretID,
			"accessor":       bootstrapToken.AccessorID,
			"description":    bootstrapToken.Description,
			"created_at":     time.Now().Format(time.RFC3339),
			"policies":       []string{"global-management"},
			"environment":    string(env),
			"warning":        "This is the Consul master token - protect it carefully!",
			"recovery_steps": "To retrieve: vault kv get -field=token " + fullPath,
		}

		// Write to Vault KV v2 (secret/)
		// Path uses environment-aware KVv2 SDK path (automatically adds secret/data/ prefix)
		_, err := vaultClient.KVv2("secret").Put(rc.Ctx, kvPath, data)
		if err != nil {
			logger.Warn("Failed to store bootstrap token in Vault",
				zap.Error(err),
				zap.String("note", "Token is still available in memory, but not persisted"))
			// Don't fail - bootstrap succeeded, just storage failed
		} else {
			logger.Info("Consul master token stored in Vault",
				zap.String("vault_path", fullPath),
				zap.String("environment", string(env)))
			result.StoredInVault = true
			result.VaultPath = fullPath
		}
	}

	// EVALUATE - Verify token works
	logger.Info("Verifying bootstrap token has correct permissions")

	// Create a new client with the bootstrap token to test
	testConfig := consulapi.DefaultConfig()
	testConfig.Token = result.MasterToken
	testClient, err := consulapi.NewClient(testConfig)
	if err != nil {
		logger.Warn("Failed to create test client for verification",
			zap.Error(err))
	} else {
		// Try to read ACL system status (requires ACL read permissions)
		_, _, err = testClient.ACL().TokenReadSelf(nil)
		if err != nil {
			logger.Warn("Failed to verify bootstrap token",
				zap.Error(err),
				zap.String("note", "Token may still be valid, verification failed"))
		} else {
			logger.Info("Bootstrap token verified successfully")
		}
	}

	logger.Info("Consul ACL bootstrap complete",
		zap.Bool("stored_in_vault", result.StoredInVault))

	return result, nil
}

// GetBootstrapTokenFromVault retrieves the Consul bootstrap token from Vault
//
// Parameters:
//   - rc: Runtime context
//   - vaultClient: Authenticated Vault client
//
// Returns:
//   - Token string
//   - Error if retrieval fails
//
// Example:
//
//	token, err := acl.GetBootstrapTokenFromVault(rc, vaultClient)
//	if err != nil {
//	    return fmt.Errorf("failed to retrieve Consul bootstrap token: %w", err)
//	}
//	consulClient.SetToken(token)
func GetBootstrapTokenFromVault(rc *eos_io.RuntimeContext, vaultClient *vaultapi.Client, env sharedvault.Environment) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Retrieving Consul bootstrap token from Vault",
		zap.String("environment", string(env)))

	// Get environment-aware paths
	kvPath := getConsulBootstrapTokenPath(env)
	fullPath := getConsulBootstrapTokenFullPath(env)

	// Read from Vault KV v2 (uses environment-aware path, SDK adds secret/data/ prefix automatically)
	secret, err := vaultClient.KVv2("secret").Get(rc.Ctx, kvPath)
	if err != nil {
		return "", fmt.Errorf("failed to read Consul bootstrap token from Vault: %w\n"+
			"Vault path: %s\n"+
			"Environment: %s\n"+
			"Remediation:\n"+
			"  - Check Vault is unsealed: vault status\n"+
			"  - Verify secret exists: vault kv get %s\n"+
			"  - Check Vault token has read permissions to secret/data/services/%s/consul/*",
			err, fullPath, env, fullPath, env)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("Consul bootstrap token not found in Vault at %s", fullPath)
	}

	token, ok := secret.Data["token"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token format in Vault (expected string)")
	}

	logger.Info("Retrieved Consul bootstrap token from Vault",
		zap.String("vault_path", fullPath),
		zap.String("environment", string(env)))

	return token, nil
}

// PromptAndStoreBootstrapToken prompts user for existing bootstrap token and stores it in Vault
//
// This function is used when:
//  1. Consul ACLs are already bootstrapped (can't bootstrap again)
//  2. Bootstrap token is NOT in Vault (can't retrieve it)
//  3. Need the token to continue with Vault-Consul integration
//
// Parameters:
//   - rc: Runtime context
//   - vaultClient: Authenticated Vault client
//
// Returns:
//   - BootstrapResult with the token and metadata
//   - Error if user doesn't provide token or storage fails
//
// Example:
//
//	result, err := acl.PromptAndStoreBootstrapToken(rc, vaultClient)
//	if err != nil {
//	    return fmt.Errorf("failed to recover bootstrap token: %w", err)
//	}
//	consulClient.SetToken(result.MasterToken)
func PromptAndStoreBootstrapToken(
	rc *eos_io.RuntimeContext,
	vaultClient *vaultapi.Client,
	env sharedvault.Environment,
) (*BootstrapResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get environment-aware paths
	fullPath := getConsulBootstrapTokenFullPath(env)

	logger.Info("Consul ACLs already bootstrapped, but token not found in Vault")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: CONSUL BOOTSTRAP TOKEN REQUIRED")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Your Consul ACLs are already initialized, but the bootstrap token")
	logger.Info("terminal prompt: is not stored in Vault. This token was created when you first ran:")
	logger.Info("terminal prompt:   consul acl bootstrap")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: To complete Vault-Consul integration, please provide the token.")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: WHERE TO FIND THE TOKEN:")
	logger.Info("terminal prompt:   - Check your initial Consul setup notes/documentation")
	logger.Info("terminal prompt:   - Look in: /etc/consul.d/acl-token (if you saved it there)")
	logger.Info("terminal prompt:   - Check environment: echo $CONSUL_HTTP_TOKEN")
	logger.Info("terminal prompt:   - Look for 'SecretID' in your bootstrap output")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: SECURITY NOTE:")
	logger.Info("terminal prompt:   - This token will be securely stored in Vault")
	logger.Info("terminal prompt:   - Path: " + fullPath)
	logger.Info("terminal prompt:   - Environment: " + string(env))
	logger.Info("terminal prompt:   - Once stored, you won't need to provide it again")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")

	// Prompt for the token
	fmt.Print("Enter Consul bootstrap token (or 'cancel' to abort): ")

	var token string
	_, err := fmt.Scanln(&token)
	if err != nil {
		return nil, fmt.Errorf("failed to read token from stdin: %w", err)
	}

	token = strings.TrimSpace(token)

	// Check if user wants to cancel
	if strings.ToLower(token) == "cancel" {
		return nil, fmt.Errorf("user cancelled token recovery")
	}

	// Validate token is not empty
	if token == "" {
		return nil, fmt.Errorf("bootstrap token cannot be empty")
	}

	// Validate token format (Consul tokens are UUIDs: 8-4-4-4-12 format)
	if len(token) != 36 {
		logger.Warn("Token does not appear to be a valid UUID format (expected 36 characters)",
			zap.Int("length", len(token)))
	}

	logger.Info("Received bootstrap token, verifying with Consul...")

	// EVALUATE - Verify the token works by trying to use it
	// Create a test Consul client with this token
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = shared.GetConsulHostPort()
	consulConfig.Token = token

	testClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Try to read our own token (requires the token to be valid)
	selfToken, _, err := testClient.ACL().TokenReadSelf(nil)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w\n"+
			"The provided token does not have valid ACL permissions.\n"+
			"Make sure you're providing the BOOTSTRAP token (global-management policy).\n"+
			"Remediation:\n"+
			"  - Verify token with: consul acl token read -self -token=<your-token>\n"+
			"  - Check token has 'global-management' policy",
			err)
	}

	// Verify it's actually a bootstrap/management token
	hasGlobalManagement := false
	for _, policy := range selfToken.Policies {
		if policy.Name == "global-management" {
			hasGlobalManagement = true
			break
		}
	}

	if !hasGlobalManagement {
		logger.Warn("WARNING: Token does not have 'global-management' policy",
			zap.String("accessor", selfToken.AccessorID),
			zap.Int("policy_count", len(selfToken.Policies)))
		logger.Warn("This may not be the bootstrap token. Vault-Consul integration requires a management token.")

		// Don't fail - just warn. User might know what they're doing.
	}

	logger.Info("Token verified successfully",
		zap.String("accessor", selfToken.AccessorID),
		zap.String("description", selfToken.Description))

	// INTERVENE - Store the token in Vault
	logger.Info("Storing bootstrap token in Vault for future use")

	// Get environment-aware paths
	kvPath := getConsulBootstrapTokenPath(env)

	data := map[string]interface{}{
		"token":          token,
		"accessor":       selfToken.AccessorID,
		"description":    selfToken.Description,
		"recovered_at":   time.Now().Format(time.RFC3339),
		"policies":       []string{"global-management"},
		"environment":    string(env),
		"warning":        "This is the Consul master token - protect it carefully!",
		"recovery_steps": "To retrieve: vault kv get -field=token " + fullPath,
		"source":         "user-provided (eos sync recovery)",
	}

	// Write to Vault KV v2 (uses environment-aware path, SDK adds secret/data/ prefix automatically)
	_, err = vaultClient.KVv2("secret").Put(rc.Ctx, kvPath, data)
	if err != nil {
		return nil, fmt.Errorf("failed to store bootstrap token in Vault: %w\n"+
			"Vault path: %s\n"+
			"Environment: %s\n"+
			"Remediation:\n"+
			"  - Check Vault is unsealed: vault status\n"+
			"  - Verify Vault token has write permissions to secret/data/services/%s/consul/*\n"+
			"  - Check Vault logs for errors",
			err, fullPath, env, env)
	}

	logger.Info("Bootstrap token stored in Vault successfully",
		zap.String("vault_path", fullPath),
		zap.String("environment", string(env)))

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ Bootstrap token verified and stored in Vault")
	logger.Info("terminal prompt: ")

	result := &BootstrapResult{
		MasterToken:   token,
		Accessor:      selfToken.AccessorID,
		AlreadyDone:   true,
		BootstrapTime: time.Now(),
		StoredInVault: true,
		VaultPath:     fullPath,
	}

	return result, nil
}
