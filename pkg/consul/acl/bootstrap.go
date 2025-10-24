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
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BootstrapResult contains the result of ACL bootstrap operation
type BootstrapResult struct {
	MasterToken    string    // The bootstrap/master token (global-management)
	Accessor       string    // Token accessor ID
	AlreadyDone    bool      // True if ACLs were already bootstrapped
	BootstrapTime  time.Time // When bootstrap occurred
	StoredInVault  bool      // True if token was stored in Vault
	VaultPath      string    // Path where token is stored in Vault
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
		if err.Error() == "Unexpected response code: 403 (Permission denied: ACL bootstrap no longer allowed (reset index: 1))" ||
			err.Error() == "Unexpected response code: 403 (Permission denied: ACL system already initialized)" {

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
		logger.Info("Storing Consul master token in Vault")

		vaultPath := "secret/consul/bootstrap-token"
		data := map[string]interface{}{
			"token":          bootstrapToken.SecretID,
			"accessor":       bootstrapToken.AccessorID,
			"description":    bootstrapToken.Description,
			"created_at":     time.Now().Format(time.RFC3339),
			"policies":       []string{"global-management"},
			"warning":        "This is the Consul master token - protect it carefully!",
			"recovery_steps": "To retrieve: vault kv get -field=token secret/consul/bootstrap-token",
		}

		// Write to Vault KV v2 (secret/)
		_, err := vaultClient.KVv2("secret").Put(rc.Ctx, "consul/bootstrap-token", data)
		if err != nil {
			logger.Warn("Failed to store bootstrap token in Vault",
				zap.Error(err),
				zap.String("note", "Token is still available in memory, but not persisted"))
			// Don't fail - bootstrap succeeded, just storage failed
		} else {
			logger.Info("Consul master token stored in Vault",
				zap.String("vault_path", vaultPath))
			result.StoredInVault = true
			result.VaultPath = vaultPath
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
func GetBootstrapTokenFromVault(rc *eos_io.RuntimeContext, vaultClient *vaultapi.Client) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Retrieving Consul bootstrap token from Vault")

	// Read from Vault KV v2
	secret, err := vaultClient.KVv2("secret").Get(rc.Ctx, "consul/bootstrap-token")
	if err != nil {
		return "", fmt.Errorf("failed to read Consul bootstrap token from Vault: %w\n"+
			"Remediation:\n"+
			"  - Check Vault is unsealed: vault status\n"+
			"  - Verify secret exists: vault kv get secret/consul/bootstrap-token\n"+
			"  - Check Vault token has read permissions to secret/consul/*",
			err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("Consul bootstrap token not found in Vault at secret/consul/bootstrap-token")
	}

	token, ok := secret.Data["token"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token format in Vault (expected string)")
	}

	logger.Info("Retrieved Consul bootstrap token from Vault")

	return token, nil
}
