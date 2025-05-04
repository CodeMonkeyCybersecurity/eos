// pkg/vault/phase7a_enable_api_client.go

package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// Phase 8A: Enable API Client Access
//
// Purpose:
// - Confirm that Vault API client is ready for EOS CLI usage
// - Validate that token (root token) is active and authorized
//--------------------------------------------------------------------

// SetVaultToken sets the Vault token on the provided client.
func SetVaultToken(client *api.Client, token string) {
	client.SetToken(token)
}

// GetPrivilegedVaultClient returns a Vault client authenticated with the root token.
// It bypasses the agent token and ensures the root token is valid.
func GetPrivilegedVaultClient() (*api.Client, error) {
	zap.L().Info("🔐 Checking Vault client token validity...")

	// Create a fresh Vault client
	client, err := NewClient()
	if err != nil {
		zap.L().Error("❌ Failed to create new Vault client", zap.Error(err))
		return nil, fmt.Errorf("create new vault client: %w", err)
	}

	// Explicitly load the root token from vault_init.json
	rootToken, err := readRootTokenFromInitFile()
	if err != nil {
		zap.L().Error("❌ Failed to load root token", zap.Error(err))
		return nil, fmt.Errorf("load root token: %w", err)
	}
	client.SetToken(rootToken)

	// Validate that the root token works
	if err := validateVaultToken(client); err != nil {
		zap.L().Error("❌ Vault root token appears invalid", zap.Error(err))
		return nil, fmt.Errorf("vault root token invalid: %w", err)
	}

	zap.L().Info("✅ Vault client authenticated and ready")
	return client, nil
}

// validateVaultToken performs a lightweight lookup to confirm the client token is valid.
func validateVaultToken(client *api.Client) error {
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil || secret == nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}
