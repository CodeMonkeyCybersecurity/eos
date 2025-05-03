// pkg/vault/phase8a_enable_api_client.go

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

// Phase 8A: Enable API Client Access
// └── GetPrivilegedVaultClient()
//     ├── GetVaultClient()
//     │   └── (returns the existing Vault client)
//     └── validateVaultToken(client)
//         └── client.Auth().Token().LookupSelf()
//             └── (Vault server confirms token validity)

// SetVaultToken sets the Vault token on the provided client.
func SetVaultToken(client *api.Client, token string) {
	client.SetToken(token)
}

// GetPrivilegedVaultClient simply returns the authenticated Vault client if available.
// It validates that the token is usable immediately.
func GetPrivilegedVaultClient() (*api.Client, error) {
	zap.L().Info("🔐 Checking Vault client token validity...")

	client, err := GetVaultClient()
	if err != nil {
		zap.L().Error("❌ Failed to retrieve existing Vault client", zap.Error(err))
		return nil, fmt.Errorf("get vault client: %w", err)
	}

	if err := validateVaultToken(client); err != nil {
		zap.L().Error("❌ Vault client token appears invalid", zap.Error(err))
		return nil, fmt.Errorf("vault client invalid: %w", err)
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
