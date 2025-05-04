// pkg/vault/phase7a_enable_api_client.go

package vault

import (
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
	zap.L().Info("🔐 Getting validated Vault client")
	return GetVaultClient()
}
