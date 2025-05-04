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

// GetRootClient returns a Vault client authenticated with the root token.
// It bypasses the agent token and ensures the root token is valid.
func GetRootClient() (*api.Client, error) {
	log := zap.L().Named("GetRootClient")
	log.Info("🔐 Starting privileged Vault client setup")

	// 1️⃣ Create a Vault API client
	log.Debug("📡 Creating new Vault API client")
	client, err := NewClient()
	if err != nil {
		log.Error("❌ Failed to create Vault API client", zap.Error(err))
		return nil, fmt.Errorf("create vault API client: %w", err)
	}
	log.Debug("✅ Vault API client created")

	// 2️⃣ Get the root token from vault-init.json or prompt
	log.Debug("🔑 Retrieving root token from init result or prompt")
	rootToken, err := tryRootToken(client)
	if err != nil {
		log.Error("❌ Failed to load root token", zap.Error(err))
		return nil, fmt.Errorf("load root token: %w", err)
	}
	log.Debug("✅ Root token retrieved", zap.String("token_preview", truncateToken(rootToken)))

	// 3️⃣ Set the root token on the client
	log.Debug("🔐 Setting root token on Vault client")
	client.SetToken(rootToken)
	log.Debug("✅ Root token set on client")

	// 4️⃣ Verify that the token is valid against Vault
	log.Debug("🔍 Verifying root token with Vault server")
	if err := VerifyRootToken(client, rootToken); err != nil {
		log.Error("❌ Root token validation failed", zap.Error(err))
		return nil, fmt.Errorf("verify root token: %w", err)
	}
	log.Info("✅ Privileged Vault client obtained and verified with root token")

	return client, nil
}

func truncateToken(token string) string {
	if len(token) <= 6 {
		return token
	}
	return token[:3] + "..." + token[len(token)-3:]
}
