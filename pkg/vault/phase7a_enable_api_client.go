package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//---------------------------------------------------------
// Phase 7A: Enable API Client Access for Root-Level Actions
//
// Purpose:
// - Construct and return a privileged Vault API client
// - Load and verify root token from disk or prompt
//---------------------------------------------------------

// SetVaultToken safely applies the token to the Vault client.
func SetVaultToken(client *api.Client, token string) {
	client.SetToken(token)
	zap.L().Debug("🔐 Vault token set on client", zap.String("token_preview", truncateToken(token)))
}

// GetRootClient constructs a Vault client authenticated with the root token.
func GetRootClient() (*api.Client, error) {
	log := zap.L().Named("vault.rootclient")
	log.Info("🔐 Initializing privileged Vault client")

	// 1️⃣ Create a Vault API client from config
	client, err := NewClient()
	if err != nil {
		log.Error("❌ Failed to create Vault API client", zap.Error(err))
		return nil, fmt.Errorf("create Vault client: %w", err)
	}
	log.Debug("✅ Vault API client created", zap.String("addr", client.Address()))

	// 2️⃣ Load root token from init file or fallback
	rootToken, err := loadPrivilegedToken()
	if err != nil {
		log.Error("❌ Failed to load root token", zap.Error(err))
		return nil, fmt.Errorf("load root token: %w", err)
	}
	SetVaultToken(client, rootToken)

	// 3️⃣ Verify token validity against Vault
	if err := VerifyRootToken(client, rootToken); err != nil {
		log.Error("❌ Root token is invalid", zap.Error(err))
		return nil, fmt.Errorf("verify root token: %w", err)
	}
	log.Info("✅ Root token validated, privileged client ready")

	return client, nil
}

// truncateToken returns a safe preview string for logging.
func truncateToken(token string) string {
	if len(token) <= 6 {
		return token
	}
	return token[:3] + "..." + token[len(token)-3:]
}
