package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
func SetVaultToken(rc *eos_io.RuntimeContext, client *api.Client, token string) {
	client.SetToken(token)
	otelzap.Ctx(rc.Ctx).Debug("🔐 Vault token set on client", zap.String("token_preview", truncateToken(token)))
}

// GetRootClient constructs a Vault client authenticated with the root token.
func GetRootClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔐 Initializing privileged Vault client")

	// 1️⃣ Create a Vault API client from config
	log.Info("🏗️ Creating new Vault client from config")
	client, err := NewClient(rc)
	if err != nil {
		log.Error("❌ Failed to create Vault API client", zap.Error(err))
		return nil, fmt.Errorf("create Vault client: %w", err)
	}
	log.Info("✅ Vault API client created",
		zap.String("addr", client.Address()),
		zap.String("existing_token", func() string {
			if token := client.Token(); token != "" {
				return token[:12] + "..."
			}
			return "none"
		}()))

	// 2️⃣ Load root token from init file or fallback
	log.Info("🔑 Loading privileged token (ignoring any VAULT_TOKEN)")
	rootToken, err := loadPrivilegedToken(rc)
	if err != nil {
		log.Error("❌ Failed to load root token", zap.Error(err))
		return nil, fmt.Errorf("load root token: %w", err)
	}

	log.Info("🔄 Setting privileged token on client")
	SetVaultToken(rc, client, rootToken)

	// 3️⃣ Verify token validity against Vault
	if err := VerifyRootToken(rc, client, rootToken); err != nil {
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
