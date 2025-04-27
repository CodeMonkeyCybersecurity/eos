// pkg/vault/phase8_validate_root_token.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 8. Prompt and Validate Root Token
//--------------------------------------------------------------------

// PHASE 8 — PhasePromptAndValidateRootToken()
//          └── PromptRootToken()
//          └── ValidateRootToken()
//          └── SetVaultToken()

// PhasePromptAndValidateRootToken prompts for root token, validates it, and sets it on client.
func PhasePromptAndValidateRootToken(client *api.Client, log *zap.Logger) error {
	log.Info("🔑 [Phase 8] Prompting and validating Vault root token")

	token, err := PromptRootToken(log)
	if err != nil {
		return fmt.Errorf("prompt root token: %w", err)
	}

	if err := ValidateRootToken(client, token); err != nil {
		return fmt.Errorf("validate root token: %w", err)
	}

	SetVaultToken(client, token)
	log.Info("✅ Root token validated and applied")
	return nil
}

// PromptRootToken requests the root token from the user.
func PromptRootToken(log *zap.Logger) (string, error) {
	log.Info("🔑 Please enter the Vault root token")
	tokens, err := interaction.PromptSecrets("Root Token", 1, log)
	if err != nil {
		return "", err
	}
	return tokens[0], nil
}

// ValidateRootToken checks if the root token is valid via a simple self-lookup.
func ValidateRootToken(client *api.Client, token string) error {
	client.SetToken(token)
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil || secret == nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}

// SetVaultToken configures the Vault client to use a provided token.
func SetVaultToken(client *api.Client, token string) {
	client.SetToken(token)
}
