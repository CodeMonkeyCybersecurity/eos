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

// PHASE 8 — PhasePromptAndVerRootToken()
//          └── PromptRootToken()
//          └── VerRootToken()
//          └── SetVaultToken()

// PhasePromptAndVerRootToken prompts for root token, validates it, and sets it on client.
func PhasePromptAndVerRootToken(client *api.Client) error {
	zap.L().Info("🔑 [Phase 8] Prompting and validating Vault root token")

	token, err := PromptRootToken()
	if err != nil {
		return fmt.Errorf("prompt root token: %w", err)
	}

	if err := VerRootToken(client, token); err != nil {
		return fmt.Errorf("validate root token: %w", err)
	}

	SetVaultToken(client, token)
	zap.L().Info("✅ Root token validated and applied")
	return nil
}

// PromptRootToken requests the root token from the user.
func PromptRootToken() (string, error) {
	zap.L().Info("🔑 Please enter the Vault root token")
	tokens, err := interaction.PromptSecrets("Root Token", 1)
	if err != nil {
		return "", err
	}
	return tokens[0], nil
}

// VerRootToken checks if the root token is valid via a simple self-lookup.
func VerRootToken(client *api.Client, token string) error {
	client.SetToken(token)
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil || secret == nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}
