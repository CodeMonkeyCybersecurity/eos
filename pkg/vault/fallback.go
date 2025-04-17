/* pkg/vault/fallback.go */

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"go.uber.org/zap"
)

func HandleFallbackOrStore(name string, secrets map[string]string) error {
	log := logger.GetLogger()

	if _, err := SetVaultEnv(); err != nil {
		log.Warn("Failed to set VAULT_ADDR environment", zap.Error(err))
	}

	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	if IsVaultAvailable(client) {
		fmt.Println("🔐 Vault is available. Storing secrets securely.")
		return WriteToVault(name, secrets)
	}

	choice := interaction.PromptGenericFallback("Vault not detected. What would you like to do?", []interaction.FallbackOption{
		{Label: "Deploy local Vault now [recommended]", Code: "deploy"},
		{Label: "Skip and save credentials to disk", Code: "disk"},
		{Label: "Abort", Code: "abort"},
	})

	return interaction.HandleFallbackChoice(choice, map[string]func() error{
		"deploy": func() error {
			client, err := NewClient()
			if err != nil {
				return fmt.Errorf("failed to create Vault client: %w", err)
			}
			return DeployAndStoreSecrets(client, name, secrets)
		},
		"disk": func() error {
			return interaction.WriteFallbackSecrets(name, secrets)
		},
		"abort": func() error {
			return fmt.Errorf("vault unavailable, user aborted")
		},
	})
}
