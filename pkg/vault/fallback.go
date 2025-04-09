// pkg/vault/fallback.go
package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

func handleFallbackOrStore(name string, secrets map[string]string) error {
	setVaultEnv()

	if isAvailable() {
		fmt.Println("🔐 Vault is available. Storing secrets securely.")
		return saveToVault(name, secrets)
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
			return deployAndStoreSecrets(client, name, secrets)
		},
		"disk": func() error {
			return interaction.WriteFallbackSecrets(name, secrets)
		},
		"abort": func() error {
			return fmt.Errorf("vault unavailable, user aborted")
		},
	})
}
