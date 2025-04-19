/* pkg/vault/fallback.go */

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

func HandleFallbackOrStore(name string, secrets map[string]string, log *zap.Logger) error {
	if _, err := EnsureVaultEnv(log); err != nil {
		log.Warn("Failed to set VAULT_ADDR environment", zap.Error(err))
	}

	client, err := NewClient(log)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	report, _ := Check(client, log, nil, "")
	if report.Initialized && !report.Sealed && report.KVWorking {
		log.Info("🔐 Vault is available and healthy — storing secrets securely")
		return WriteToVault(name, secrets, log)
	}

	// Vault is not ready — offer fallback options
	choice := interaction.FallbackPrompter("Vault not detected or not ready. What would you like to do?", []interaction.FallbackOption{
		{Label: "Deploy local Vault now [recommended]", Code: "deploy"},
		{Label: "Skip and save credentials to disk", Code: "disk"},
		{Label: "Abort", Code: "abort"},
	}, log)

	return interaction.HandleFallbackChoice(choice, map[string]func() error{
		"deploy": func() error {
			client, err := NewClient(log)
			if err != nil {
				return fmt.Errorf("failed to create Vault client: %w", err)
			}
			return DeployAndStoreSecrets(client, name, secrets, log)
		},
		"disk": func() error {
			log.Warn("Saving secrets to disk fallback")
			return interaction.WriteFallbackSecrets(name, secrets)
		},
		"abort": func() error {
			log.Warn("User aborted — Vault unavailable and disk fallback declined")
			return fmt.Errorf("vault unavailable, user aborted")
		},
	})
}
