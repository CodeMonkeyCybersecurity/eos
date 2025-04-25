package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// HandleFallbackOrStore determines whether secrets should be written to Vault,
// stored to disk, or handled via user fallback flow, based on Vault availability.
func HandleFallbackOrStore(name string, secrets map[string]string, log *zap.Logger) error {
	if _, err := EnsureVaultEnv(log); err != nil {
		log.Warn("Failed to set VAULT_ADDR environment", zap.Error(err))
	}

	client, err := mustNewClient(log)
	if err != nil {
		return err
	}

	report, client := Check(client, log, nil, "")
	if client == nil {
		log.Warn("Vault check failed: client unavailable")
		return handleVaultUnavailable(name, secrets, log)
	}

	if report.Initialized && !report.Sealed && report.KVWorking {
		log.Info("🔐 Vault is available and healthy — storing secrets securely", zap.String("name", name))
		return WriteToVault(name, secrets, log)
	}

	log.Info("🔍 Vault unavailable or unhealthy", zap.String("name", name))
	return handleVaultUnavailable(name, secrets, log)
}

// handleVaultUnavailable prompts the user to select a fallback strategy when Vault is unavailable.
func handleVaultUnavailable(name string, secrets map[string]string, log *zap.Logger) error {
	choice := interaction.FallbackPrompter(
		"Vault not detected or not ready. What would you like to do?",
		[]interaction.FallbackOption{
			{Label: "Deploy local Vault now [recommended]", Code: string(shared.FallbackDeploy)},
			{Label: "Skip and save credentials to disk", Code: string(shared.FallbackDisk)},
			{Label: "Abort", Code: string(shared.FallbackAbort)},
		},
		log,
	)

	return interaction.HandleFallbackChoice(choice, map[string]func() error{
		string(shared.FallbackDeploy): func() error {
			client, err := mustNewClient(log)
			if err != nil {
				return err
			}
			return DeployAndStoreSecrets(client, name, secrets, log)
		},
		string(shared.FallbackDisk): func() error {
			log.Warn("Saving secrets to disk fallback", zap.String("fallback", "disk"), zap.String("name", name))
			return WriteFallbackSecrets(name, secrets, log) // ✅ fixed missing logger arg
		},
		string(shared.FallbackAbort): func() error {
			log.Warn("User aborted — Vault unavailable and disk fallback declined", zap.String("name", name))
			log.Info("Secrets were not saved due to user abort", zap.String("name", name))
			return fmt.Errorf("vault unavailable, user aborted")
		},
	}, log) // ✅ fixed missing logger arg
}

// mustNewClient attempts to create a Vault client and logs any error.
func mustNewClient(log *zap.Logger) (*api.Client, error) {
	client, err := NewClient(log)
	if err != nil {
		log.Error("Failed to create Vault client", zap.Error(err))
	}
	return client, err
}
