package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// HandleFallbackOrStore determines whether secrets should be written to Vault,
// stored to disk, or handled via user fallback flow, based on Vault availability.
func HandleFallbackOrStore(name string, secrets map[string]string) error {
	if _, err := EnsureVaultEnv(); err != nil {
		zap.L().Warn("Failed to set VAULT_ADDR environment", zap.Error(err))
	}

	client, err := mustNewClient()
	if err != nil {
		return err
	}

	report, client := Check(client, nil, "")
	if client == nil {
		zap.L().Warn("Vault check failed: client unavailable")
		return handleVaultUnavailable(name, secrets)
	}

	if report.Initialized && !report.Sealed && report.KVWorking {
		zap.L().Info("🔐 Vault is available and healthy — storing secrets securely", zap.String("name", name))
		return WriteToVault(name, secrets)
	}

	zap.L().Info("🔍 Vault unavailable or unhealthy", zap.String("name", name))
	return handleVaultUnavailable(name, secrets)
}

// handleVaultUnavailable prompts the user to select a fallback strategy when Vault is unavailable.
func handleVaultUnavailable(name string, secrets map[string]string) error {
	choice := interaction.FallbackPrompter(
		"Vault not detected or not ready. What would you like to do?",
		[]interaction.FallbackOption{
			{Label: "Deploy local Vault now [recommended]", Code: string(shared.FallbackDeploy)},
			{Label: "Skip and save credentials to disk", Code: string(shared.FallbackDisk)},
			{Label: "Abort", Code: string(shared.FallbackAbort)},
		},
	)

	return interaction.HandleFallbackChoice(choice, map[string]func() error{
		string(shared.FallbackDeploy): func() error {
			client, err := mustNewClient()
			if err != nil {
				return err
			}
			return DeployAndStoreSecrets(client, name, secrets)
		},
		string(shared.FallbackDisk): func() error {
			zap.L().Warn("Saving secrets to disk fallback", zap.String("fallback", "disk"), zap.String("name", name))
			return WriteFallbackSecrets(name, secrets) // ✅ fixed missing logger arg
		},
		string(shared.FallbackAbort): func() error {
			zap.L().Warn("User aborted — Vault unavailable and disk fallback declined", zap.String("name", name))
			zap.L().Info("Secrets were not saved due to user abort", zap.String("name", name))
			return fmt.Errorf("vault unavailable, user aborted")
		},
	}) // ✅ fixed missing logger arg
}

// mustNewClient attempts to create a Vault client and logs any error.
func mustNewClient() (*api.Client, error) {
	client, err := NewClient()
	if err != nil {
		zap.L().Error("Failed to create Vault client", zap.Error(err))
	}
	return client, err
}

func MaybeWriteVaultInitFallback(init *api.InitResponse) error {
	fmt.Print("💾 Save Vault init material to fallback file? (y/N): ")
	var resp string
	shared.SafeScanln(&resp)
	if strings.ToLower(resp) != "y" {
		zap.L().Warn("❌ Skipping fallback write at user request")
		return nil
	}
	return SaveInitResult(init)
}

// TryLoadUnsealKeysFromFallback attempts to load the vault-init.json file and parse the keys.
func TryLoadUnsealKeysFromFallback() (*api.InitResponse, error) {
	path := DiskPath("vault_init")
	zap.L().Info("📂 Attempting fallback unseal using init file", zap.String("path", path))
	initRes := new(api.InitResponse)

	if err := ReadFallbackJSON(path, initRes); err != nil {
		zap.L().Warn("⚠️ Failed to read fallback file", zap.Error(err))
		return nil, fmt.Errorf("failed to read vault init fallback file: %w", err)
	}
	if len(initRes.KeysB64) < 3 || initRes.RootToken == "" {
		return nil, fmt.Errorf("invalid or incomplete vault-init.json file")
	}
	zap.L().Info("✅ Fallback file validated", zap.Int("keys_found", len(initRes.KeysB64)))
	return initRes, nil
}
