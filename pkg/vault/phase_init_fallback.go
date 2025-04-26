// pkg/vault/phase_init.go

package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// LoadInitResultOrPrompt tries loading the init result from disk; otherwise prompts the user.
func LoadInitResultOrPrompt(client *api.Client, log *zap.Logger) (*api.InitResponse, error) {
	initRes := new(api.InitResponse)
	if err := ReadFallbackJSON(DiskPath("vault_init", log), initRes, log); err != nil {
		log.Warn("⚠️ Fallback file missing or unreadable — prompting user", zap.Error(err))
		return PromptForInitResult(log)
	}
	log.Info("✅ Vault init result loaded from fallback")
	return initRes, nil
}

func MaybeWriteVaultInitFallback(init *api.InitResponse, log *zap.Logger) error {
	fmt.Print("💾 Save Vault init material to fallback file? (y/N): ")
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) != "y" {
		log.Warn("❌ Skipping fallback write at user request")
		return nil
	}
	return SaveInitResult(init, log)
}

// TryLoadUnsealKeysFromFallback attempts to load the vault-init.json file and parse the keys.
func TryLoadUnsealKeysFromFallback(log *zap.Logger) (*api.InitResponse, error) {
	path := DiskPath("vault_init", log)
	log.Info("📂 Attempting fallback unseal using init file", zap.String("path", path))
	initRes := new(api.InitResponse)

	if err := ReadFallbackJSON(path, initRes, log); err != nil {
		log.Warn("⚠️ Failed to read fallback file", zap.Error(err))
		return nil, fmt.Errorf("failed to read vault init fallback file: %w", err)
	}
	if len(initRes.KeysB64) < 3 || initRes.RootToken == "" {
		return nil, fmt.Errorf("invalid or incomplete vault-init.json file")
	}
	log.Info("✅ Fallback file validated", zap.Int("keys_found", len(initRes.KeysB64)))
	return initRes, nil
}
