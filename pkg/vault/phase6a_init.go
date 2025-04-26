// pkg/vault/phase6a_init.go

package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 6a.  Initialize Vault
//--------------------------------------------------------------------

func PhaseInitVaultOnly(client *api.Client, log *zap.Logger) (*api.Client, error) {
	log.Info("[5/6] Initializing Vault only (no unseal)")

	status, err := client.Sys().InitStatus()
	if err != nil {
		log.Error("❌ Failed to check Vault init status", zap.Error(err))
		return nil, err
	}
	if status {
		log.Info("🔓 Vault already initialized — skipping")
		return client, nil
	}

	log.Info("⚙️ Vault not initialized — starting initialization sequence")
	initRes, err := InitVault(client, log)
	if err != nil {
		return nil, err
	}

	if err := PromptToSaveVaultInitData(initRes, log); err != nil {
		return nil, err
	}
	if err := ConfirmUnsealMaterialSaved(initRes, log); err != nil {
		return nil, err
	}
	if err := SaveInitResult(initRes, log); err != nil {
		return nil, err
	}

	log.Warn("⚠️ Vault is initialized but NOT unsealed yet")
	log.Info("📜 Please run 'eos inspect vault-init' to retrieve your keys and token")
	log.Info("🚀 Then run 'eos enable vault' to unseal and secure Vault")

	return client, nil
}

// initVault initializes Vault with default settings (5 keys, 3 threshold).
func InitVault(client *api.Client, log *zap.Logger) (*api.InitResponse, error) {
	initOptions := &api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}
	initRes, err := client.Sys().Init(initOptions)
	if err != nil {
		log.Error("❌ Vault initialization failed", zap.Error(err))
		return nil, err
	}
	log.Info("✅ Vault successfully initialized",
		zap.Int("num_keys", len(initRes.KeysB64)),
		zap.String("root_token_hash", crypto.HashString(initRes.RootToken)))
	return initRes, nil
}

// SaveInitResult stores the init result in fallback path.
func SaveInitResult(initRes *api.InitResponse, log *zap.Logger) error {
	b, err := json.MarshalIndent(initRes, "", "  ")
	if err != nil {
		log.Error("❌ Failed to marshal vault init result", zap.Error(err))
		return err
	}

	path := DiskPath("vault_init", log)
	if err := os.WriteFile(path, b, 0600); err != nil {
		log.Error("❌ Failed to write vault init file", zap.String("path", path), zap.Error(err))
		return err
	}

	log.Info("💾 Vault init result saved", zap.String("path", path))
	return nil
}

func PromptToSaveVaultInitData(init *api.InitResponse, log *zap.Logger) error {
	fmt.Println("\n⚠️  WARNING: This is the only time you will see these unseal keys and root token.")
	fmt.Println("You MUST securely back them up. Losing them means permanent loss of access.")
	fmt.Print("\nType 'yes' to confirm you've saved the keys somewhere safe: ")

	var response string
	fmt.Scanln(&response)
	if strings.ToLower(strings.TrimSpace(response)) != "yes" {
		return fmt.Errorf("user did not confirm secure storage of unseal material")
	}

	log.Info("✅ User confirmed Vault init material has been backed up securely")
	return nil
}

func ConfirmUnsealMaterialSaved(init *api.InitResponse, log *zap.Logger) error {
	fmt.Println("\n🔐 Please re-enter 3 of your unseal keys and the root token to confirm you've saved them.")

	keys, err := crypto.PromptSecrets("Unseal Key", 3, log)
	if err != nil {
		return fmt.Errorf("failed to read unseal keys: %w", err)
	}
	root, err := crypto.PromptSecrets("Root Token", 1, log)
	if err != nil {
		return fmt.Errorf("failed to read root token: %w", err)
	}

	if crypto.HashString(root[0]) != crypto.HashString(init.RootToken) {
		return fmt.Errorf("root token did not match original")
	}

	matchCount := 0
	for _, entered := range keys {
		for _, known := range init.KeysB64 {
			if crypto.HashString(entered) == crypto.HashString(known) {
				matchCount++
				break
			}
		}
	}

	if matchCount < 3 {
		return fmt.Errorf("less than 3 unseal keys matched")
	}

	log.Info("✅ User successfully confirmed unseal material")
	return nil
}
