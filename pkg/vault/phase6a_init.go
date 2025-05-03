// pkg/vault/phase6a_init.go

package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 6a️⃣ Initialize Vault (only — no unseal yet)
//--------------------------------------------------------------------

// PhaseInitVaultOnly initializes Vault if not already initialized.
func PhaseInitVaultOnly(client *api.Client) (*api.Client, error) {
	zap.L().Info("🚀 Phase 6a/6: Initialize Vault (only, no unseal)")

	status, err := client.Sys().InitStatus()
	if err != nil {
		zap.L().Error("❌ Failed to check Vault initialization status", zap.Error(err))
		return nil, fmt.Errorf("check vault init status: %w", err)
	}
	if status {
		zap.L().Info("🔓 Vault already initialized — skipping Phase 6a")
		return client, nil
	}

	zap.L().Info("⚙️ Vault not initialized — beginning initialization sequence")
	initRes, err := InitVault(client)
	if err != nil {
		return nil, fmt.Errorf("initialize vault: %w", err)
	}

	if err := SaveInitResult(initRes); err != nil {
		// If save fails, advise user to rescue init material manually
		zap.L().Warn("⚠️ Failed to persist Vault init result — printing keys to console")
		fmt.Printf("\n\nUNSEAL KEYS:\n%v\n\nROOT TOKEN:\n%s\n\n", initRes.KeysB64, initRes.RootToken)
		return nil, fmt.Errorf("save vault init result: %w", err)
	}

	// Strongly suggest user to manually confirm backup
	if err := PromptToSaveVaultInitData(initRes); err != nil {
		return nil, fmt.Errorf("user did not confirm backup: %w", err)
	}

	zap.L().Warn("⚠️ Vault is initialized but NOT unsealed yet")
	zap.L().Info("📜 Please run 'eos inspect vault-init' to retrieve your keys and token")
	zap.L().Info("🚀 Then run 'eos enable vault' to unseal and secure Vault")

	return client, nil
}

// InitVault initializes Vault with default 5 keys, 3 threshold.
func InitVault(client *api.Client) (*api.InitResponse, error) {
	initOptions := &api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}
	initRes, err := client.Sys().Init(initOptions)
	if err != nil {
		zap.L().Error("❌ Vault initialization failed", zap.Error(err))
		return nil, fmt.Errorf("vault init API call: %w", err)
	}
	zap.L().Info("✅ Vault initialized successfully",
		zap.Int("num_keys", len(initRes.KeysB64)),
		zap.String("root_token_hash", crypto.HashString(initRes.RootToken)),
	)
	return initRes, nil
}

// SaveInitResult saves the Vault initialization result securely to disk.
func SaveInitResult(initRes *api.InitResponse) error {
	path := shared.VaultInitPath
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		zap.L().Error("❌ Failed to create init directory", zap.String("dir", dir), zap.Error(err))
		return fmt.Errorf("create init dir: %w", err)
	}

	b, err := json.MarshalIndent(initRes, "", "  ")
	if err != nil {
		zap.L().Error("❌ Failed to marshal Vault init result", zap.Error(err))
		return fmt.Errorf("marshal init result: %w", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		zap.L().Error("❌ Failed to write Vault init file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("write init result: %w", err)
	}

	zap.L().Info("💾 Vault init result saved securely", zap.String("path", path))
	return nil
}

// PromptToSaveVaultInitData asks user to confirm that they have safely backed up unseal material.
func PromptToSaveVaultInitData(init *api.InitResponse) error {
	fmt.Println("\n⚠️  WARNING: This is the only time you will see these unseal keys and root token.")
	fmt.Println("You MUST securely back them up. Losing them means permanent loss of access.")
	fmt.Print("\nType 'yes' to confirm you have saved the keys somewhere safe: ")

	var response string
	if _, err := fmt.Scanln(&response); err != nil {
		zap.L().Warn("Failed to read user input", zap.Error(err))
	}
	if strings.ToLower(strings.TrimSpace(response)) != "yes" {
		return fmt.Errorf("user did not confirm secure storage of unseal material")
	}

	zap.L().Info("✅ User confirmed Vault init material backup")
	return nil
}
