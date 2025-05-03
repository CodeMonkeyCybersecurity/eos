package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func UnsealVault() (*api.Client, error) {
	client, err := CreateVaultClient()
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	initStatus, err := client.Sys().InitStatus()
	if err != nil {
		return nil, fmt.Errorf("check init status: %w", err)
	}

	if initStatus {
		zap.L().Info("🔓 Vault already initialized")
		return client, nil
	}

	zap.L().Info("⚙️ Initializing Vault")
	initRes, err := initVaultWithTimeout(client)
	if err != nil {
		return nil, err
	}

	if err := handleInitMaterial(initRes); err != nil {
		return nil, err
	}

	if err := finalizeVaultSetup(client, initRes); err != nil {
		return nil, err
	}

	zap.L().Info("✅ Vault initialized and unsealed")
	return client, nil
}

func initVaultWithTimeout(client *api.Client) (*api.InitResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	initRes, err := client.Sys().InitWithContext(ctx, &api.InitRequest{SecretShares: 5, SecretThreshold: 3})
	if err == nil {
		return initRes, nil
	}

	if IsAlreadyInitialized(err) {
		return LoadInitResultOrPrompt(client)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("vault init timed out: %w", err)
	}
	if strings.Contains(err.Error(), "connection refused") {
		return nil, fmt.Errorf("vault connection refused: %w", err)
	}

	return nil, fmt.Errorf("vault init error: %w", err)
}

func handleInitMaterial(initRes *api.InitResponse) error {
	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		return fmt.Errorf("invalid init result: missing keys or root token")
	}

	if err := PromptToSaveVaultInitData(initRes); err != nil {
		return err
	}
	if err := ConfirmUnsealMaterialSaved(initRes); err != nil {
		return err
	}
	return SaveInitResult(initRes)
}

func finalizeVaultSetup(client *api.Client, initRes *api.InitResponse) error {
	if err := Unseal(client, initRes); err != nil {
		return err
	}

	client.SetToken(initRes.RootToken)

	if err := Write(client, "vault_init", initRes); err != nil {
		zap.L().Warn("💡 Failed to persist init result, re-unsealing may be needed next time", zap.Error(err))
	}

	return nil
}

func Unseal(client *api.Client, init *api.InitResponse) error {
	zap.L().Info("🔐 Submitting unseal keys to Vault")
	for i := 0; i < 3; i++ {
		resp, err := client.Sys().Unseal(init.KeysB64[i])
		if err != nil {
			return fmt.Errorf("unseal key %d failed: %w", i+1, err)
		}
		zap.L().Info("🔑 Unseal key accepted", zap.Int("submitted", i+1), zap.Bool("sealed", resp.Sealed))
		if !resp.Sealed {
			zap.L().Info("✅ Vault is unsealed")
			return nil
		}
	}
	return errors.New("vault remains sealed after 3 unseal keys")
}

func LoadInitResultOrPrompt(client *api.Client) (*api.InitResponse, error) {
	initRes := new(api.InitResponse)
	if err := ReadFallbackJSON(shared.VaultInitPath, initRes); err != nil {
		zap.L().Warn("⚠️ Fallback file missing, prompting user", zap.Error(err))
		return PromptForInitResult()
	}
	return initRes, nil
}

func ConfirmUnsealMaterialSaved(init *api.InitResponse) error {
	fmt.Println("\n🔐 Re-enter 3 unseal keys + root token to confirm you've saved them.")
	keys, err := interaction.PromptSecrets("Unseal Key", 3)
	if err != nil {
		return err
	}
	root, err := interaction.PromptSecrets("Root Token", 1)
	if err != nil {
		return err
	}

	if crypto.HashString(root[0]) != crypto.HashString(init.RootToken) {
		return fmt.Errorf("root token mismatch")
	}

	match := 0
	for _, entered := range keys {
		for _, known := range init.KeysB64 {
			if crypto.HashString(entered) == crypto.HashString(known) {
				match++
				break
			}
		}
	}
	if match < 3 {
		return fmt.Errorf("less than 3 unseal keys matched")
	}

	zap.L().Info("✅ User confirmed unseal material backup")
	return nil
}
