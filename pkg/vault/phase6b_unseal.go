// pkg/vault/phase6b_unseal.go

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
	zap.L().Info("🚀 Entering UnsealVault")

	client, err := CreateVaultClient()
	if err != nil {
		zap.L().Error("❌ Failed to create Vault client", zap.Error(err))
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	initStatus, err := client.Sys().InitStatus()
	if err != nil {
		zap.L().Error("❌ Failed to check init status", zap.Error(err))
		return nil, fmt.Errorf("check init status: %w", err)
	}
	zap.L().Info("ℹ️ InitStatus retrieved", zap.Bool("initialized", initStatus))

	if initStatus {
		zap.L().Info("🔓 Vault already initialized")

		sealStatus, err := client.Sys().SealStatus()
		if err != nil {
			zap.L().Error("❌ Failed to check seal status", zap.Error(err))
			return nil, fmt.Errorf("check seal status: %w", err)
		}
		zap.L().Info("ℹ️ SealStatus retrieved", zap.Bool("sealed", sealStatus.Sealed))

		if sealStatus.Sealed {
			zap.L().Warn("🔒 Vault is initialized but sealed — attempting unseal")

			initRes, loadErr := LoadInitResultOrPrompt(client)
			if loadErr != nil {
				zap.L().Warn("⚠️ Failed to load init result file, falling back to manual prompt", zap.Error(loadErr))

				// PROMPT user as final fallback
				keys, err := interaction.PromptSecrets("Unseal Key", 3)
				if err != nil {
					return nil, fmt.Errorf("prompt unseal keys failed: %w", err)
				}
				root, err := interaction.PromptSecrets("Root Token", 1)
				if err != nil {
					return nil, fmt.Errorf("prompt root token failed: %w", err)
				}
				initRes = &api.InitResponse{
					KeysB64:   keys,
					RootToken: root[0],
				}
			}
			zap.L().Info("✅ Init result (or manual input) loaded successfully")

			if err := Unseal(client, initRes); err != nil {
				zap.L().Error("❌ Unseal failed", zap.Error(err))
				return nil, fmt.Errorf("unseal vault: %w", err)
			}

			// POST-UNSEAL CHECK
			status, _ := client.Sys().SealStatus()
			if status.Sealed {
				return nil, fmt.Errorf("vault remains sealed after unseal attempt")
			}
			zap.L().Info("✅ Vault unsealed successfully")
		} else {
			zap.L().Info("✅ Vault is already unsealed")
		}

		return client, nil
	}

	zap.L().Info("⚙️ Vault not initialized — beginning initialization sequence")
	initRes, err := initVaultWithTimeout(client)
	if err != nil {
		zap.L().Error("❌ Vault init failed", zap.Error(err))
		return nil, err
	}
	zap.L().Info("✅ Vault initialized with init response", zap.Int("num_keys", len(initRes.Keys)))

	if err := handleInitMaterial(initRes); err != nil {
		zap.L().Error("❌ Handling init material failed", zap.Error(err))
		return nil, err
	}

	if err := finalizeVaultSetup(client, initRes); err != nil {
		zap.L().Error("❌ Finalizing Vault setup failed", zap.Error(err))
		return nil, err
	}

	zap.L().Info("✅ Vault initialized and unsealed")
	return client, nil
}

func initVaultWithTimeout(client *api.Client) (*api.InitResponse, error) {
	zap.L().Info("🚀 Starting initVaultWithTimeout")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	initRes, err := client.Sys().InitWithContext(ctx, &api.InitRequest{SecretShares: 5, SecretThreshold: 3})
	if err == nil {
		zap.L().Info("✅ Vault init successful")
		return initRes, nil
	}

	zap.L().Warn("⚠️ Vault init failed, evaluating error", zap.Error(err))

	if IsAlreadyInitialized(err) {
		zap.L().Warn("⚠️ Vault already initialized, loading init result")
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
	zap.L().Info("🚀 Handling init material")
	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		return fmt.Errorf("invalid init result: missing keys or root token")
	}
	if err := ConfirmUnsealMaterialSaved(initRes); err != nil {
		return err
	}
	return SaveInitResult(initRes)
}

func finalizeVaultSetup(client *api.Client, initRes *api.InitResponse) error {
	zap.L().Info("🚀 Finalizing Vault setup")
	if err := Unseal(client, initRes); err != nil {
		return err
	}

	client.SetToken(initRes.RootToken)
	zap.L().Info("ℹ️ Root token set on client")

	if err := Write(client, "vault_init", initRes); err != nil {
		zap.L().Warn("💡 Failed to persist init result, re-unsealing may be needed next time", zap.Error(err))
	}

	return nil
}

func Unseal(client *api.Client, init *api.InitResponse) error {
	zap.L().Info("🔐 Submitting unseal keys to Vault")
	for i := 0; i < 3; i++ {
		zap.L().Debug("🔑 Submitting unseal key", zap.Int("index", i))
		resp, err := client.Sys().Unseal(init.KeysB64[i])
		if err != nil {
			zap.L().Error("❌ Unseal key submission failed", zap.Int("index", i), zap.Error(err))
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

func ConfirmUnsealMaterialSaved(init *api.InitResponse) error {
	fmt.Println("\n🔐 Re-enter 3 unseal keys + root token to confirm you've saved them.")
	keys, err := interaction.PromptSecrets("Unseal Key", 3)
	if err != nil {
		zap.L().Error("❌ Failed to prompt unseal keys", zap.Error(err))
		return err
	}
	root, err := interaction.PromptSecrets("Root Token", 1)
	if err != nil {
		zap.L().Error("❌ Failed to prompt root token", zap.Error(err))
		return err
	}

	if crypto.HashString(root[0]) != crypto.HashString(init.RootToken) {
		zap.L().Error("❌ Root token mismatch")
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
		zap.L().Error("❌ Less than 3 unseal keys matched", zap.Int("matched", match))
		return fmt.Errorf("less than 3 unseal keys matched")
	}

	zap.L().Info("✅ User confirmed unseal material backup")
	return nil
}

func LoadInitResultOrPrompt(client *api.Client) (*api.InitResponse, error) {
	initRes := new(api.InitResponse)
	if err := ReadFallbackJSON(shared.VaultInitPath, initRes); err != nil {
		zap.L().Warn("⚠️ Fallback file missing, prompting user", zap.Error(err))
		return PromptForInitResult()
	}

	// NEW: validate loaded init result
	if err := validateInitResult(initRes); err != nil {
		zap.L().Warn("⚠️ Loaded init result is invalid or incomplete, prompting user", zap.Error(err))
		return PromptForInitResult()
	}

	return initRes, nil
}

func validateInitResult(initRes *api.InitResponse) error {
	if initRes == nil {
		return fmt.Errorf("init result is nil")
	}
	if len(initRes.KeysB64) < 3 {
		return fmt.Errorf("expected at least 3 unseal keys, got %d", len(initRes.KeysB64))
	}
	if strings.TrimSpace(initRes.RootToken) == "" {
		return fmt.Errorf("root token is missing or empty")
	}
	return nil
}
