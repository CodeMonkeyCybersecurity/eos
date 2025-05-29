// pkg/vault/phase6b_unseal.go

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func UnsealVault(rc *eos_io.RuntimeContext) (*api.Client, error) {
	otelzap.Ctx(rc.Ctx).Info("🚀 Entering UnsealVault")

	client, err := NewClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to create Vault client", zap.Error(err))
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	initStatus, err := client.Sys().InitStatus()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to check init status", zap.Error(err))
		return nil, fmt.Errorf("check init status: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info("ℹ️ InitStatus retrieved", zap.Bool("initialized", initStatus))

	if initStatus {
		otelzap.Ctx(rc.Ctx).Info("🔓 Vault already initialized")

		sealStatus, err := client.Sys().SealStatus()
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("❌ Failed to check seal status", zap.Error(err))
			return nil, fmt.Errorf("check seal status: %w", err)
		}
		otelzap.Ctx(rc.Ctx).Info("ℹ️ SealStatus retrieved", zap.Bool("sealed", sealStatus.Sealed))

		if sealStatus.Sealed {
			otelzap.Ctx(rc.Ctx).Warn("🔒 Vault is initialized but sealed — attempting unseal")

			initRes, loadErr := LoadOrPromptInitResult(rc)
			if loadErr != nil {
				otelzap.Ctx(rc.Ctx).Warn("⚠️ Failed to load init result file, falling back to manual prompt", zap.Error(loadErr))

				// PROMPT user as final fallback
				keys, err := interaction.PromptSecrets(rc.Ctx, "Unseal Key", 3)
				if err != nil {
					return nil, fmt.Errorf("prompt unseal keys failed: %w", err)
				}
				root, err := interaction.PromptSecrets(rc.Ctx, "Root Token", 1)
				if err != nil {
					return nil, fmt.Errorf("prompt root token failed: %w", err)
				}
				initRes = &api.InitResponse{
					KeysB64:   keys,
					RootToken: root[0],
				}
			}
			otelzap.Ctx(rc.Ctx).Info("✅ Init result (or manual input) loaded successfully")

			if err := Unseal(rc, client, initRes); err != nil {
				otelzap.Ctx(rc.Ctx).Error("❌ Unseal failed", zap.Error(err))
				return nil, fmt.Errorf("unseal vault: %w", err)
			}

			// POST-UNSEAL CHECK
			status, _ := client.Sys().SealStatus()
			if status.Sealed {
				return nil, fmt.Errorf("vault remains sealed after unseal attempt")
			}
			otelzap.Ctx(rc.Ctx).Info("✅ Vault unsealed successfully")
		} else {
			otelzap.Ctx(rc.Ctx).Info("✅ Vault is already unsealed")
		}

		return client, nil
	}

	otelzap.Ctx(rc.Ctx).Info("⚙️ Vault not initialized — beginning initialization sequence")
	initRes, err := initVaultWithTimeout(rc, client)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Vault init failed", zap.Error(err))
		return nil, err
	}
	otelzap.Ctx(rc.Ctx).Info("✅ Vault initialized with init response", zap.Int("num_keys", len(initRes.Keys)))

	if err := handleInitMaterial(rc, initRes); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Handling init material failed", zap.Error(err))
		return nil, err
	}

	if err := finalizeVaultSetup(rc, client, initRes); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Finalizing Vault setup failed", zap.Error(err))
		return nil, err
	}

	otelzap.Ctx(rc.Ctx).Info("✅ Vault initialized and unsealed")
	return client, nil
}

func initVaultWithTimeout(rc *eos_io.RuntimeContext, client *api.Client) (*api.InitResponse, error) {
	otelzap.Ctx(rc.Ctx).Info("🚀 Starting initVaultWithTimeout")

	initRes, err := client.Sys().InitWithContext(rc.Ctx, &api.InitRequest{SecretShares: 5, SecretThreshold: 3})
	if err == nil {
		otelzap.Ctx(rc.Ctx).Info("✅ Vault init successful")
		return initRes, nil
	}

	otelzap.Ctx(rc.Ctx).Warn("⚠️ Vault init failed, evaluating error", zap.Error(err))

	if IsAlreadyInitialized(err) {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Vault already initialized, loading init result")
		return LoadOrPromptInitResult(rc)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("vault init timed out: %w", err)
	}
	if strings.Contains(err.Error(), "connection refused") {
		return nil, fmt.Errorf("vault connection refused: %w", err)
	}

	return nil, fmt.Errorf("vault init error: %w", err)
}

func handleInitMaterial(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
	otelzap.Ctx(rc.Ctx).Info("🚀 Handling init material")
	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		return fmt.Errorf("invalid init result: missing keys or root token")
	}
	if err := ConfirmUnsealMaterialSaved(rc, initRes); err != nil {
		return err
	}
	return SaveInitResult(rc, initRes)
}

func finalizeVaultSetup(rc *eos_io.RuntimeContext, client *api.Client, initRes *api.InitResponse) error {
	otelzap.Ctx(rc.Ctx).Info("🚀 Finalizing Vault setup")
	if err := Unseal(rc, client, initRes); err != nil {
		return err
	}

	client.SetToken(initRes.RootToken)
	otelzap.Ctx(rc.Ctx).Info("ℹ️ Root token set on client")

	if err := Write(rc, client, "vault_init", initRes); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("💡 Failed to persist init result, re-unsealing may be needed next time", zap.Error(err))
	}

	return nil
}

func Unseal(rc *eos_io.RuntimeContext, client *api.Client, init *api.InitResponse) error {
	otelzap.Ctx(rc.Ctx).Info("🔐 Submitting unseal keys to Vault")
	for i := 0; i < 3; i++ {
		otelzap.Ctx(rc.Ctx).Debug("🔑 Submitting unseal key", zap.Int("index", i))
		resp, err := client.Sys().Unseal(init.KeysB64[i])
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("❌ Unseal key submission failed", zap.Int("index", i), zap.Error(err))
			return fmt.Errorf("unseal key %d failed: %w", i+1, err)
		}
		otelzap.Ctx(rc.Ctx).Info("🔑 Unseal key accepted", zap.Int("submitted", i+1), zap.Bool("sealed", resp.Sealed))
		if !resp.Sealed {
			otelzap.Ctx(rc.Ctx).Info("✅ Vault is unsealed")
			return nil
		}
	}
	return errors.New("vault remains sealed after 3 unseal keys")
}

func ConfirmUnsealMaterialSaved(rc *eos_io.RuntimeContext, init *api.InitResponse) error {
	fmt.Println("\n🔐 Re-enter 3 unseal keys + root token to confirm you've saved them.")
	keys, err := interaction.PromptSecrets(rc.Ctx, "Unseal Key", 3)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to prompt unseal keys", zap.Error(err))
		return err
	}
	root, err := interaction.PromptSecrets(rc.Ctx, "Root Token", 1)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to prompt root token", zap.Error(err))
		return err
	}

	if crypto.HashString(root[0]) != crypto.HashString(init.RootToken) {
		otelzap.Ctx(rc.Ctx).Error("❌ Root token mismatch")
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
		otelzap.Ctx(rc.Ctx).Error("❌ Less than 3 unseal keys matched", zap.Int("matched", match))
		return fmt.Errorf("less than 3 unseal keys matched")
	}

	otelzap.Ctx(rc.Ctx).Info("✅ User confirmed unseal material backup")
	return nil
}
