// pkg/vault/phase6b_unseal.go

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 6b.  Unseal Vault
//--------------------------------------------------------------------

// PHASE 6 — PhaseInitAndUnsealVault()
//             └── SetupVault()
//                 └── initAndUnseal()
//                 └── finalizeVaultSetup()
//                     └── UnsealVault()
//                     └── Write()

// PhaseInitAndUnsealVault is the entry point when Vault is uninitialized.
// It initializes Vault if necessary, confirms safe backup of init materials,
// unseals Vault, and stores a fallback copy of the init result.
func PhaseInitAndUnsealVault(client *api.Client) (*api.Client, error) {
	zap.L().Info("[5/6] Initializing and unsealing Vault if necessary")

	status, err := client.Sys().InitStatus()
	if err != nil {
		zap.L().Error("❌ Failed to check Vault init status", zap.Error(err))
		return nil, err
	}
	if status {
		zap.L().Info("🔓 Vault is already initialized — skipping")
		return client, nil
	}

	zap.L().Info("⚙️ Vault not initialized — starting initialization sequence")
	initRes, err := InitVault(client)
	if err != nil {
		return nil, err
	}

	if err := PromptToSaveVaultInitData(initRes); err != nil {
		return nil, err
	}

	if err := ConfirmUnsealMaterialSaved(initRes); err != nil {
		return nil, err
	}

	if err := SaveInitResult(initRes); err != nil {
		return nil, err
	}

	if err := UnsealVault(client, initRes); err != nil {
		return nil, err
	}

	zap.L().Info("✅ Vault initialization and unsealing complete")
	return client, nil
}

func SetupVault(client *api.Client) (*api.Client, *api.InitResponse, error) {
	zap.L().Info("⚙️ Starting Vault setup")

	// Step 1: Attempt initialization with timeout
	zap.L().Debug("⏱️ Creating context for Vault init with 30s timeout")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	zap.L().Info("🧪 Attempting Vault initialization")
	initRes, err := client.Sys().InitWithContext(ctx, &api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		// Step 2: Handle already-initialized fallback
		if IsAlreadyInitialized(err) {
			zap.L().Info("ℹ️ Vault already initialized — attempting reuse via fallback")

			initRes, err := LoadInitResultOrPrompt(client)
			if err != nil {
				zap.L().Error("❌ Failed to reuse init result", zap.Error(err))
				zap.L().Warn("💡 Run `eos enable vault` on a fresh Vault to regenerate fallback data")
				return nil, nil, fmt.Errorf("vault already initialized and fallback failed: %w", err)
			}

			zap.L().Debug("🔓 Reusing init result — attempting unseal + persist")
			if err := finalizeVaultSetup(client, initRes); err != nil {
				zap.L().Error("❌ Failed to finalize Vault setup from fallback", zap.Error(err))
				return nil, nil, fmt.Errorf("failed to finalize reused Vault setup: %w", err)
			}

			zap.L().Info("✅ Vault setup finalized from fallback")
			return client, initRes, nil
		}

		// Unknown error: surface context-related issues clearly
		zap.L().Error("❌ Vault initialization failed", zap.Error(err))
		if errors.Is(err, context.DeadlineExceeded) {
			zap.L().Warn("💡 Vault init timed out — is the Vault API responding on the correct port?")
		} else if strings.Contains(err.Error(), "connection refused") {
			zap.L().Warn("💡 Vault appears down — check systemd status or port binding")
		}
		return nil, nil, fmt.Errorf("vault init error: %w", err)
	}

	// Step 3: Successful init
	zap.L().Info("🎉 Vault successfully initialized")

	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		zap.L().Error("❌ Init result missing unseal keys or root token")
		return nil, nil, fmt.Errorf("invalid init result returned by Vault")
	}

	if err := finalizeVaultSetup(client, initRes); err != nil {
		zap.L().Error("❌ Final Vault setup failed", zap.Error(err))
		return nil, nil, fmt.Errorf("vault finalize setup error: %w", err)
	}

	zap.L().Info("✅ Vault setup completed and ready")
	zap.L().Info("📁 Vault unseal keys and root token stored to fallback file and Vault KV")
	return client, initRes, nil
}

// initAndUnseal is called when /sys/health returns 501 (uninitialized).
func initAndUnseal(c *api.Client) error {
	_, _, err := SetupVault(c)
	return err
}

func finalizeVaultSetup(client *api.Client, initRes *api.InitResponse) error {
	zap.L().Info("🔐 Finalizing Vault setup")

	// Step 0: Defensive validation of initRes
	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		zap.L().Error("❌ Invalid init result: missing keys or root token")
		return fmt.Errorf("invalid init result: missing keys or token")
	}

	// Step 1: Attempt unseal
	zap.L().Debug("🔓 Attempting to unseal Vault using init result")
	if err := UnsealVault(client, initRes); err != nil {
		zap.L().Error("❌ Failed to unseal Vault", zap.Error(err))
		zap.L().Warn("💡 Make sure Vault is running and the unseal keys are correct")
		return fmt.Errorf("failed to unseal vault: %w", err)
	}
	zap.L().Info("✅ Vault unsealed successfully")

	// (Optional) Verify unseal status
	sealStatus, err := client.Sys().SealStatus()
	if err != nil {
		zap.L().Warn("⚠️ Failed to verify seal status after unsealing", zap.Error(err))
	} else if sealStatus.Sealed {
		zap.L().Error("❌ Vault reports still sealed after unseal attempt")
		return fmt.Errorf("vault still sealed after unseal")
	}

	// Step 2: Set root token
	zap.L().Debug("🔑 Setting root token on Vault client")
	client.SetToken(initRes.RootToken)

	// Step 3: Write init result for future reuse
	zap.L().Debug("💾 Persisting Vault init result")
	if err := Write(client, "vault_init", initRes); err != nil {
		zap.L().Error("❌ Failed to persist Vault init result", zap.Error(err))
		zap.L().Warn("💡 This will require re-unsealing on next run if not stored")
		return fmt.Errorf("failed to persist init result: %w", err)
	}

	zap.L().Info("📦 Vault init result written to Vault backend or fallback")
	return nil
}

// UnsealVault attempts to unseal Vault using either fallback file or interactive prompts.
func UnsealVault(client *api.Client, init *api.InitResponse) error {
	// Submit 3 of 5 keys interactively
	zap.L().Info("🔐 Submitting unseal keys to Vault")
	for i := 0; i < 3; i++ {
		resp, err := client.Sys().Unseal(init.KeysB64[i])
		if err != nil {
			return fmt.Errorf("failed to submit unseal key %d: %w", i+1, err)
		}
		zap.L().Info("🔑 Unseal key accepted", zap.Int("submitted", i+1), zap.Bool("sealed", resp.Sealed))
		if !resp.Sealed {
			zap.L().Info("✅ Vault is now unsealed")
			return nil
		}
	}
	return errors.New("vault remains sealed after submitting 3 unseal keys")
}

// LoadInitResultOrPrompt tries loading the init result from disk; otherwise prompts the user.
func LoadInitResultOrPrompt(client *api.Client) (*api.InitResponse, error) {
	initRes := new(api.InitResponse)
	if err := ReadFallbackJSON(shared.VaultInitPath, initRes); err != nil {
		zap.L().Warn("⚠️ Fallback file missing or unreadable — prompting user", zap.Error(err))
		return PromptForInitResult()
	}
	zap.L().Info("✅ Vault init result loaded from fallback")
	return initRes, nil
}

func ConfirmUnsealMaterialSaved(init *api.InitResponse) error {
	fmt.Println("\n🔐 Please re-enter 3 of your unseal keys and the root token to confirm you've saved them.")

	keys, err := interaction.PromptSecrets("Unseal Key", 3)
	if err != nil {
		return fmt.Errorf("failed to read unseal keys: %w", err)
	}
	root, err := interaction.PromptSecrets("Root Token", 1)
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

	zap.L().Info("✅ User successfully confirmed unseal material")
	return nil
}
