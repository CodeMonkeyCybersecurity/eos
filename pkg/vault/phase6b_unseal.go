// pkg/vault/phase6b_unseal.go

package vault

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func UnsealVault(rc *eos_io.RuntimeContext) (*api.Client, error) {
	otelzap.Ctx(rc.Ctx).Info(" Entering UnsealVault")

	client, err := GetVaultClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to create Vault client", zap.Error(err))
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	initStatus, err := client.Sys().InitStatus()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to check init status", zap.Error(err))
		return nil, fmt.Errorf("check init status: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info(" InitStatus retrieved", zap.Bool("initialized", initStatus))

	if initStatus {
		otelzap.Ctx(rc.Ctx).Info(" Vault already initialized")

		sealStatus, err := client.Sys().SealStatus()
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Failed to check seal status", zap.Error(err))
			return nil, fmt.Errorf("check seal status: %w", err)
		}
		otelzap.Ctx(rc.Ctx).Info(" SealStatus retrieved", zap.Bool("sealed", sealStatus.Sealed))

		if sealStatus.Sealed {
			otelzap.Ctx(rc.Ctx).Warn(" Vault is initialized but sealed — attempting unseal")

			initRes, loadErr := LoadOrPromptInitResult(rc)
			if loadErr != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to load init result file, falling back to manual prompt", zap.Error(loadErr))

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
			otelzap.Ctx(rc.Ctx).Info(" Init result (or manual input) loaded successfully")

			if err := Unseal(rc, client, initRes); err != nil {
				otelzap.Ctx(rc.Ctx).Error(" Unseal failed", zap.Error(err))
				return nil, fmt.Errorf("unseal vault: %w", err)
			}

			// POST-UNSEAL CHECK
			status, _ := client.Sys().SealStatus()
			if status.Sealed {
				return nil, fmt.Errorf("vault remains sealed after unseal attempt")
			}
			otelzap.Ctx(rc.Ctx).Info(" Vault unsealed successfully")
		} else {
			otelzap.Ctx(rc.Ctx).Info(" Vault is already unsealed")
		}

		return client, nil
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault not initialized — beginning initialization sequence")
	initRes, err := initVaultWithTimeout(rc, client)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Vault init failed", zap.Error(err))
		return nil, err
	}
	otelzap.Ctx(rc.Ctx).Info(" Vault initialized with init response", zap.Int("num_keys", len(initRes.Keys)))

	if err := handleInitMaterial(rc, initRes); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Handling init material failed", zap.Error(err))
		return nil, err
	}

	if err := finalizeVaultSetup(rc, client, initRes); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Finalizing Vault setup failed", zap.Error(err))
		return nil, err
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault initialized and unsealed")
	return client, nil
}

func initVaultWithTimeout(rc *eos_io.RuntimeContext, client *api.Client) (*api.InitResponse, error) {
	otelzap.Ctx(rc.Ctx).Info(" Starting initVaultWithTimeout")

	initRes, err := client.Sys().InitWithContext(rc.Ctx, &api.InitRequest{SecretShares: 5, SecretThreshold: 3})
	if err == nil {
		otelzap.Ctx(rc.Ctx).Info(" Vault init successful")
		return initRes, nil
	}

	otelzap.Ctx(rc.Ctx).Warn("Vault init failed, evaluating error", zap.Error(err))

	if IsAlreadyInitialized(err) {
		otelzap.Ctx(rc.Ctx).Warn("Vault already initialized, loading init result")
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
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Handling init material")

	if len(initRes.Keys) == 0 || initRes.RootToken == "" {
		return fmt.Errorf("invalid init result: missing keys or root token")
	}

	// STEP 1: Save credentials to file FIRST (backup/recovery)
	logger.Info(" Saving Vault initialization credentials securely")
	if err := SaveInitResult(rc, initRes); err != nil {
		return fmt.Errorf("failed to save init credentials: %w", err)
	}
	logger.Info(" Credentials saved to file", zap.String("path", shared.VaultInitPath))

	// STEP 2: Display prominent instructions and PAUSE for user to save externally
	printVaultInitializationInstructions()

	// STEP 3: Wait for user to confirm they've saved the credentials
	logger.Info("terminal prompt: Press ENTER after you have SAVED the credentials to your password manager...")
	fmt.Fprintf(os.Stderr, "Press ENTER to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// STEP 4: Verify they saved it by re-entering credentials
	if err := ConfirmUnsealMaterialSaved(rc, initRes); err != nil {
		return fmt.Errorf("credential confirmation failed: %w", err)
	}

	// STEP 5: Offer to delete local file (best practice for production)
	if shouldDeleteLocalCredentials(rc) {
		logger.Warn(" Deleting local credentials file - ensure you have saved them externally!")
		logger.Info("terminal prompt: Deleting local credential file for security")

		if err := os.Remove(shared.VaultInitPath); err != nil {
			logger.Warn("Failed to delete local credentials file", zap.Error(err))
			// Don't fail - this is optional cleanup
		} else {
			logger.Info(" Local credentials file deleted successfully")
			fmt.Fprintln(os.Stderr, "\n✓ Local credentials file deleted for security")
			fmt.Fprintln(os.Stderr, "  Credentials only exist in your password manager now.")
		}
	} else {
		logger.Info(" Keeping local credentials file")
		fmt.Fprintln(os.Stderr, "\nℹ Local credentials file kept at: "+shared.VaultInitPath)
		fmt.Fprintln(os.Stderr, "  Consider deleting this file after distributing keys to operators.")
	}

	return nil
}

// printVaultInitializationInstructions displays clear, prominent instructions
// for saving Vault initialization credentials (Tier 2 security best practice)
func printVaultInitializationInstructions() {
	fmt.Fprintln(os.Stderr, "\n"+strings.Repeat("=", 70))
	fmt.Fprintln(os.Stderr, "  ⚠️  VAULT INITIALIZED SUCCESSFULLY")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 70))
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "CRITICAL: Your unseal keys and root token are ready.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "WITHOUT THESE CREDENTIALS YOU CANNOT RECOVER YOUR VAULT!")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 70))
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, " STEP 1: Open a SECOND terminal session and run:")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    sudo cat /var/lib/eos/secret/vault_init.json")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    OR")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    sudo eos read vault-init")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "💾 STEP 2: Copy ALL credentials to your password manager:")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    • All 5 unseal keys (you need 3 minimum to unseal)")
	fmt.Fprintln(os.Stderr, "    • Root token (provides admin access)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "✅ STEP 3: Verify you saved them correctly!")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "   Recommended password managers:")
	fmt.Fprintln(os.Stderr, "    • 1Password (use Secure Notes)")
	fmt.Fprintln(os.Stderr, "    • Bitwarden (use Secure Notes)")
	fmt.Fprintln(os.Stderr, "    • KeePassXC (use Notes field)")
	fmt.Fprintln(os.Stderr, "    • Encrypted file on separate device")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "⚠️  PRODUCTION TIP:")
	fmt.Fprintln(os.Stderr, "   For high security, distribute different keys to different operators")
	fmt.Fprintln(os.Stderr, "   (Shamir's Secret Sharing - requires 3 of 5 keys to unseal)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 70))
	fmt.Fprintln(os.Stderr, "")
}

// shouldDeleteLocalCredentials asks user if they want to delete the local file
func shouldDeleteLocalCredentials(rc *eos_io.RuntimeContext) bool {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 70))
	fmt.Fprintln(os.Stderr, "SECURITY RECOMMENDATION:")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "For production environments, you should DELETE the local credentials file")
	fmt.Fprintln(os.Stderr, "after you've saved them to your password manager.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "This prevents all keys from being stored in one location.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "For development/lab environments, keeping the file is fine for convenience.")
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 70))
	fmt.Fprintln(os.Stderr, "")

	return interaction.PromptYesNo(
		rc.Ctx,
		"Delete local credentials file? (you MUST have saved them externally first)",
		false, // Default: no (safe default)
	)
}

func finalizeVaultSetup(rc *eos_io.RuntimeContext, client *api.Client, initRes *api.InitResponse) error {
	otelzap.Ctx(rc.Ctx).Info(" Finalizing Vault setup")
	if err := Unseal(rc, client, initRes); err != nil {
		return err
	}

	client.SetToken(initRes.RootToken)
	otelzap.Ctx(rc.Ctx).Info(" Root token set on client")

	if err := Write(rc, client, "vault_init", initRes); err != nil {
		otelzap.Ctx(rc.Ctx).Warn(" Failed to persist init result, re-unsealing may be needed next time", zap.Error(err))
	}

	return nil
}

func Unseal(rc *eos_io.RuntimeContext, client *api.Client, init *api.InitResponse) error {
	otelzap.Ctx(rc.Ctx).Info(" Submitting unseal keys to Vault")
	for i := 0; i < 3; i++ {
		otelzap.Ctx(rc.Ctx).Debug(" Submitting unseal key", zap.Int("index", i))
		resp, err := client.Sys().Unseal(init.KeysB64[i])
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Unseal key submission failed", zap.Int("index", i), zap.Error(err))
			return fmt.Errorf("unseal key %d failed: %w", i+1, err)
		}
		otelzap.Ctx(rc.Ctx).Info(" Unseal key accepted", zap.Int("submitted", i+1), zap.Bool("sealed", resp.Sealed))
		if !resp.Sealed {
			otelzap.Ctx(rc.Ctx).Info(" Vault is unsealed")
			return nil
		}
	}
	return errors.New("vault remains sealed after 3 unseal keys")
}

func ConfirmUnsealMaterialSaved(rc *eos_io.RuntimeContext, init *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("terminal prompt: Re-enter 3 unseal keys + root token to confirm you've saved them.")
	keys, err := interaction.PromptSecrets(rc.Ctx, "Unseal Key", 3)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to prompt unseal keys", zap.Error(err))
		return err
	}
	root, err := interaction.PromptSecrets(rc.Ctx, "Root Token", 1)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to prompt root token", zap.Error(err))
		return err
	}

	if crypto.HashString(root[0]) != crypto.HashString(init.RootToken) {
		otelzap.Ctx(rc.Ctx).Error(" Root token mismatch")
		return fmt.Errorf("root token mismatch")
	}

	match := 0
	for _, entered := range keys {
		// Check against both base64 keys (KeysB64) and hex keys (Keys)
		// Users might copy either format from the JSON file
		matched := false

		// Try base64 format first (most common)
		for _, known := range init.KeysB64 {
			if crypto.HashString(entered) == crypto.HashString(known) {
				match++
				matched = true
				break
			}
		}

		// If not matched in base64, try hex format
		if !matched && len(init.Keys) > 0 {
			for _, known := range init.Keys {
				if crypto.HashString(entered) == crypto.HashString(known) {
					match++
					break
				}
			}
		}
	}

	if match < 3 {
		logger.Error(" Less than 3 unseal keys matched", zap.Int("matched", match))
		logger.Debug("Comparison details",
			zap.Int("entered_keys", len(keys)),
			zap.Int("available_base64_keys", len(init.KeysB64)),
			zap.Int("available_hex_keys", len(init.Keys)))
		return fmt.Errorf("less than 3 unseal keys matched (got %d matches)", match)
	}

	otelzap.Ctx(rc.Ctx).Info(" User confirmed unseal material backup")
	return nil
}
