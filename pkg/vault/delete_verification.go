// pkg/vault/delete_verification.go
// Security verification for Vault deletion operations

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerifyDeletionCredentials prompts the user for root token and 3 unseal keys,
// then verifies them against the Vault instance before allowing deletion.
// This provides a strong security check to prevent accidental data loss.
func VerifyDeletionCredentials(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("════════════════════════════════════════════════════════════════════")
	logger.Info("SECURITY VERIFICATION REQUIRED")
	logger.Info("════════════════════════════════════════════════════════════════════")
	logger.Info("")
	logger.Info("To prevent accidental data loss, you must provide:")
	logger.Info("  1. Root token (for verification)")
	logger.Info("  2. Three (3) unseal keys (to prove you have the master keys)")
	logger.Info("")
	logger.Info("This ensures you have the necessary credentials to recover this Vault")
	logger.Info("instance if deletion is a mistake.")
	logger.Info("")

	// Step 1: Prompt for root token
	logger.Info("terminal prompt: Step 1/2: Root Token Verification")
	rootToken, err := interaction.PromptSecret(rc.Ctx, "Root Token")
	if err != nil {
		return fmt.Errorf("failed to read root token: %w", err)
	}

	// Verify root token against Vault API
	logger.Info("Verifying root token against Vault...")
	if err := VerifyRootToken(rc, client, rootToken); err != nil {
		logger.Error("Root token verification failed",
			zap.Error(err),
			zap.String("remediation", "Ensure you're using the correct root token from Vault initialization"))
		return fmt.Errorf("root token verification failed: %w\n\n"+
			"The provided root token is invalid or has been revoked.\n"+
			"Cannot proceed with Vault deletion without valid root token.", err)
	}

	logger.Info("✓ Root token verified successfully")
	logger.Info("")

	// Step 2: Prompt for unseal keys
	logger.Info("terminal prompt: Step 2/2: Unseal Keys Verification")
	logger.Info("terminal prompt: Please enter 3 unseal keys (base64-encoded)")

	unsealKeys, err := interaction.PromptSecrets(rc.Ctx, "Unseal Key", 3)
	if err != nil {
		return fmt.Errorf("failed to read unseal keys: %w", err)
	}

	// Verify unseal keys by attempting to use them
	// This requires sealing Vault first, then unsealing with provided keys
	logger.Info("Verifying unseal keys...")
	if err := verifyUnsealKeys(rc, client, unsealKeys, rootToken); err != nil {
		logger.Error("Unseal keys verification failed",
			zap.Error(err),
			zap.String("remediation", "Ensure you're using the correct unseal keys from Vault initialization"))
		return fmt.Errorf("unseal key verification failed: %w\n\n"+
			"One or more of the provided unseal keys is invalid.\n"+
			"Cannot proceed with Vault deletion without valid unseal keys.", err)
	}

	logger.Info("✓ All 3 unseal keys verified successfully")
	logger.Info("")
	logger.Info("════════════════════════════════════════════════════════════════════")
	logger.Info("CREDENTIALS VERIFIED - Deletion authorized")
	logger.Info("════════════════════════════════════════════════════════════════════")
	logger.Info("")

	return nil
}

// verifyUnsealKeys verifies that the provided unseal keys are valid by
// sealing Vault and then unsealing it with the provided keys.
// This is a destructive test but necessary to prove the user has the correct keys.
func verifyUnsealKeys(rc *eos_io.RuntimeContext, client *api.Client, keys []string, rootToken string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check current seal status
	status, err := client.Sys().SealStatus()
	if err != nil {
		return fmt.Errorf("failed to get seal status: %w", err)
	}

	logger.Debug("Current Vault seal status",
		zap.Bool("sealed", status.Sealed),
		zap.Int("threshold", status.T),
		zap.Int("shares", status.N))

	// If Vault is unsealed, we need to seal it first to test the keys
	wasSealed := status.Sealed
	if !status.Sealed {
		logger.Info("Sealing Vault to verify unseal keys...")
		// Set root token first (required for seal operation)
		client.SetToken(rootToken)

		if err := client.Sys().Seal(); err != nil {
			return fmt.Errorf("failed to seal Vault for key verification: %w", err)
		}
		logger.Debug("Vault sealed successfully for key verification")
	}

	// Now attempt to unseal with provided keys
	logger.Info("Testing unseal keys...")
	unsealed := false
	for i, key := range keys {
		logger.Debug("Submitting unseal key", zap.Int("index", i+1))

		statusResp, err := client.Sys().Unseal(key)
		if err != nil {
			// If unseal fails, try to restore state if we sealed it
			if !wasSealed {
				logger.Warn("Unseal key verification failed, attempting to restore Vault unsealed state")
				// Try to unseal with stored keys as fallback
				restoreVaultState(rc, client)
			}
			return fmt.Errorf("unseal key %d is invalid: %w", i+1, err)
		}

		logger.Debug("Unseal key accepted",
			zap.Int("index", i+1),
			zap.Int("progress", statusResp.Progress),
			zap.Int("threshold", statusResp.T),
			zap.Bool("sealed", statusResp.Sealed))

		if !statusResp.Sealed {
			logger.Info("Vault successfully unsealed with provided keys",
				zap.Int("keys_used", i+1))
			unsealed = true
			break
		}
	}

	if !unsealed {
		// Verification failed - try to restore state
		if !wasSealed {
			logger.Warn("Failed to unseal with provided keys, attempting to restore Vault state")
			restoreVaultState(rc, client)
		}
		return fmt.Errorf("vault still sealed after submitting all %d keys - keys are insufficient or invalid", len(keys))
	}

	// Success - keys are valid
	// Restore root token for subsequent operations
	client.SetToken(rootToken)

	return nil
}

// restoreVaultState attempts to restore Vault to unsealed state using stored keys
// This is a fallback recovery mechanism if user-provided keys fail verification
func restoreVaultState(rc *eos_io.RuntimeContext, client *api.Client) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Attempting to restore Vault to unsealed state using stored credentials")

	// Try to load stored init result
	initRes, err := LoadOrPromptInitResult(rc)
	if err != nil {
		logger.Error("Failed to load stored credentials for recovery",
			zap.Error(err),
			zap.String("remediation", "You may need to manually unseal Vault with: vault operator unseal"))
		return
	}

	// Set root token
	client.SetToken(initRes.RootToken)

	// Attempt unseal with stored keys
	for i, key := range initRes.KeysB64 {
		statusResp, err := client.Sys().Unseal(key)
		if err != nil {
			logger.Warn("Failed to submit stored unseal key",
				zap.Int("index", i),
				zap.Error(err))
			continue
		}

		if !statusResp.Sealed {
			logger.Info("Vault successfully restored to unsealed state",
				zap.Int("keys_used", i+1))
			return
		}
	}

	logger.Error("Failed to restore Vault state - manual intervention required",
		zap.String("remediation", "Manually unseal Vault with: vault operator unseal"))
}
