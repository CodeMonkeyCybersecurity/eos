// pkg/vault/phase6a_init.go

package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 6a️⃣ Initialize Vault (only — no unseal yet)
//--------------------------------------------------------------------

func InitializeVault(rc *eos_io.RuntimeContext) error {
	client, err := GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("create Vault client: %w", err)
	}

	_, err = PhaseInitVault(rc, client)
	if err != nil {
		return fmt.Errorf("initialize Vault: %w", err)
	}

	return nil
}

// PhaseInitVaultOnly initializes Vault if not already initialized.
func PhaseInitVault(rc *eos_io.RuntimeContext, client *api.Client) (*api.Client, error) {
	otelzap.Ctx(rc.Ctx).Info(" [Phase 6a]: Initialize Vault")

	status, err := client.Sys().InitStatus()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to check Vault initialization status", zap.Error(err))
		return nil, fmt.Errorf("check vault init status: %w", err)
	}
	if status {
		otelzap.Ctx(rc.Ctx).Info(" Vault already initialized — checking for credentials file")

		// SECURITY FIX P0: Handle "already initialized but missing credentials file" edge case
		// This prevents infinite authentication prompts in later phases
		if err := handleAlreadyInitialized(rc, client); err != nil {
			return nil, fmt.Errorf("handle already initialized vault: %w", err)
		}
		return client, nil
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault not initialized — beginning initialization sequence")
	initRes, err := InitVault(rc, client)
	if err != nil {
		return nil, fmt.Errorf("initialize vault: %w", err)
	}

	if err := SaveInitResult(rc, initRes); err != nil {
		// CRITICAL: Never print vault tokens/keys to console - security violation
		logger := otelzap.Ctx(rc.Ctx)
		logger.Error("Failed to persist Vault init result - initialization data lost",
			zap.Error(err),
			zap.String("security_note", "vault tokens and keys not saved"))
		logger.Info("terminal prompt: Vault initialization failed - keys and tokens could not be saved securely")
		return nil, fmt.Errorf("save vault init result: %w", err)
	}

	// CRITICAL FIX: Display security warnings about insecure key storage
	// This addresses the security requirement from the specification:
	// Users MUST be warned that storing all 5 unseal keys together violates
	// Shamir's Secret Sharing model and is only safe for development/testing
	DisplaySecurityWarnings(rc, shared.VaultInitPath)

	// CRITICAL: Prompt for key distribution immediately after initialization
	// This ensures keys are properly distributed before continuing
	otelzap.Ctx(rc.Ctx).Info(" Prompting for key distribution...")
	if err := DistributeInitKeys(rc, initRes); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Key distribution workflow failed (non-fatal)",
			zap.Error(err))
		otelzap.Ctx(rc.Ctx).Info("terminal prompt:   Keys were saved but not distributed")
		otelzap.Ctx(rc.Ctx).Info("terminal prompt: Run 'eos inspect vault-init' to retrieve keys later")
	}

	otelzap.Ctx(rc.Ctx).Warn("Vault is initialized but NOT unsealed yet")
	otelzap.Ctx(rc.Ctx).Info(" Please run 'eos inspect vault-init' to retrieve your keys and token")
	otelzap.Ctx(rc.Ctx).Info(" Then run 'eos enable vault' to unseal and secure Vault")

	return client, nil
}

// InitVault initializes Vault with default 5 keys, 3 threshold.
// SECURITY: Rate limited to prevent initialization spam attacks
func InitVault(rc *eos_io.RuntimeContext, client *api.Client) (*api.InitResponse, error) {
	// SECURITY: Apply rate limiting to prevent brute force initialization attempts
	if err := RateLimitVaultOperation(rc, VaultOpInit); err != nil {
		return nil, err
	}

	initOptions := &api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}
	initRes, err := client.Sys().Init(initOptions)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Vault initialization failed", zap.Error(err))
		return nil, fmt.Errorf("vault init API call: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info(" Vault initialized successfully",
		zap.Int("num_keys", len(initRes.KeysB64)),
		zap.String("root_token_hash", crypto.HashString(initRes.RootToken)),
	)
	return initRes, nil
}

// SaveInitResult saves the Vault initialization result securely to disk.
// handleAlreadyInitialized checks if vault_init.json exists when Vault is already initialized.
// If the file is missing, it prompts the user for recovery and saves the credentials.
// This prevents the infinite authentication prompt loop in later phases.
func handleAlreadyInitialized(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	path := shared.VaultInitPath

	// Check if credentials file exists
	logger.Debug("Checking for vault init credentials file", zap.String("path", path))
	if _, err := os.Stat(path); err == nil {
		// File exists - verify it's valid
		logger.Info(" Vault credentials file found", zap.String("path", path))
		var initRes api.InitResponse
		if err := ReadFallbackJSON(rc, path, &initRes); err != nil {
			logger.Warn("Vault credentials file is corrupted", zap.Error(err))
			return handleMissingOrCorruptedCredentials(rc, client, path)
		}
		if err := VerifyInitResult(rc, &initRes); err != nil {
			logger.Warn("Vault credentials file is invalid", zap.Error(err))
			return handleMissingOrCorruptedCredentials(rc, client, path)
		}
		logger.Info(" Vault credentials file is valid")
		return nil
	}

	// File doesn't exist - this is the problematic edge case
	logger.Warn(" Vault is initialized but credentials file is missing",
		zap.String("expected_path", path),
		zap.String("issue", "This will cause authentication prompts in every phase"))

	return handleMissingOrCorruptedCredentials(rc, client, path)
}

// handleMissingOrCorruptedCredentials prompts the user for Vault credentials and saves them.
// This provides recovery for the edge case where Vault is initialized but vault_init.json is missing.
func handleMissingOrCorruptedCredentials(rc *eos_io.RuntimeContext, client *api.Client, path string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Warn(" VAULT CREDENTIALS RECOVERY MODE")
	logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Vault is already initialized but the credentials file is missing or corrupted.")
	logger.Info("This can happen if:")
	logger.Info("  1. Vault was initialized previously and the file was deleted")
	logger.Info("  2. A previous installation was interrupted")
	logger.Info("  3. File permissions prevented writing the credentials")
	logger.Info("")
	logger.Info("You will be prompted to enter the Vault unseal keys and root token.")
	logger.Info("These credentials will be saved securely to prevent repeated prompts.")
	logger.Info("")

	logger.Info("terminal prompt: Do you have the Vault unseal keys and root token? (y/N)")
	var response string
	shared.SafeScanln(&response)

	if strings.ToLower(strings.TrimSpace(response)) != "y" {
		logger.Error(" Cannot proceed without Vault credentials")
		logger.Info("Options:")
		logger.Info("  1. If this is a test/dev environment: sudo eos delete vault && sudo eos create vault")
		logger.Info("  2. If this is production: Locate the vault_init.json backup")
		logger.Info("  3. Contact your Vault administrator for the unseal keys and root token")
		return fmt.Errorf("vault credentials recovery aborted by user")
	}

	// Prompt for credentials with recovery context
	logger.Info(" Please enter the Vault credentials for recovery")
	initRes, err := PromptForInitResult(rc)
	if err != nil {
		logger.Error("Failed to read credentials from prompt", zap.Error(err))
		return fmt.Errorf("credential recovery prompt failed: %w", err)
	}

	// Verify the credentials work before saving
	logger.Info(" Verifying provided credentials against Vault")
	if err := VerifyRootToken(rc, client, initRes.RootToken); err != nil {
		logger.Error(" Provided root token is invalid", zap.Error(err))
		return fmt.Errorf("credential verification failed: %w", err)
	}

	// Save the verified credentials
	logger.Info(" Credentials verified — saving to prevent future prompts")
	if err := SaveInitResult(rc, initRes); err != nil {
		logger.Error("Failed to save verified credentials", zap.Error(err))
		return fmt.Errorf("save credentials failed: %w", err)
	}

	logger.Info(" Vault credentials recovered and saved successfully",
		zap.String("path", path))
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	return nil
}

func SaveInitResult(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
	path := shared.VaultInitPath
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, VaultDataDirPerm); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to create init directory", zap.String("dir", dir), zap.Error(err))
		return fmt.Errorf("create init dir: %w", err)
	}

	b, err := json.MarshalIndent(initRes, "", "  ")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to marshal Vault init result", zap.Error(err))
		return fmt.Errorf("marshal init result: %w", err)
	}

	if err := os.WriteFile(path, b, VaultSecretFilePerm); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to write Vault init file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("write init result: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault init result saved securely", zap.String("path", path))
	return nil
}
