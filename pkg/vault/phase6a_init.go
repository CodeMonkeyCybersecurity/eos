// pkg/vault/phase6a_init.go

package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
		otelzap.Ctx(rc.Ctx).Info(" Vault already initialized — skipping Phase 6a")
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
func SaveInitResult(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
	path := shared.VaultInitPath
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to create init directory", zap.String("dir", dir), zap.Error(err))
		return fmt.Errorf("create init dir: %w", err)
	}

	b, err := json.MarshalIndent(initRes, "", "  ")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to marshal Vault init result", zap.Error(err))
		return fmt.Errorf("marshal init result: %w", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to write Vault init file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("write init result: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault init result saved securely", zap.String("path", path))
	return nil
}
