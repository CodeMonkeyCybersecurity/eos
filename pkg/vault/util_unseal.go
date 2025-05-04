// pkg/vault/util_unseal.go

package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// loadUnsealKeys loads unseal keys and root token from disk or prompt.
func loadUnsealKeys() (*api.InitResponse, error) {
	initRes, err := LoadOrPromptInitResult()
	if err != nil {
		return nil, fmt.Errorf("could not load stored unseal keys: %w", err)
	}
	return initRes, nil
}

// UnsealVaultIfNeeded attempts to unseal Vault if it's currently sealed.
// It returns true if unsealing was performed, false if not needed.
func UnsealVaultIfNeeded(client *api.Client) (bool, error) {
	status, err := client.Sys().SealStatus()
	if err != nil {
		return false, fmt.Errorf("could not get seal status: %w", err)
	}
	if !status.Sealed {
		zap.L().Info("🔓 Vault is already unsealed")
		return false, nil
	}

	initRes, err := loadUnsealKeys()
	if err != nil {
		return false, err
	}

	// Preload root token even before successful unseal
	client.SetToken(initRes.RootToken)

	for i, key := range initRes.KeysB64 {
		zap.L().Debug("🔐 Submitting unseal key", zap.Int("index", i))
		statusResp, err := client.Sys().Unseal(key)
		if err != nil {
			zap.L().Warn("❌ Unseal key submission failed", zap.Int("index", i), zap.Error(err))
			continue
		}
		if !statusResp.Sealed {
			zap.L().Info("✅ Vault successfully unsealed", zap.Int("used_keys", i+1))
			return true, nil
		}
	}

	return false, fmt.Errorf("vault still sealed after submitting all keys")
}

// MustUnseal ensures Vault is unsealed or returns an error.
// Useful for callers that expect (error), not (bool, error).
func MustUnseal(client *api.Client) error {
	_, err := UnsealVaultIfNeeded(client)
	return err
}
