// pkg/vault/phase_init.go

package vault

import (
	"encoding/json"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// initVault initializes Vault with default settings (5 keys, 3 threshold).
func InitVault(client *api.Client, log *zap.Logger) (*api.InitResponse, error) {
	initOptions := &api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}
	initRes, err := client.Sys().Init(initOptions)
	if err != nil {
		log.Error("❌ Vault initialization failed", zap.Error(err))
		return nil, err
	}
	log.Info("✅ Vault successfully initialized",
		zap.Int("num_keys", len(initRes.KeysB64)),
		zap.String("root_token_hash", crypto.HashString(initRes.RootToken)))
	return initRes, nil
}

// SaveInitResult stores the init result in fallback path.
func SaveInitResult(initRes *api.InitResponse, log *zap.Logger) error {
	b, err := json.MarshalIndent(initRes, "", "  ")
	if err != nil {
		log.Error("❌ Failed to marshal vault init result", zap.Error(err))
		return err
	}

	path := DiskPath("vault_init", log)
	if err := os.WriteFile(path, b, 0600); err != nil {
		log.Error("❌ Failed to write vault init file", zap.String("path", path), zap.Error(err))
		return err
	}

	log.Info("💾 Vault init result saved", zap.String("path", path))
	return nil
}
