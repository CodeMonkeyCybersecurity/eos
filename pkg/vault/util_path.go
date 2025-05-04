// pkg/vault/util_path.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// VaultPath returns the full Vault path for a logical entry name.
func VaultPath(name string) string {
	if strings.Contains(name, "/") {
		zap.L().Warn("VaultPath should not receive slashes", zap.String("input", name))
	}
	final := fmt.Sprintf("%s/%s", shared.EosID, name)
	zap.L().Debug("Resolved Vault path", zap.String("input", name), zap.String("result", final))
	return final
}

// DiskPath constructs a fallback config path like: /var/lib/eos/secrets/<name>.json
func DiskPath(name string) string {
	var final string

	// Always prefer storing fallback disk files in SecretsDir
	switch name {
	case "vault_init":
		final = filepath.Join(shared.SecretsDir, "vault_init.json")
	case "delphi_fallback":
		final = filepath.Join(shared.SecretsDir, "delphi_fallback.json")
	case "vault_userpass":
		final = filepath.Join(shared.SecretsDir, "vault_userpass.json")
	default:
		final = filepath.Join(shared.SecretsDir, name+".json")
		zap.L().Warn("DiskPath fallback: unknown name, using default layout", zap.String("name", name))
	}

	zap.L().Debug("Resolved disk path", zap.String("input", name), zap.String("result", final))
	return final
}

// ensureVaultDataDir ensures the Vault data directory exists.
func ensureVaultDataDir() error {
	dataPath := shared.VaultDataPath
	if err := os.MkdirAll(dataPath, 0700); err != nil {
		zap.L().Error("❌ Failed to create Vault data dir", zap.String("path", dataPath), zap.Error(err))
		return fmt.Errorf("failed to create Vault data dir: %w", err)
	}
	zap.L().Info("✅ Vault data directory ready", zap.String("path", dataPath))
	return nil
}
