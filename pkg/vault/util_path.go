// pkg/vault/util_path.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultPath returns the full Vault path for a logical entry name.
func VaultPath(rc *eos_io.RuntimeContext, name string) string {
	if strings.Contains(name, "/") {
		otelzap.Ctx(rc.Ctx).Warn("VaultPath should not receive slashes", zap.String("input", name))
	}
	final := fmt.Sprintf("%s/%s", shared.EosID, name)
	otelzap.Ctx(rc.Ctx).Debug("Resolved Vault path", zap.String("input", name), zap.String("result", final))
	return final
}

// DiskPath constructs a fallback config path like: /var/lib/eos/secrets/<name>.json
func DiskPath(rc *eos_io.RuntimeContext, name string) string {
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
		otelzap.Ctx(rc.Ctx).Warn("DiskPath fallback: unknown name, using default layout", zap.String("name", name))
	}

	otelzap.Ctx(rc.Ctx).Debug("Resolved disk path", zap.String("input", name), zap.String("result", final))
	return final
}

// ensureVaultDataDir ensures the Vault data directory exists.
func ensureVaultDataDir(rc *eos_io.RuntimeContext) error {
	dataPath := shared.VaultDataPath
	if err := os.MkdirAll(dataPath, 0700); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to create Vault data dir", zap.String("path", dataPath), zap.Error(err))
		return fmt.Errorf("failed to create Vault data dir: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info("✅ Vault data directory ready", zap.String("path", dataPath))
	return nil
}
