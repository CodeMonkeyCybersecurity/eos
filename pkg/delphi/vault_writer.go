package delphi

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debian"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

// WriteConfig writes Delphi config to Vault (if available), and always to disk as fallback.
func WriteConfig(cfg *Config) error {
	// Always write to disk
	diskPath := xdg.XDGConfigPath(shared.EosID, "delphi.json")
	if err := debian.EnsureDir(diskPath); err != nil {
		zap.L().Warn("❌ Failed to ensure disk config directory", zap.Error(err))
		return fmt.Errorf("unable to create config path: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		zap.L().Warn("❌ Failed to marshal Delphi config", zap.Error(err))
		return fmt.Errorf("unable to marshal config: %w", err)
	}

	if err := os.WriteFile(diskPath, data, 0644); err != nil {
		zap.L().Warn("❌ Failed to write config to disk", zap.Error(err))
		return fmt.Errorf("unable to write config to disk: %w", err)
	}

	zap.L().Info("💾 Delphi config saved to disk", zap.String("path", diskPath))

	// Attempt Vault write (optional)
	if err := vault.Write(nil, VaultDelphiConfig, cfg); err != nil {
		zap.L().Warn("⚠️  Failed to write config to Vault", zap.Error(err))
		// Not fatal — return nil to allow disk-only fallback
		return nil
	}

	zap.L().Info("✅ Delphi config also saved to Vault", zap.String("vault_path", VaultDelphiConfig))
	return nil
}
