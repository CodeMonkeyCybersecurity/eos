package delphi

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

// WriteConfig writes Delphi config to Vault (if available), and always to disk as fallback.
func WriteConfig(cfg *Config, log *zap.Logger) error {
	if log == nil {
		log = zap.NewNop()
	}

	// Always write to disk
	diskPath := xdg.XDGConfigPath("eos", "delphi.json")
	if err := xdg.EnsureDir(diskPath); err != nil {
		log.Warn("❌ Failed to ensure disk config directory", zap.Error(err))
		return fmt.Errorf("unable to create config path: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Warn("❌ Failed to marshal Delphi config", zap.Error(err))
		return fmt.Errorf("unable to marshal config: %w", err)
	}

	if err := os.WriteFile(diskPath, data, 0644); err != nil {
		log.Warn("❌ Failed to write config to disk", zap.Error(err))
		return fmt.Errorf("unable to write config to disk: %w", err)
	}

	log.Info("💾 Delphi config saved to disk", zap.String("path", diskPath))

	// Attempt Vault write (optional)
	if err := vault.Write(nil, VaultDelphiConfig, cfg, log); err != nil {
		log.Warn("⚠️  Failed to write config to Vault", zap.Error(err))
		// Not fatal — return nil to allow disk-only fallback
		return nil
	}

	log.Info("✅ Delphi config also saved to Vault", zap.String("vault_path", VaultDelphiConfig))
	return nil
}
