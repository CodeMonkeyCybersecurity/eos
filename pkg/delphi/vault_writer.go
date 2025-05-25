package delphi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

// WriteConfig writes Delphi config to Vault (if available), and always to disk as fallback.
func WriteConfig(ctx context.Context, cfg *Config) error {
	// 1) Determine file + directory
	diskPath := xdg.XDGConfigPath(shared.EosID, "delphi.json")
	dir := filepath.Dir(diskPath)

	// 2) Ensure directory exists (755 perms)
	if err := eos_unix.MkdirP(ctx, dir, 0o755); err != nil {
		zap.L().Warn("Failed to ensure disk config directory", zap.Error(err))
		return fmt.Errorf("cannot create config dir %q: %w", dir, err)
	}

	// 3) Marshal
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		zap.L().Warn("Failed to marshal Delphi config", zap.Error(err))
		return fmt.Errorf("unable to marshal config: %w", err)
	}

	// 4) Write file
	if err := os.WriteFile(diskPath, data, 0o644); err != nil {
		zap.L().Warn("Failed to write config to disk", zap.Error(err))
		return fmt.Errorf("unable to write config to disk: %w", err)
	}
	zap.L().Info("Delphi config saved to disk", zap.String("path", diskPath))

	// 5) Try Vault, but don’t fail on error
	if err := vault.Write(nil, VaultDelphiConfig, cfg); err != nil {
		zap.L().Warn("Failed to write config to Vault (continuing with disk-only)", zap.Error(err))
	} else {
		zap.L().Info("Delphi config also saved to Vault", zap.String("vault_path", VaultDelphiConfig))
	}
	return nil
}
