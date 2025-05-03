// pkg/vault/phase4_config.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 4️⃣ Render, Write, Validate Vault Configuration vault.hcl
//--------------------------------------------------------------------

func WriteAndValidateConfig() error {
	if err := PhaseEnsureVaultConfigExists(); err != nil {
		return err
	}
	if err := PhasePatchVaultConfigIfNeeded(); err != nil {
		return err
	}
	if err := ValidateVaultConfig(); err != nil {
		return err
	}
	return nil
}

// PhaseEnsureVaultConfigExists ensures that Vault's server config exists or writes a default.
func PhaseEnsureVaultConfigExists() error {
	zap.L().Info("📋 Checking if Vault config exists", zap.String("path", shared.VaultConfigPath))
	if _, err := os.Stat(shared.VaultConfigPath); os.IsNotExist(err) {
		zap.L().Warn("⚠️ Vault config missing — generating default vault.hcl", zap.String("path", shared.VaultConfigPath))
		if err := WriteVaultHCL(); err != nil {
			zap.L().Error("❌ Failed to write vault.hcl", zap.Error(err))
			return fmt.Errorf("write vault.hcl: %w", err)
		}
		zap.L().Info("✅ Default vault.hcl written successfully", zap.String("path", shared.VaultConfigPath))
	} else if err != nil {
		zap.L().Error("❌ Error checking vault config", zap.Error(err))
		return fmt.Errorf("check vault config: %w", err)
	} else {
		zap.L().Info("✅ Vault config already present", zap.String("path", shared.VaultConfigPath))
	}
	return nil
}

// PhasePatchVaultConfigIfNeeded detects legacy port 8200 and patches to 8179 if needed.
func PhasePatchVaultConfigIfNeeded() error {
	zap.L().Info("🔎 Checking for Vault port mismatch (8200 → 8179)", zap.String("path", shared.VaultConfigPath))

	data, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		zap.L().Warn("⚠️ Could not read vault config file — skipping patch", zap.Error(err))
		return nil
	}
	content := string(data)

	if strings.Contains(content, shared.VaultDefaultPort) {
		zap.L().Info("✅ Vault already configured for port 8179 — no patch needed")
		return nil
	}

	if !strings.Contains(content, "8200") {
		zap.L().Info("ℹ️ No 8200 port found in config — no patch needed")
		return nil
	}

	zap.L().Warn("🔧 Detected legacy port 8200 — patching to 8179")

	// Replace and rewrite
	newContent := strings.ReplaceAll(content, "8200", shared.VaultDefaultPort)
	if err := os.WriteFile(shared.VaultConfigPath, []byte(newContent), 0644); err != nil {
		zap.L().Error("❌ Failed to patch vault.hcl", zap.Error(err))
		return fmt.Errorf("failed to patch vault config: %w", err)
	}

	zap.L().Info("✅ Vault config patched to 8179 — manual Vault restart required", zap.String("path", shared.VaultConfigPath))
	return nil
}

// ValidateVaultConfig validates Vault configuration using Vault binary itself.
func ValidateVaultConfig() error {
	zap.L().Info("🧪 Validating vault.hcl", zap.String("path", shared.VaultConfigPath))

	info, err := os.Stat(shared.VaultConfigPath)
	if err != nil {
		zap.L().Error("❌ Vault config file not found", zap.Error(err))
		return fmt.Errorf("vault config missing: %w", err)
	}
	if info.Size() == 0 {
		zap.L().Error("❌ Vault config file is empty")
		return fmt.Errorf("vault config file empty")
	}

	// Optionally: simple keyword checks
	expected := []string{"listener", "storage", "api_addr"}
	content, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		zap.L().Error("Failed to read config", zap.Error(err))
		return fmt.Errorf("read config failed: %w", err)
	}
	for _, keyword := range expected {
		if !strings.Contains(string(content), keyword) {
			zap.L().Warn("⚠️ Vault config missing expected keyword", zap.String("keyword", keyword))
		}
	}

	zap.L().Info("✅ Vault configuration validated successfully")
	return nil
}

// WriteVaultHCL renders the Vault server configuration (HCL) dynamically
// and writes it to the expected config file on disk. Ensures the directory exists.
// Returns a wrapped error if writing fails.
func WriteVaultHCL() error {
	vaultAddr := shared.GetVaultAddr()
	hcl := shared.RenderVaultConfig(vaultAddr)
	configPath := shared.VaultConfigPath // should be: /etc/vault.d/vault.hcl

	// Guarantee the parent directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		zap.L().Error("failed to create Vault config directory", zap.String("path", dir), zap.Error(err))
		return fmt.Errorf("mkdir vault config dir: %w", err)
	}
	zap.L().Debug("✅ Vault config directory ready", zap.String("path", dir))

	// Now safely write the Vault config
	if err := os.WriteFile(configPath, []byte(hcl), 0644); err != nil {
		zap.L().Error("failed to write Vault HCL config", zap.Error(err))
		return fmt.Errorf("write vault hcl: %w", err)
	}

	zap.L().Info("✅ Vault configuration written", zap.String("path", configPath))
	return nil
}
