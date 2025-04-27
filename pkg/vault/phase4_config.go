// pkg/vault/phase4_config.go

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 4️⃣ Render, Write, Validate Vault Configuration vault.hcl
//--------------------------------------------------------------------

// PhaseEnsureVaultConfigExists ensures that Vault's server config exists or writes a default.
func PhaseEnsureVaultConfigExists(log *zap.Logger) error {
	log.Info("📋 Checking if Vault config exists", zap.String("path", shared.VaultConfigPath))
	if _, err := os.Stat(shared.VaultConfigPath); os.IsNotExist(err) {
		log.Warn("⚠️ Vault config missing — generating default vault.hcl", zap.String("path", shared.VaultConfigPath))
		if err := WriteVaultHCL(log); err != nil {
			log.Error("❌ Failed to write vault.hcl", zap.Error(err))
			return fmt.Errorf("write vault.hcl: %w", err)
		}
		log.Info("✅ Default vault.hcl written successfully", zap.String("path", shared.VaultConfigPath))
	} else if err != nil {
		log.Error("❌ Error checking vault config", zap.Error(err))
		return fmt.Errorf("check vault config: %w", err)
	} else {
		log.Info("✅ Vault config already present", zap.String("path", shared.VaultConfigPath))
	}
	return nil
}

// PhasePatchVaultConfigIfNeeded detects legacy port 8200 and patches to 8179 if needed.
func PhasePatchVaultConfigIfNeeded(log *zap.Logger) error {
	log.Info("🔎 Checking for Vault port mismatch (8200 → 8179)", zap.String("path", shared.VaultConfigPath))

	data, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		log.Warn("⚠️ Could not read vault config file — skipping patch", zap.Error(err))
		return nil
	}
	content := string(data)

	if strings.Contains(content, shared.VaultDefaultPort) {
		log.Info("✅ Vault already configured for port 8179 — no patch needed")
		return nil
	}

	if !strings.Contains(content, "8200") {
		log.Info("ℹ️ No 8200 port found in config — no patch needed")
		return nil
	}

	log.Warn("🔧 Detected legacy port 8200 — patching to 8179")

	// Replace and rewrite
	newContent := strings.ReplaceAll(content, "8200", shared.VaultDefaultPort)
	if err := os.WriteFile(shared.VaultConfigPath, []byte(newContent), 0644); err != nil {
		log.Error("❌ Failed to patch vault.hcl", zap.Error(err))
		return fmt.Errorf("failed to patch vault config: %w", err)
	}

	log.Info("✅ Vault config patched to 8179 — manual Vault restart required", zap.String("path", shared.VaultConfigPath))
	return nil
}

// ValidateVaultConfig validates Vault configuration using Vault binary itself.
func ValidateVaultConfig(log *zap.Logger) error {
	log.Info("🧪 Validating vault.hcl", zap.String("path", shared.VaultConfigPath))

	info, err := os.Stat(shared.VaultConfigPath)
	if err != nil {
		log.Error("❌ Vault config file not found", zap.Error(err))
		return fmt.Errorf("vault config missing: %w", err)
	}
	if info.Size() == 0 {
		log.Error("❌ Vault config file is empty")
		return fmt.Errorf("vault config file empty")
	}

	// Optionally: simple keyword checks
	expected := []string{"listener", "storage", "api_addr"}
	content, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		log.Error("Failed to read config", zap.Error(err))
		return fmt.Errorf("read config failed: %w", err)
	}
	for _, keyword := range expected {
		if !strings.Contains(string(content), keyword) {
			log.Warn("⚠️ Vault config missing expected keyword", zap.String("keyword", keyword))
		}
	}

	// ✨ More thorough: run vault server -check
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "vault", "server", "-config", shared.VaultConfigPath, "-check")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Info("🔎 Running 'vault server -check'")
	if err := cmd.Run(); err != nil {
		log.Error("❌ Vault server config validation failed", zap.Error(err))
		return fmt.Errorf("vault config validation failed: %w", err)
	}

	log.Info("✅ Vault configuration validated successfully")
	return nil
}
