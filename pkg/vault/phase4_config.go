// pkg/vault/vault_lifecycle.go

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
// 4.  Render,  Write Validate Vault Configuration vault.hcl
//--------------------------------------------------------------------

// PHASE 4 — PhaseEnsureVaultConfigExists() + PhasePatchVaultConfigIfNeeded() + ValidateVaultConfig()

// PhaseEnsureVaultConfigExists ensures that Vault's server config exists, or writes a default one if missing.
func PhaseEnsureVaultConfigExists(log *zap.Logger) error {
	log.Info("📋 Checking if Vault config exists", zap.String("path", shared.VaultConfigPath))
	if _, err := os.Stat(shared.VaultConfigPath); os.IsNotExist(err) {
		log.Warn("⚠️ Vault config missing — generating default vault.hcl", zap.String("path", shared.VaultConfigPath))
		if err := WriteVaultHCL(log); err != nil {
			log.Error("❌ Failed to write default vault.hcl", zap.Error(err))
			return fmt.Errorf("write default vault.hcl: %w", err)
		}
		log.Info("✅ Default Vault config written", zap.String("path", shared.VaultConfigPath))
	} else if err != nil {
		log.Error("❌ Error checking Vault config file", zap.Error(err))
		return fmt.Errorf("check vault config existence: %w", err)
	} else {
		log.Info("✅ Vault config already present")
	}
	return nil
}

// PhasePatchVaultConfigIfNeeded ensures Vault is configured to use the expected port (8179).
func PhasePatchVaultConfigIfNeeded(log *zap.Logger) error {
	log.Info("[2/6] Checking for Vault port mismatch (8200 → 8179)")

	data, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		log.Warn("Could not read Vault config file", zap.String("path", shared.VaultConfigPath), zap.Error(err))
		return nil // Not fatal, continue without patching
	}
	content := string(data)

	if strings.Contains(content, shared.VaultDefaultPort) {
		log.Info("✅ Vault config already uses port 8179 — no patch needed")
		return nil
	}

	if !strings.Contains(content, "8200") {
		log.Info("ℹ️ No 8200 port found in Vault config — no changes applied")
		return nil
	}

	// Patch config: replace 8200 with 8179
	log.Warn("🔧 Vault config uses port 8200 — patching to 8179")
	newContent := strings.ReplaceAll(content, "8200", shared.VaultDefaultPort)
	if err := os.WriteFile(shared.VaultConfigPath, []byte(newContent), 0644); err != nil {
		log.Error("❌ Failed to write patched Vault config", zap.Error(err))
		return fmt.Errorf("failed to write patched Vault config: %w", err)
	}

	log.Info("✅ Vault config patched successfully — restarting Vault service...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "restart", "vault")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("❌ Failed to restart Vault service after patch", zap.Error(err))
		return fmt.Errorf("vault restart failed after config patch: %w", err)
	}

	log.Info("✅ Vault service restarted successfully after config patch")
	return nil
}

// ValidateVaultConfig runs Vault's built-in configuration validation.
// It returns an error if validation fails, and logs the vault output for diagnosis.
// This must be called before attempting to start Vault.
func ValidateVaultConfig(log *zap.Logger) error {
	log.Info("🧪 Validating Vault configuration syntax")
	cmd := exec.Command("vault", "server", "-config", shared.VaultConfigPath, "-check")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Vault config validation failed", zap.Error(err), zap.String("output", string(out)))
		return fmt.Errorf("vault config validation error: %w", err)
	}
	log.Info("✅ Vault config validation successful", zap.String("output", string(out)))
	return nil
}
