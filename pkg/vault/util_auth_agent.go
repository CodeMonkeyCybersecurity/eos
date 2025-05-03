// pkg/vault/util_auth_approle.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

// PhasePrepareVaultAgent writes agent password and systemd unit.
func PhasePrepareVaultAgent(password string) error {
	zap.L().Info("🔏 [Phase X] Preparing Vault Agent configuration")

	if password != "" {
		zap.L().Info("🔏 Writing Vault Agent authentication secret", zap.String("path", shared.VaultAgentPassPath))
		if err := writeAgentPassword(password); err != nil {
			return fmt.Errorf("write agent password: %w", err)
		}
		zap.L().Info("✅ Vault Agent password written")
	} else {
		zap.L().Info("ℹ️ No agent password provided — skipping password file write")
	}

	if err := WriteAgentSystemdUnit(); err != nil {
		return fmt.Errorf("write agent systemd unit: %w", err)
	}
	zap.L().Info("✅ Vault Agent systemd unit written")

	if err := EnsureAgentServiceReady(); err != nil {
		return fmt.Errorf("enable agent service: %w", err)
	}
	zap.L().Info("✅ Vault Agent service ready and enabled")

	return nil
}

func EnsureAgentServiceReady() error {
	if err := EnsureVaultAgentUnitExists(); err != nil {
		return err
	}
	zap.L().Info("🚀 Reloading daemon and enabling Vault Agent service")
	if err := system.ReloadDaemonAndEnable(shared.VaultAgentService); err != nil {
		zap.L().Error("❌ Failed to enable/start Vault Agent service", zap.Error(err))
		return fmt.Errorf("enable/start Vault Agent service: %w", err)
	}
	return nil
}

func writeAgentPassword(password string) error {
	zap.L().Debug("🔏 Writing Vault Agent password to file", zap.String("path", shared.VaultAgentPassPath))

	data := []byte(password + "\n")
	if err := os.WriteFile(shared.VaultAgentPassPath, data, 0600); err != nil {
		zap.L().Error("❌ Failed to write password file", zap.String("path", shared.VaultAgentPassPath), zap.Error(err))
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", shared.VaultAgentPassPath, err)
	}

	zap.L().Info("✅ Vault Agent password file written",
		zap.String("path", shared.VaultAgentPassPath),
		zap.Int("bytes_written", len(data)))

	return nil
}

func EnsureVaultAgentUnitExists() error {
	if _, err := os.Stat(shared.VaultAgentServicePath); os.IsNotExist(err) {
		zap.L().Warn("⚙️ Vault Agent systemd unit missing — creating", zap.String("path", shared.VaultAgentServicePath))
		if err := WriteAgentSystemdUnit(); err != nil {
			zap.L().Error("❌ Failed to write Vault Agent systemd unit", zap.Error(err))
			return fmt.Errorf("write Vault Agent unit: %w", err)
		}
		zap.L().Info("✅ Vault Agent systemd unit ensured", zap.String("path", shared.VaultAgentServicePath))
	}
	return nil
}
