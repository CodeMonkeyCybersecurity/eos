// pkg/vault/lifecycle1_create.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

func InstallVaultBinary() error {
	return PhaseInstallVault()
}

func PrepareEnvironment() error {
	if _, err := EnsureVaultEnv(); err != nil {
		return err
	}
	if err := system.EnsureEosUser(true, false); err != nil {
		return err
	}
	if err := EnsureVaultDirs(); err != nil {
		return err
	}
	if err := PrepareVaultAgentEnvironment(); err != nil {
		return err
	}
	return nil
}

func GenerateTLS() error {
	zap.L().Info("📁 Starting full Vault TLS generation and trust setup")

	crt, key, err := EnsureVaultTLS()
	if err != nil {
		return fmt.Errorf("ensure vault TLS certs: %w", err)
	}
	zap.L().Info("✅ Vault TLS certs ensured", zap.String("key", key), zap.String("crt", crt))

	if err := TrustVaultCA(); err != nil {
		return fmt.Errorf("trust vault CA system-wide: %w", err)
	}
	zap.L().Info("✅ Vault CA trusted system-wide")

	if err := secureVaultTLSOwnership(); err != nil {
		return fmt.Errorf("secure Vault TLS ownership: %w", err)
	}
	zap.L().Info("✅ Vault Agent CA cert ensured")
	zap.L().Info("✅ Vault TLS generation and trust setup complete")

	return nil
}

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

func StartVault() error {
	return StartVaultService()
}
