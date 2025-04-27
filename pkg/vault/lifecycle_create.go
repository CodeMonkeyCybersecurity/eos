// pkg/vault/lifecycle_create.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func InstallVaultBinary(log *zap.Logger) error {
	return PhaseInstallVault(log)
}

func PrepareEnvironment(log *zap.Logger) error {
	if _, err := EnsureVaultEnv(log); err != nil {
		return err
	}
	if err := system.EnsureEosUser(true, false, log); err != nil {
		return err
	}
	if err := EnsureVaultDirs(log); err != nil {
		return err
	}
	if err := PrepareVaultAgentEnvironment(log); err != nil {
		return err
	}
	return nil
}


func GenerateTLS(log *zap.Logger) error {
	log.Info("📁 Starting full Vault TLS generation and trust setup")

	crt, key, err := EnsureVaultTLS(log)
	if err != nil {
		return fmt.Errorf("ensure vault TLS certs: %w", err)
	}
	log.Info("✅ Vault TLS certs ensured", zap.String("key", key), zap.String("crt", crt))

	if err := TrustVaultCA(log); err != nil {
		return fmt.Errorf("trust vault CA system-wide: %w", err)
	}
	log.Info("✅ Vault CA trusted system-wide")

	if err := secureVaultTLSOwnership(log); err != nil {
		return fmt.Errorf("secure Vault TLS ownership: %w", err)
	}
	log.Info("✅ Vault Agent CA cert ensured")
	log.Info("✅ Vault TLS generation and trust setup complete")

	return nil
}

func WriteAndValidateConfig(log *zap.Logger) error {
	if err := PhaseEnsureVaultConfigExists(log); err != nil {
		return err
	}
	if err := PhasePatchVaultConfigIfNeeded(log); err != nil {
		return err
	}
	if err := ValidateVaultConfig(log); err != nil {
		return err
	}
	return nil
}

func StartVault(log *zap.Logger) error {
	return StartVaultService(log)
}

func InitializeVaultOnly(log *zap.Logger) (string, error) {
	if _, err := EnsureVaultEnv(log); err != nil {
		return "", fmt.Errorf("ensure Vault environment: %w", err)
	}

	client, err := CreateVaultClient(log)
	if err != nil {
		return "", fmt.Errorf("create Vault client: %w", err)
	}

	client, err = PhaseInitVaultOnly(client, log)
	if err != nil {
		return "", fmt.Errorf("initialize Vault only: %w", err)
	}
	if client == nil {
		return "", fmt.Errorf("vault client invalid after initialization; Vault server may be unreachable or misconfigured")
	}

	addr := VaultAddress()
	log.Info("✅ Vault initialized successfully — unseal keys securely stored", zap.String("VAULT_ADDR", addr))

	return addr, nil
}

func CreateVaultClient(log *zap.Logger) (*api.Client, error) {
	return NewClient(log)
}

func VaultAddress() string {
	return os.Getenv(shared.VaultAddrEnv)
}

func ApplyCoreSecretsAndHealthCheck(client *api.Client, log *zap.Logger) error {
	if err := PhaseApplyCoreSecrets(client, shared.VaultTestPath, map[string]string{"example_key": "example_value"}, log); err != nil {
		return err
	}

	healthy, err := CheckVaultHealth(log)
	if err != nil || !healthy {
		return fmt.Errorf("vault unhealthy after setup: %w", err)
	}
	return nil
}
