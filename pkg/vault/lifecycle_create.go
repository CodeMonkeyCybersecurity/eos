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
	if err := GenerateVaultTLSCert(log); err != nil {
		return err
	}
	if err := TrustVaultCA(log); err != nil {
		return err
	}
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

func InitializeAndUnsealVault(log *zap.Logger) (string, *api.Client, error) {
	if _, err := EnsureVaultEnv(log); err != nil {
		return "", nil, err
	}
	client, err := NewClient(log)
	if err != nil {
		return "", nil, err
	}
	client, err = PhaseInitAndUnsealVault(client, log)
	if err != nil {
		return "", nil, err
	}
	addr := os.Getenv(shared.VaultAddrEnv)
	return addr, client, nil
}

func ApplyCoreSecretsAndHealthCheck(client *api.Client, log *zap.Logger) error {
	// Apply core bootstrap secrets
	if err := PhaseApplyCoreSecrets(client, shared.VaultTestPath, map[string]string{"example_key": "example_value"}, log); err != nil {
		return err
	}
	// Final Vault health check
	if healthy, err := CheckVaultHealth(log); err != nil || !healthy {
		return fmt.Errorf("vault unhealthy after setup: %w", err)
	}
	return nil
}
