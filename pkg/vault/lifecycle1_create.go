// pkg/vault/lifecycle1_create.go

package vault

import (
	"fmt"

	"go.uber.org/zap"
)

func OrchestrateVaultCreate() error {
	zap.L().Info("🚀 Starting full Vault create lifecycle")

	if err := PhaseInstallVault(); err != nil {
		return fmt.Errorf("install vault binary: %w", err)
	}
	if err := PrepareEnvironment(); err != nil {
		return fmt.Errorf("prepare environment: %w", err)
	}
	if err := GenerateTLS(); err != nil {
		return fmt.Errorf("generate TLS: %w", err)
	}
	if err := WriteAndValidateConfig(); err != nil {
		return fmt.Errorf("write and validate config: %w", err)
	}
	if err := StartVaultService(); err != nil {
		return fmt.Errorf("start vault: %w", err)
	}
	if err := InitializeVault(); err != nil {
		return fmt.Errorf("initialize vault: %w", err)
	}

	zap.L().Info("🎉 Vault create lifecycle completed successfully")
	return nil
}
