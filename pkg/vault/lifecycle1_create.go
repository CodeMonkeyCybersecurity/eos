// pkg/vault/lifecycle1_create.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func OrchestrateVaultCreate(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info("🚀 Starting full Vault create lifecycle")

	if err := PhaseInstallVault(rc); err != nil {
		return fmt.Errorf("install vault binary: %w", err)
	}
	if err := PrepareEnvironment(rc); err != nil {
		return fmt.Errorf("prepare environment: %w", err)
	}
	if err := GenerateTLS(rc); err != nil {
		return fmt.Errorf("generate TLS: %w", err)
	}
	if err := WriteAndValidateConfig(rc); err != nil {
		return fmt.Errorf("write and validate config: %w", err)
	}
	if err := StartVaultService(rc); err != nil {
		return fmt.Errorf("start vault: %w", err)
	}
	if err := InitializeVault(rc); err != nil {
		return fmt.Errorf("initialize vault: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info("🎉 Vault create lifecycle completed successfully")
	return nil
}
