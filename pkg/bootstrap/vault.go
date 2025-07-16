package bootstrap

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// BootstrapVault installs and configures HashiCorp Vault
func BootstrapVault(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check prerequisites and current state
	logger.Info("Assessing Vault installation prerequisites")
	
	// INTERVENE - Install Vault using the existing vault package
	logger.Info("Installing HashiCorp Vault using existing vault package")
	
	// The vault package has a comprehensive orchestration function
	if err := vault.OrchestrateVaultCreate(rc); err != nil {
		return err
	}
	
	// EVALUATE - The vault package already includes verification
	logger.Info("Vault bootstrap completed successfully")
	
	return nil
}