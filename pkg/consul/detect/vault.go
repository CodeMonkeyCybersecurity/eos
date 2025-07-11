package detect

import (
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultInstallation detects if Vault is installed and healthy
// Migrated from cmd/create/consul.go detectVaultInstallation
func VaultInstallation(rc *eos_io.RuntimeContext) bool {
	log := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if Vault integration is possible
	log.Info("Assessing Vault installation for Consul integration")
	
	// Check if VAULT_ADDR is set
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		log.Debug("VAULT_ADDR not set, skipping Vault integration")
		return false
	}

	// INTERVENE - Try to create a Vault client
	log.Debug("Attempting to connect to Vault", zap.String("vault_addr", vaultAddr))
	
	client, err := vault.NewClient(rc)
	if err != nil {
		log.Debug("Failed to create Vault client", zap.Error(err))
		return false
	}

	// EVALUATE - Check if Vault is healthy
	log.Debug("Checking Vault health")
	
	_, err = client.Sys().Health()
	if err != nil {
		log.Debug("Vault health check failed", zap.Error(err))
		return false
	}

	log.Info("Vault detected and healthy, enabling integration",
		zap.String("vault_addr", vaultAddr))
	
	return true
}