package detect

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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

	// Get Vault address (env var or smart fallback)
	vaultAddr := shared.GetVaultAddrWithEnv()
	log.Debug("Attempting to connect to Vault", zap.String("vault_addr", vaultAddr))

	// INTERVENE - Try to create a Vault client

	client, err := vault.NewClient(vaultAddr, log.Logger().Logger)
	if err != nil {
		log.Debug("Failed to create Vault client", zap.Error(err))
		return false
	}

	// EVALUATE - Check if Vault is healthy
	log.Debug("Checking Vault health")

	err = client.CheckHealth(rc.Ctx)
	if err != nil {
		log.Debug("Vault health check failed", zap.Error(err))
		return false
	}

	log.Info("Vault detected and healthy, enabling integration",
		zap.String("vault_addr", vaultAddr))

	return true
}
