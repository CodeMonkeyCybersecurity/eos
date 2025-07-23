// pkg/vault/lifecycle1_create.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// DEPRECATED PACKAGE: This package is deprecated in favor of vault_salt.
// All new vault deployments should use 'eos create vault-salt' which provides:
// - Complete SaltStack-based deployment
// - Better error handling and rollback capabilities  
// - Standardized configuration management
// - Integrated hardening and security policies
// - Comprehensive lifecycle management
//
// This package is maintained only for backward compatibility and emergency scenarios.
// Direct installation methods will be removed in a future version.

func OrchestrateVaultCreate(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Starting full Vault create lifecycle")

	// DEPRECATED: Direct installation is deprecated, always attempt Salt-based deployment
	otelzap.Ctx(rc.Ctx).Warn("DEPRECATION WARNING: Direct vault installation is deprecated. Use 'eos create vault-salt' instead.")
	
	// Check if Salt is available and use it if possible
	if err := checkSaltAvailability(rc); err == nil {
		otelzap.Ctx(rc.Ctx).Info("Salt is available, using Salt-based deployment")
		return OrchestrateVaultCreateViaSalt(rc)
	}

	// Salt not available - require it for new deployments
	otelzap.Ctx(rc.Ctx).Error("Salt is required for vault installation. Please install SaltStack first using 'eos create saltstack'")
	return fmt.Errorf("salt is required for vault installation - direct installation is deprecated")
}
