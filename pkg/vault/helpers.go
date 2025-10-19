// pkg/vault/helpers.go
// Helper functions for common Vault operations

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// EnsureFacadeInitialized ensures the Vault service facade is initialized and returns it
// This is a DRY helper to avoid repeating the same initialization + nil check pattern
func EnsureFacadeInitialized(rc *eos_io.RuntimeContext) (*ServiceFacade, error) {
	// Initialize if not already done
	if err := InitializeServiceFacade(rc); err != nil {
		return nil, fmt.Errorf("failed to initialize Vault: %w", err)
	}

	// Get the facade
	facade := GetServiceFacade()
	if facade == nil {
		return nil, fmt.Errorf("vault service not available")
	}

	return facade, nil
}
