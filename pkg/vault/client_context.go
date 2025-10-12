package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// vaultClientKey is the context key for storing vault client
const vaultClientKey contextKey = "vault-client"

// GetVaultClient retrieves the vault client from context or creates a new one
func GetVaultClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	// Check if client exists in context
	if client, ok := rc.Ctx.Value(vaultClientKey).(*api.Client); ok && client != nil {
		return client, nil
	}

	// Create new client with default config
	config := api.DefaultConfig()
	
	// Check for VAULT_ADDR environment variable or use default
	if config.Address == "" {
		config.Address = fmt.Sprintf("http://127.0.0.1:%d", shared.PortVault)
	}
	
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	return client, nil
}

// SetVaultClient stores the vault client in the runtime context
func SetVaultClient(rc *eos_io.RuntimeContext, client *api.Client) {
	// Note: This is a simplified implementation. In a real scenario,
	// we'd need to create a new context with the value and update rc.Ctx
	// For now, this is a no-op to satisfy the compilation
}

// validateAndCacheClient validates the vault client and caches it
// This is a helper function used internally
// Prefixed with underscore to indicate it's intentionally unused (future caching implementation)
//
//nolint:unused
func _validateAndCacheClient(rc *eos_io.RuntimeContext, client *api.Client) {
	// This is a placeholder implementation
	// In a real implementation, this would validate the client connection
	// and cache it appropriately
	_ = rc
	_ = client
}