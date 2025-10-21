package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// vaultClientKey is the context key for storing vault client
const vaultClientKey contextKey = "vault-client"

// GetVaultClient retrieves the vault client from context or creates a new one
// This function properly reads environment variables including VAULT_SKIP_VERIFY
// for self-signed certificate support during installation.
// CRITICAL P0: Uses centralized SecureAuthenticationOrchestrator for automatic token loading
// This ensures consistent authentication across ALL Vault operations.
func GetVaultClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if client exists in context and is authenticated
	if client, ok := rc.Ctx.Value(vaultClientKey).(*api.Client); ok && client != nil {
		// Verify the client still has a token
		if client.Token() != "" {
			logger.Debug("Using cached Vault client from context",
				zap.String("address", client.Address()))
			return client, nil
		}
		logger.Debug("Cached client has no token, re-authenticating")
	}

	// Create new client with default config
	config := api.DefaultConfig()

	// CRITICAL: Read environment variables including VAULT_SKIP_VERIFY
	// This is necessary for self-signed certificates during installation
	if err := config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("reading vault environment config: %w", err)
	}

	// Check for VAULT_ADDR environment variable or use default
	if config.Address == "" {
		config.Address = fmt.Sprintf("http://127.0.0.1:%d", shared.PortVault)
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	// CRITICAL P0: Use centralized authentication orchestrator
	// This tries (in order):
	//   1. Vault Agent token (/run/eos/vault_agent_eos.token) - PRIMARY METHOD
	//   2. AppRole authentication (if credentials available)
	//   3. Interactive userpass (only if user confirms)
	// This ensures ALL eos commands automatically authenticate without VAULT_TOKEN
	if client.Token() == "" {
		logger.Debug("No token set, attempting centralized authentication")
		if err := SecureAuthenticationOrchestrator(rc, client); err != nil {
			logger.Warn("Centralized authentication failed, returning unauthenticated client",
				zap.Error(err),
				zap.String("note", "Some operations may fail with 403 permission denied"))
			// Don't fail here - return the client anyway for operations that don't need auth
			// (like checking seal status, health endpoints, etc.)
			return client, nil
		}
		logger.Info("Centralized authentication succeeded",
			zap.String("address", client.Address()))
	}

	return client, nil
}

// SetVaultClient stores the vault client in the runtime context
func SetVaultClient(rc *eos_io.RuntimeContext, client *api.Client) {
	// Note: This is a simplified implementation. In a real scenario,
	// we'd need to create a new context with the value and update rc.Ctx
	// For now, this is a no-op to satisfy the compilation
}
