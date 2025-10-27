package vault

import (
	"context"
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

// privilegedClientKey is the context key for storing privileged (root token) vault client
// This prevents duplicate client initializations during setup
const privilegedClientKey contextKey = "privileged-vault-client"

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
			logger.Debug(" Using cached Vault client from RuntimeContext",
				zap.String("vault_addr", client.Address()),
				zap.String("source", "context cache"),
				zap.Bool("has_token", true))
			return client, nil
		}
		logger.Debug(" Cached client has no token, creating new authenticated client",
			zap.String("vault_addr", client.Address()))
	} else {
		logger.Debug(" No cached Vault client in context, creating new client")
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
		config.Address = fmt.Sprintf("http://shared.GetInternalHostname:%d", shared.PortVault)
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
	logger := otelzap.Ctx(rc.Ctx)

	// CRITICAL P0 FIX: Actually store the client in context
	// This was previously a no-op which caused re-authentication on every operation!
	if client == nil {
		logger.Warn(" Attempted to store nil Vault client in context",
			zap.String("action", "skipped"))
		return
	}

	logger.Debug(" Storing Vault client in RuntimeContext",
		zap.String("vault_addr", client.Address()),
		zap.Bool("has_token", client.Token() != ""))

	rc.Ctx = context.WithValue(rc.Ctx, vaultClientKey, client)

	logger.Debug(" Vault client stored in context successfully",
		zap.String("context_key", string(vaultClientKey)))
}

// SetPrivilegedClient stores a privileged (root token) vault client in the runtime context.
// This prevents duplicate client initializations during Vault setup.
// CRITICAL P0 FIX: Caching the privileged client eliminates 34+ redundant GetRootClient() calls
// which was causing 306 duplicate log lines and ~30 seconds of wasted auth validation.
func SetPrivilegedClient(rc *eos_io.RuntimeContext, client *api.Client) {
	logger := otelzap.Ctx(rc.Ctx)

	if client == nil {
		logger.Warn(" Attempted to store nil privileged Vault client in context",
			zap.String("action", "skipped"))
		return
	}

	logger.Debug(" Storing privileged Vault client in RuntimeContext",
		zap.String("vault_addr", client.Address()),
		zap.Bool("has_token", client.Token() != ""),
		zap.String("purpose", "root token client for setup operations"))

	rc.Ctx = context.WithValue(rc.Ctx, privilegedClientKey, client)

	logger.Debug(" Privileged Vault client stored in context successfully",
		zap.String("context_key", string(privilegedClientKey)))
}

// GetPrivilegedClient retrieves the cached privileged (root token) vault client from context.
//
// ⚠️  HASHICORP BEST PRACTICE NOTICE (2025-10-27):
// This function uses ROOT TOKEN which has unlimited Vault access.
// For operational commands (NOT initial setup), use GetAdminClient() instead.
//
// When to use GetPrivilegedClient():
//   ✅ CORRECT: During 'eos create vault' (initial setup, Phases 6-15)
//   ✅ CORRECT: When explicitly handling root token operations
//   ❌ AVOID: For maintenance commands (policy updates, MFA repair, drift correction)
//
// When to use GetAdminClient():
//   ✅ CORRECT: eos update vault --fix
//   ✅ CORRECT: eos update vault --policies
//   ✅ CORRECT: eos debug vault
//   ✅ CORRECT: Any operational command after initial setup
//
// Why this matters (HashiCorp security model):
//   - Root token should be deleted after initial setup
//   - Operational commands should use policy-bound auth (admin AppRole)
//   - Admin AppRole is still audited (root bypasses all policies)
//   - GetAdminClient() tries: Vault Agent → Admin AppRole → Userpass → Root (last resort)
//
// IMPORTANT: This function expects the client to be cached by Phase 6 (EnableVault → UnsealVault).
// Phase 6 creates a root-authenticated client from vault_init.json and caches it via
// SetPrivilegedClient(). All subsequent phases (6c, 7-15) use this cached client.
//
// Authentication timeline:
//   - Phase 6: UnsealVault() → Root token from vault_init.json → SetPrivilegedClient()
//   - Phase 10b: AppRole configured (for future runs)
//   - Phase 10b2: Admin AppRole configured (for operational commands)
//   - Phase 14: Vault Agent configured (for future runs)
//   - Subsequent runs: Use GetAdminClient() for operational commands
//
// Why cached client is necessary during setup:
//   - During initial setup, Vault Agent (Phase 14) and AppRole (Phase 10b) don't exist yet
//   - Attempting to authenticate before Phase 6 would fail (no credentials available)
//   - Phase 6 provides the ONLY working auth method during fresh installation
//
// Caching benefits:
//   - 34 client initializations → 1 initialization
//   - 306 log lines → 9 log lines
//   - ~30 seconds of auth validation → 0 seconds
//   - No 30s wait for agent token that doesn't exist yet
//   - No confusing userpass prompt during installation
//
// If not cached: This function will attempt to create a new client via GetRootClient(),
// which may trigger SecureAuthenticationOrchestrator and wait 30s for agent token.
// This should only happen on subsequent runs where Agent/AppRole are already configured.
//
// Usage: Call this during Vault setup phases (after Phase 6) instead of GetRootClient().
//
// TODO (Post-Migration): Once all operational commands use GetAdminClient(),
// this function should ONLY be called during 'eos create vault' setup.
func GetPrivilegedClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if privileged client exists in context
	if client, ok := rc.Ctx.Value(privilegedClientKey).(*api.Client); ok && client != nil {
		// Verify the client still has a token
		if client.Token() != "" {
			logger.Debug(" Using cached privileged Vault client from RuntimeContext",
				zap.String("vault_addr", client.Address()),
				zap.String("source", "context cache"),
				zap.Bool("has_token", true))
			return client, nil
		}
		logger.Debug(" Cached privileged client has no token, creating new one",
			zap.String("vault_addr", client.Address()))
	} else {
		logger.Debug(" No cached privileged client in context, creating new one")
	}

	// No cached client or token expired - get fresh root client
	logger.Info(" Initializing privileged Vault client",
		zap.String("note", "This should only happen once during setup"))

	client, err := GetRootClient(rc)
	if err != nil {
		logger.Error(" Failed to get privileged Vault client",
			zap.Error(err),
			zap.String("remediation", "Check root token in vault_init.json"))
		return nil, fmt.Errorf("get privileged vault client: %w", err)
	}

	// Cache it for future use
	SetPrivilegedClient(rc, client)

	logger.Info(" Privileged Vault client initialized and cached successfully",
		zap.String("vault_addr", client.Address()))

	return client, nil
}
