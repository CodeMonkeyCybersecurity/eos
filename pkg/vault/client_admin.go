// pkg/vault/client_admin.go
// Admin-level Vault client management following HashiCorp best practices
//
// This file implements the proper authentication hierarchy for operational commands:
// 1. Vault Agent token (with admin policy) - Automatic, zero-touch
// 2. Admin AppRole credentials - Fallback if agent down
// 3. Interactive userpass (with capability check) - Manual fallback
// 4. Root token - ONLY with explicit user consent (emergency)
//
// Why this matters (HashiCorp recommendations):
// - Root token should be deleted after initial setup
// - Operational commands should use policy-bound auth (admin AppRole)
// - Admin operations are audited (unlike root which bypasses policies)
// - Credentials can be rotated without regenerating root token
//
// GetAdminClient() vs GetPrivilegedClient():
// - GetAdminClient(): For operational commands (policy updates, MFA repair, drift correction)
// - GetPrivilegedClient(): For initial setup only (root token required)

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AdminAuthMethod represents an admin-level authentication method
type AdminAuthMethod struct {
	Name        string
	Description string
	TryFunc     func(*eos_io.RuntimeContext, *api.Client) (string, error)
	Required    []string // Required capabilities for this method
}

// GetAdminClient retrieves or creates a Vault client with admin-level privileges.
//
// This function implements HashiCorp best practice of using admin-level AppRole
// instead of root token for operational commands.
//
// Authentication hierarchy (in order):
//  1. Vault Agent token (if agent running and has admin policy)
//  2. Admin AppRole (if credentials exist on disk)
//  3. Interactive userpass (if enabled, prompts user)
//  4. Suggests root token (does NOT auto-try, requires explicit command)
//
// Use cases:
//   - Policy updates: eos update vault --policies
//   - MFA repair: eos update vault --fix --mfa
//   - Drift correction: eos update vault --fix
//   - Debug operations: eos debug vault
//
// DO NOT USE for:
//   - Initial setup: use GetPrivilegedClient() (needs root token)
//   - Normal operations: use GetVaultClient() (regular auth)
func GetAdminClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Initializing admin-level Vault client",
		zap.String("note", "Using admin AppRole instead of root token (HashiCorp best practice)"))

	// Check if admin client already cached in context
	if client, ok := rc.Ctx.Value(adminClientKey).(*api.Client); ok && client != nil {
		if client.Token() != "" {
			logger.Debug(" Using cached admin Vault client from RuntimeContext",
				zap.String("vault_addr", client.Address()),
				zap.String("source", "context cache"),
				zap.Bool("has_token", true))

			// Verify token still has admin capabilities
			if hasAdminCapabilities(rc, client) {
				return client, nil
			} else {
				logger.Warn(" Cached admin client lost admin capabilities, re-authenticating")
			}
		} else {
			logger.Debug(" Cached admin client has no token, creating new one")
		}
	}

	// Create new Vault client
	config := api.DefaultConfig()
	if err := config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("reading vault environment config: %w", err)
	}

	if config.Address == "" {
		config.Address = fmt.Sprintf("https://shared.GetInternalHostname:%d", shared.PortVault)
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	// Define admin authentication methods in priority order
	// P0 FIX: Root token added BEFORE userpass to prevent MFA bypass vulnerability
	adminAuthMethods := []AdminAuthMethod{
		{
			Name:        "vault-agent-with-admin-policy",
			Description: "Vault Agent token (automatic, zero-touch)",
			TryFunc: func(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
				token, err := coreAgentTokenAuth(rc, client, VaultAgentTokenPath)
				if err != nil {
					return "", err
				}
				// Verify token has admin capabilities
				client.SetToken(token)
				if !hasAdminCapabilities(rc, client) {
					return "", fmt.Errorf("Vault Agent token lacks admin capabilities (needs eos-admin-policy)")
				}
				return token, nil
			},
			Required: []string{"identity/mfa/*", "sys/policy/*", "sys/mounts/*"},
		},
		{
			Name:        "admin-approle",
			Description: "Admin AppRole credentials (fallback if agent down)",
			TryFunc: func(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
				return tryAdminAppRole(rc, client)
			},
			Required: []string{"identity/mfa/*", "sys/policy/*", "sys/mounts/*"},
		},
		{
			Name:        "root-token-interactive",
			Description: "Root token (emergency use, requires sudo)",
			TryFunc: func(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
				return tryRootTokenInteractive(rc, client, AuthContextRuntime)
			},
			Required: []string{"root"},
		},
		{
			Name:        "interactive-userpass-with-admin-check",
			Description: "Interactive userpass (manual, prompts user)",
			TryFunc: func(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
				token, err := tryUserpassInteractive(rc, client, AuthContextRuntime)
				if err != nil {
					return "", err
				}
				// Verify token has admin capabilities
				client.SetToken(token)
				if !hasAdminCapabilities(rc, client) {
					return "", fmt.Errorf("userpass token lacks admin capabilities (needs eos-admin-policy)")
				}
				return token, nil
			},
			Required: []string{"identity/mfa/*", "sys/policy/*", "sys/mounts/*"},
		},
	}

	// Try each admin authentication method
	// P1 FIX: Enhanced diagnostic logging with method-specific remediation
	var lastErr error
	for _, method := range adminAuthMethods {
		logger.Info(" Attempting admin authentication method",
			zap.String("method", method.Name),
			zap.String("description", method.Description))

		token, err := method.TryFunc(rc, client)
		if err != nil {
			lastErr = err

			// P1 FIX: WARN level with diagnostic context (was DEBUG)
			logger.Warn(" Admin authentication method failed",
				zap.String("method", method.Name),
				zap.Error(err),
				zap.String("next_action", "trying next method"))

			// P1 FIX: Method-specific remediation guidance
			switch method.Name {
			case "vault-agent-with-admin-policy":
				logger.Warn("   Possible causes:")
				logger.Warn("     • Vault Agent service not running")
				logger.Warn("     • Token file stale (agent crashed)")
				logger.Warn("     • Token lacks eos-admin-policy")
				logger.Warn("   Check with: sudo systemctl status vault-agent-eos")

			case "admin-approle":
				logger.Warn("   Possible causes:")
				logger.Warn("     • Credentials missing: /var/lib/eos/secret/admin_role_id")
				logger.Warn("     • Wrong permissions (need 0600, owned by root)")
				logger.Warn("     • AppRole not configured in Vault")
				logger.Warn("   Check with: sudo ls -la /var/lib/eos/secret/admin_*")

			case "root-token-interactive":
				logger.Warn("   Possible causes:")
				logger.Warn("     • Root token file missing")
				logger.Warn("     • User declined to use root token")
				logger.Warn("     • Not running with sudo")
				logger.Warn("   Check with: sudo ls -la /run/eos/vault_init_output.json")

			case "interactive-userpass-with-admin-check":
				logger.Warn("   Possible causes:")
				logger.Warn("     • User declined interactive auth")
				logger.Warn("     • Wrong username/password")
				logger.Warn("     • User lacks eos-admin-policy")
				logger.Warn("     • MFA verification failed")
			}

			continue
		}

		// Success! Set token and cache client
		client.SetToken(token)
		SetAdminClient(rc, client)

		logger.Info(" ✓ Admin authentication successful",
			zap.String("method", method.Name))

		return client, nil
	}

	// All admin methods failed - provide helpful error message
	logger.Error(" All admin authentication methods failed",
		zap.Error(lastErr))

	return nil, fmt.Errorf(
		"admin authentication failed: no valid admin-level credentials available\n\n"+
			"This operation requires elevated privileges (eos-admin-policy).\n\n"+
			"Options:\n"+
			"  1. Ensure Vault Agent is running and has admin policy:\n"+
			"     systemctl status vault-agent-eos\n"+
			"     (Agent should have been configured during 'eos create vault')\n\n"+
			"  2. Check if admin AppRole exists:\n"+
			"     ls -la /var/lib/eos/secret/admin_role_id\n"+
			"     (Should have been created during 'eos create vault')\n\n"+
			"  3. Re-run Vault setup to create admin AppRole:\n"+
			"     sudo eos create vault\n"+
			"     (This will detect existing Vault and only create missing components)\n\n"+
			"  4. Emergency root access (use with caution):\n"+
			"     export VAULT_TOKEN=$(sudo cat /run/eos/vault_init_output.json | jq -r '.root_token')\n"+
			"     (This should only be used in emergencies - root token has unlimited access)\n\n"+
			"Last error: %v", lastErr)
}

// SetAdminClient stores an admin-level vault client in the runtime context.
// This prevents duplicate authentication for admin operations.
func SetAdminClient(rc *eos_io.RuntimeContext, client *api.Client) {
	logger := otelzap.Ctx(rc.Ctx)

	if client == nil {
		logger.Warn(" Attempted to store nil admin Vault client in context",
			zap.String("action", "skipped"))
		return
	}

	logger.Debug(" Storing admin Vault client in RuntimeContext",
		zap.String("vault_addr", client.Address()),
		zap.Bool("has_token", client.Token() != ""),
		zap.String("purpose", "admin-level operations"))

	rc.Ctx = context.WithValue(rc.Ctx, adminClientKey, client)

	logger.Debug(" Admin Vault client stored in context successfully",
		zap.String("context_key", string(adminClientKey)))
}

// adminClientKey is the context key for storing admin-level vault client
const adminClientKey contextKey = "admin-vault-client"

// hasAdminCapabilities checks if a token has the required capabilities for admin operations.
// This verifies that the token has eos-admin-policy (or equivalent permissions).
func hasAdminCapabilities(rc *eos_io.RuntimeContext, client *api.Client) bool {
	logger := otelzap.Ctx(rc.Ctx)

	// Check 1: Token must be valid
	if client.Token() == "" {
		logger.Debug("Token is empty, no admin capabilities")
		return false
	}

	// Check 2: Verify token with Vault
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		logger.Debug("Token lookup failed, assuming no admin capabilities",
			zap.Error(err))
		return false
	}

	if secret == nil || secret.Data == nil {
		logger.Debug("Token lookup returned nil, no admin capabilities")
		return false
	}

	// Check 3: Verify token has admin policy
	policies, ok := secret.Data["policies"].([]interface{})
	if !ok {
		logger.Debug("Token has no policies field")
		return false
	}

	hasAdminPolicy := false
	for _, p := range policies {
		if policy, ok := p.(string); ok {
			if policy == shared.EosAdminPolicyName || policy == "root" {
				hasAdminPolicy = true
				break
			}
		}
	}

	if !hasAdminPolicy {
		logger.Debug("Token lacks admin policy",
			zap.Any("policies", policies),
			zap.String("required", shared.EosAdminPolicyName))
		return false
	}

	// Check 4: Verify token has required capabilities (optional, expensive check)
	// We skip this for performance - policy check is sufficient

	logger.Debug("Token has admin capabilities",
		zap.Any("policies", policies))

	return true
}

// checkCapabilities verifies that a token has specific Vault capabilities on a path.
// This is an expensive operation (makes API call to Vault) so use sparingly.
func checkCapabilities(rc *eos_io.RuntimeContext, client *api.Client, path string, required []string) bool {
	logger := otelzap.Ctx(rc.Ctx)

	resp, err := client.Logical().Write("sys/capabilities-self", map[string]interface{}{
		"paths": []string{path},
	})

	if err != nil {
		logger.Debug("Capabilities check failed",
			zap.String("path", path),
			zap.Error(err))
		return false
	}

	if resp == nil || resp.Data == nil {
		return false
	}

	capabilities, ok := resp.Data[path].([]interface{})
	if !ok {
		return false
	}

	capSet := make(map[string]bool)
	for _, c := range capabilities {
		if cap, ok := c.(string); ok {
			capSet[strings.ToLower(cap)] = true
		}
	}

	// Check if token has required capabilities
	for _, req := range required {
		if !capSet[strings.ToLower(req)] && !capSet["root"] && !capSet["sudo"] {
			logger.Debug("Token lacks required capability",
				zap.String("path", path),
				zap.String("required", req),
				zap.Any("actual", capSet))
			return false
		}
	}

	return true
}
