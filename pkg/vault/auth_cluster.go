// pkg/vault/auth_cluster.go
//
// Authentication helpers for Vault cluster operations (Raft, Autopilot, snapshots)
//
// This file provides authentication and authorization helpers specifically for
// cluster-level operations that require admin-level access.
//
// Functions follow the Assess → Intervene → Evaluate pattern per CLAUDE.md.

package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TTL threshold constants for token validation
const (
	// TTLWarningThreshold is the TTL (in seconds) below which we warn the user
	// that their token will expire soon. 5 minutes is enough time for cluster ops.
	TTLWarningThreshold = 300 // 5 minutes

	// TTLMinimumRequired is the absolute minimum TTL (in seconds) required to proceed.
	// Below this, operations will fail even if token is non-periodic.
	TTLMinimumRequired = 60 // 1 minute

	// TTLRecheckThreshold is the TTL (in seconds) below which we re-check TTL after
	// validation to detect race conditions. 2 minutes is chosen because validation
	// takes ~1-2 seconds for 4 capability checks.
	TTLRecheckThreshold = 120 // 2 minutes
)

// GetVaultClientWithToken creates a Vault client with a specific token
// and validates it has sufficient capabilities for cluster operations.
//
// Used when token is provided via --token flag or VAULT_TOKEN environment variable.
//
// SECURITY: Token value is NEVER logged in plain text. Use sanitizeTokenForLogging()
// if you need to reference the token in logs for debugging.
//
// ASSESS: Validate token format
// INTERVENE: Create client and set token
// EVALUATE: Verify token has cluster operation capabilities
func GetVaultClientWithToken(rc *eos_io.RuntimeContext, token string) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Validate token is non-empty
	if token == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}

	// ASSESS: Check token format for dangerous characters
	if err := validateTokenFormat(token); err != nil {
		return nil, fmt.Errorf("token format invalid: %w", err)
	}

	logger.Debug("Creating Vault client with provided token")

	// INTERVENE: Create Vault client
	client, err := GetVaultClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// INTERVENE: Set token on client
	client.SetToken(token)

	// EVALUATE: Verify token is valid and has sufficient capabilities
	logger.Debug("Verifying token capabilities for cluster operations")
	if err := verifyClusterOperationCapabilities(rc, client); err != nil {
		return nil, fmt.Errorf("token lacks required capabilities: %w\n\n"+
			"Cluster operations require admin-level access.\n"+
			"Ensure your token has one of:\n"+
			"  • eos-admin-policy (recommended - audited, rotatable)\n"+
			"  • root policy (emergency use only - bypasses audit)\n\n"+
			"To get an admin token:\n"+
			"  1. Ensure Vault Agent is running: systemctl status vault-agent-eos\n"+
			"  2. Or use Admin AppRole credentials from /var/lib/eos/secret/\n"+
			"  3. Or authenticate manually: vault login -method=userpass", err)
	}

	logger.Info("✓ Token authenticated and validated for cluster operations")
	return client, nil
}

// sanitizeTokenForLogging returns a safe version of token for logging.
// Shows ONLY the token type prefix (hvs., s., b.) without exposing any token data.
//
// SECURITY: NEVER log raw token values - use this function for all token logging.
// SECURITY: Does NOT show token characters beyond type prefix to prevent entropy leakage.
//
// Examples:
//   "hvs.CAESIJlU02LQZq..." → "hvs.***"
//   "s.1234567890abcdef" → "s.***"
//   "s.12abc..." → "s.***" (NOT "s.12***" - would expose token data)
//   "b.AAAAAQKr..." → "b.***"
//   "unknown" → "***"
//
// P1 Issue #20 Fix: Exported for use in other packages (cmd/update, pkg/vault/*)
func SanitizeTokenForLogging(token string) string {
	if len(token) == 0 {
		return "***" // Empty token
	}

	// Identify token type WITHOUT exposing any token value characters
	if strings.HasPrefix(token, "hvs.") {
		return "hvs.***" // HVAC token (Vault 1.10+)
	}
	if strings.HasPrefix(token, "s.") {
		return "s.***" // Service token / root token
	}
	if strings.HasPrefix(token, "b.") {
		return "b.***" // Batch token
	}

	// Unknown format - hide completely
	return "***"
}

// sanitizeTokenForLogging is a lowercase alias for backwards compatibility with internal callers.
// New code should use the exported SanitizeTokenForLogging() instead.
func sanitizeTokenForLogging(token string) string {
	return SanitizeTokenForLogging(token)
}

// validateTokenFormat checks token for dangerous characters.
// Vault tokens are typically base64-encoded UUID or HVAC format.
// This validation prevents terminal injection attacks.
//
// SECURITY: Token is validated but NEVER logged.
func validateTokenFormat(token string) error {
	// Check for control characters that could cause terminal injection
	for _, r := range token {
		// Allow printable ASCII only (space to tilde)
		if r < 32 || r > 126 {
			return fmt.Errorf("contains invalid character (ascii %d)", r)
		}
	}

	// Check reasonable length (Vault tokens are typically 24-96 chars)
	if len(token) < 10 {
		return fmt.Errorf("token too short (minimum 10 characters)")
	}

	if len(token) > 256 {
		return fmt.Errorf("token too long (maximum 256 characters)")
	}

	return nil
}

// verifyClusterOperationCapabilities checks if token can perform cluster operations.
//
// Required capabilities:
// - sys/storage/raft/* (Raft cluster operations)
// - sys/storage/raft/snapshot (snapshot backup/restore)
// - sys/storage/raft/autopilot/configuration (Autopilot config)
//
// Returns detailed error if token lacks capabilities.
func verifyClusterOperationCapabilities(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check 0: Vault must be unsealed (check BEFORE token validation)
	logger.Debug("Checking Vault seal status")
	sealStatus, err := client.Sys().SealStatus()
	if err != nil {
		logger.Debug("Failed to check seal status", zap.Error(err))
		return fmt.Errorf("cannot connect to Vault: %w\n\n"+
			"Possible causes:\n"+
			"  • Vault service is not running: systemctl status vault\n"+
			"  • Vault address is incorrect: check VAULT_ADDR\n"+
			"  • Network connectivity issue", err)
	}

	if sealStatus.Sealed {
		return fmt.Errorf("Vault is sealed - cannot perform cluster operations\n\n"+
			"Unseal Vault first:\n"+
			"  vault operator unseal\n"+
			"  Or: eos update vault unseal\n\n"+
			"Seal status:\n"+
			"  Sealed: %t\n"+
			"  Progress: %d/%d keys provided",
			sealStatus.Sealed, sealStatus.Progress, sealStatus.T)
	}

	logger.Debug("✓ Vault is unsealed", zap.Int("threshold", sealStatus.T))

	// Check 1: Token must be valid
	logger.Debug("Checking token validity with Vault")
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		logger.Debug("Token lookup failed", zap.Error(err))
		return fmt.Errorf("token is invalid or expired: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("token lookup returned no data (token may be expired)")
	}

	// Check 1b: Token must not be orphaned or in revocation queue
	// Orphan tokens have no parent - if parent was revoked, orphan token persists but may be risky
	orphan := false
	if orphanRaw, ok := secret.Data["orphan"].(bool); ok {
		orphan = orphanRaw
	}

	if orphan {
		logger.Warn("⚠️  Token is orphaned (parent token was revoked)",
			zap.Bool("orphan", true))
		// Don't reject orphan tokens (they're valid) but warn user for awareness
		// Orphan tokens can be legitimate (created with -orphan flag or from root)
	}

	// Check for explicit_max_ttl=0 which indicates token in revocation queue
	// This is a Vault internal marker that token is marked for deletion
	if explicitMaxTTL, ok := secret.Data["explicit_max_ttl"].(json.Number); ok {
		maxTTLSeconds, err := explicitMaxTTL.Int64()
		if err == nil && maxTTLSeconds == 0 {
			// Check if this is a periodic token (which legitimately has explicit_max_ttl=0)
			// P0 Issue #12 Fix: Use centralized helper instead of duplicate logic
			if !isPeriodicToken(secret) {
				// Non-periodic token with explicit_max_ttl=0 is suspicious
				logger.Warn("⚠️  Token has explicit_max_ttl=0 (may be in revocation queue)",
					zap.Int64("explicit_max_ttl", maxTTLSeconds))
				// Don't reject yet - might be legitimate, but warn
			}
		}
	}

	// Check token TTL (Time To Live) and renewal properties
	// CRITICAL: Periodic tokens auto-renew - don't reject based on low TTL
	if ttlRaw, ok := secret.Data["ttl"].(json.Number); ok {
		ttlSeconds, err := ttlRaw.Int64()
		if err == nil {
			ttlDuration := time.Duration(ttlSeconds) * time.Second

			// Check if token is periodic (auto-renewable, never expires)
			// P0 Issue #12 Fix: Use centralized helper instead of duplicate logic
			isPeriodic := isPeriodicToken(secret)
			if isPeriodic {
				// Get period for logging
				if periodRaw, ok := secret.Data["period"].(json.Number); ok {
					periodSeconds, _ := periodRaw.Int64()
					logger.Debug("✓ Token is periodic (auto-renewable)",
						zap.Int64("current_ttl_seconds", ttlSeconds),
						zap.Int64("period_seconds", periodSeconds),
						zap.String("period_human", formatTTLDuration(periodSeconds)))
				}
			}

			// Check if token is renewable (can be manually renewed)
			isRenewable := false
			if renewableRaw, ok := secret.Data["renewable"].(bool); ok {
				isRenewable = renewableRaw
			}

			// Periodic tokens: Don't check TTL (they auto-renew)
			// Examples: Vault Agent tokens (period=4h), AppRole tokens with period
			if isPeriodic {
				logger.Debug("Token is periodic - TTL check skipped (auto-renews)",
					zap.Int64("current_ttl", ttlSeconds),
					zap.Bool("periodic", true))
				// Don't reject periodic tokens regardless of TTL
			} else {
				// Non-periodic tokens: Check TTL and warn/reject
				if ttlSeconds < TTLWarningThreshold {
					logger.Warn("⚠️  Token expires soon",
						zap.Int64("ttl_seconds", ttlSeconds),
						zap.String("ttl_human", formatTTLDuration(ttlSeconds)),
						zap.Bool("renewable", isRenewable))

					// Reject if token expires too soon (less than minimum required)
					if ttlSeconds < TTLMinimumRequired {
						return fmt.Errorf("token expires in %d seconds (too short for cluster operations)\n\n"+
							"Get a longer-lived token:\n"+
							"  vault token create -policy=%s -ttl=1h\n"+
							"  Or use Vault Agent (automatic token renewal)", ttlSeconds, shared.EosAdminPolicyName)
					}
				} else {
					logger.Debug("Token TTL acceptable",
						zap.Duration("ttl", ttlDuration),
						zap.Bool("renewable", isRenewable))
				}
			}
		}
	}

	// Check 2: Token must have required policies
	logger.Debug("Checking token policies")
	policies, ok := secret.Data["policies"].([]interface{})
	if !ok {
		return fmt.Errorf("token has no policies attached")
	}

	// Check for admin or root policy
	hasRequiredPolicy := false
	policyNames := []string{}
	for _, p := range policies {
		if policy, ok := p.(string); ok {
			policyNames = append(policyNames, policy)
			if policy == "root" || policy == shared.EosAdminPolicyName {
				hasRequiredPolicy = true
				logger.Debug("✓ Token has required policy",
					zap.String("policy", policy))
				break
			}
		}
	}

	if !hasRequiredPolicy {
		return fmt.Errorf("token lacks required policy\n"+
			"Token has policies: %v\n"+
			"Required: %s or root", policyNames, shared.EosAdminPolicyName)
	}

	// Check 3: Verify specific capabilities for ALL required cluster operation paths
	// Raft cluster operations require access to multiple sys/storage/raft/* endpoints
	requiredPaths := []string{
		"sys/storage/raft/configuration",          // Raft peer configuration
		"sys/storage/raft/snapshot",               // Snapshot backup/restore
		"sys/storage/raft/autopilot/configuration", // Autopilot config
		"sys/storage/raft/autopilot/state",        // Autopilot state query
	}

	logger.Debug("Checking capabilities for all cluster operation paths",
		zap.Int("path_count", len(requiredPaths)))

	for _, path := range requiredPaths {
		logger.Debug("Checking capabilities", zap.String("path", path))
		capabilities, err := client.Sys().CapabilitiesSelf(path)
		if err != nil {
			logger.Debug("Capabilities check failed",
				zap.String("path", path),
				zap.Error(err))
			// If we can't check capabilities but token has root/admin policy, assume OK
			if hasRequiredPolicy {
				logger.Warn("Cannot verify capabilities but token has required policy - proceeding",
					zap.String("path", path))
				continue // Try next path
			}
			return fmt.Errorf("cannot verify cluster operation capabilities for %s: %w", path, err)
		}

		// Token needs read capability (or root/sudo which implies read)
		hasCapability := false
		for _, cap := range capabilities {
			if cap == "root" || cap == "sudo" || cap == "read" {
				hasCapability = true
				logger.Debug("✓ Token has required capability",
					zap.String("capability", cap),
					zap.String("path", path))
				break
			}
		}

		if !hasCapability {
			return fmt.Errorf("token cannot access %s\n"+
				"Token capabilities: %v\n"+
				"Required: root, sudo, or read\n\n"+
				"Ensure token has one of:\n"+
				"  • eos-admin-policy (full cluster access)\n"+
				"  • root policy (full access)", path, capabilities)
		}
	}

	logger.Debug("✓ Token verified for ALL cluster operations",
		zap.Strings("policies", policyNames),
		zap.Int("paths_checked", len(requiredPaths)))

	// Check 4: Race condition mitigation - Re-check TTL for non-periodic tokens
	// Validation took time (~1-2 seconds for 4 capability checks). For non-periodic tokens,
	// verify TTL didn't drop below threshold during validation.
	// Periodic tokens skip this (they auto-renew).
	//
	// P0 Issue #12 Fix: Use centralized helper instead of duplicate logic
	// P0 Issue #13 Fix: Check fresh periodic status from secretRefresh (not stale original data)
	if ttlRaw, ok := secret.Data["ttl"].(json.Number); ok {
		ttlSeconds, _ := ttlRaw.Int64()

		// Check if token WAS periodic at start of validation
		isPeriodic := isPeriodicToken(secret)

		// Only re-check for non-periodic tokens (periodic tokens auto-renew)
		if !isPeriodic && ttlSeconds < TTLRecheckThreshold {
			logger.Debug("Token TTL is low, re-checking after validation delay",
				zap.Int64("initial_ttl", ttlSeconds))

			// Re-check TTL to account for validation time
			secretRefresh, err := client.Auth().Token().LookupSelf()
			if err != nil {
				logger.Warn("Could not re-check TTL after validation",
					zap.Error(err))
				// Don't fail - original TTL was acceptable
			} else if secretRefresh != nil && secretRefresh.Data != nil {
				// CRITICAL: Check if token became periodic during validation (P0 Issue #13 Fix)
				isPeriodicRefresh := isPeriodicToken(secretRefresh)

				if isPeriodicRefresh && !isPeriodic {
					// Token became periodic during validation - this is OK, it will auto-renew
					logger.Info("✓ Token became periodic during validation - will auto-renew",
						zap.Int64("initial_ttl", ttlSeconds),
						zap.Bool("was_periodic", isPeriodic),
						zap.Bool("is_periodic_now", isPeriodicRefresh))
					return nil
				}

				if ttlRefreshRaw, ok := secretRefresh.Data["ttl"].(json.Number); ok {
					ttlRefresh, _ := ttlRefreshRaw.Int64()

					// Calculate TTL delta (might be negative if token was renewed)
					ttlDelta := ttlSeconds - ttlRefresh
					if ttlDelta < 0 {
						// Token was renewed during validation (TTL increased)
						logger.Debug("Token was renewed during validation (TTL increased)",
							zap.Int64("initial_ttl", ttlSeconds),
							zap.Int64("current_ttl", ttlRefresh),
							zap.Int64("ttl_increased_by", -ttlDelta))
						return nil
					}

					logger.Debug("TTL after validation",
						zap.Int64("initial_ttl", ttlSeconds),
						zap.Int64("current_ttl", ttlRefresh),
						zap.Int64("ttl_dropped_by", ttlDelta))

					// If TTL dropped below threshold during validation, reject
					if ttlRefresh < TTLMinimumRequired {
						return fmt.Errorf("token expired during validation (TTL now %d seconds, was %d)\n\n"+
							"Validation took time and token TTL was too low.\n"+
							"Get a longer-lived token:\n"+
							"  vault token create -policy=%s -ttl=1h\n"+
							"  Or use Vault Agent (automatic token renewal)",
							ttlRefresh, ttlSeconds, shared.EosAdminPolicyName)
					}
				}
			}
		}
	}

	return nil
}

// formatTTLDuration converts seconds into human-readable duration string for TTL display.
// This is a simple formatter for token TTL (avoids conflict with existing formatDuration).
//
// Examples:
//   45 seconds  → "45s"
//   120 seconds → "2m"
//   3665 seconds → "1h1m"
func formatTTLDuration(seconds int64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	} else if seconds < 3600 {
		minutes := seconds / 60
		return fmt.Sprintf("%dm", minutes)
	}
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	if minutes > 0 {
		return fmt.Sprintf("%dh%dm", hours, minutes)
	}
	return fmt.Sprintf("%dh", hours)
}

// isPeriodicToken checks if a token is periodic (auto-renewable).
// Periodic tokens have a non-zero period value and will automatically renew.
//
// This is a centralized helper to ensure consistent periodic token detection
// across multiple validation checks. It handles error cases consistently:
// - nil secret or nil Data returns false
// - type assertion failure returns false
// - Int64() conversion error returns false
// - period <= 0 returns false
//
// P0 Issue #12 Fix: Replaces 3 duplicate isPeriodic checks with inconsistent error handling.
//
// Returns: true if token has period > 0, false otherwise
func isPeriodicToken(secret *api.Secret) bool {
	if secret == nil || secret.Data == nil {
		return false
	}

	if periodRaw, ok := secret.Data["period"].(json.Number); ok {
		periodSeconds, err := periodRaw.Int64()
		// Only return true if conversion succeeded AND period > 0
		return err == nil && periodSeconds > 0
	}

	return false
}
