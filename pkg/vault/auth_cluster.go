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
//
// SECURITY CRITICAL: These constants determine when cluster operations are allowed/rejected.
// Incorrect values can lead to operations failing mid-execution (data loss, inconsistent state)
// or allow operations with insufficient time to complete (DoS vector).
//
// P1 Issue #28 Fix: Added comprehensive RATIONALE/SECURITY/THREAT MODEL per CLAUDE.md P0 requirement.
const (
	// TTLWarningThreshold is the TTL (in seconds) below which we warn the user
	// that their token will expire soon.
	//
	// RATIONALE: 5 minutes provides buffer for cluster operations (snapshots, Raft reconfigs,
	//            Autopilot adjustments) which typically take 30-120 seconds. Allows time for
	//            token renewal if needed before operation starts.
	// SECURITY: Prevents operations starting with insufficient time to complete, which could
	//           leave cluster in inconsistent state (partial config applied, incomplete backup,
	//           half-completed Raft peer changes).
	// THREAT MODEL:
	//   - DoS via token expiry mid-operation (cluster left in degraded state)
	//   - Data loss from incomplete snapshots (backup starts but token expires before completion)
	//   - Split-brain risk from partial Raft reconfig (peer added but not fully joined)
	TTLWarningThreshold = 300 // 5 minutes

	// TTLMinimumRequired is the absolute minimum TTL (in seconds) required to proceed.
	//
	// RATIONALE: 60 seconds is bare minimum for capability checks (4 paths @ ~250ms each) plus
	//            initialization overhead (~10s) plus minimal operation time (~30s). Any less and
	//            operation is guaranteed to fail mid-execution.
	// SECURITY: Hard stop before operations that would fail mid-execution. Prevents:
	//           - Snapshot corruption (backup starts but token expires before write completes)
	//           - Raft peer instability (peer joins but token expires before consensus)
	//           - Autopilot misconfiguration (partial config write)
	// THREAT MODEL:
	//   - Operational: User wastes time on operation that will fail
	//   - Security: Failed operations may leave credentials/state exposed in error messages
	//   - Availability: Repeated failures from expired tokens → operator frustration → bypass attempts
	TTLMinimumRequired = 60 // 1 minute

	// TTLRecheckThreshold is the TTL (in seconds) below which we re-check TTL after
	// validation to detect race conditions.
	//
	// RATIONALE: 2 minutes chosen because validation takes ~1-2 seconds for 4 capability checks.
	//            If TTL < 120s at start, it could drop below TTLMinimumRequired (60s) during
	//            validation. Re-checking catches this race condition.
	// SECURITY: Prevents TOCTOU (Time-Of-Check-Time-Of-Use) vulnerability where token is valid
	//           at start of validation but expires before operation begins.
	// THREAT MODEL:
	//   - Race condition: Token expires between validation and operation start
	//   - Attack scenario: Attacker provides token with 61s TTL → passes validation → expires
	//                      during operation → leaves cluster in inconsistent state
	//   - Defense: Re-check TTL after validation if initial TTL was < 120s
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
//
//	"hvs.CAESIJlU02LQZq..." → "hvs.***"
//	"s.1234567890abcdef" → "s.***"
//	"s.12abc..." → "s.***" (NOT "s.12***" - would expose token data)
//	"b.AAAAAQKr..." → "b.***"
//	"unknown" → "***"
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
			// P1 Issue #32 Fix: Use returned period value (but don't need it here)
			isPeriodic, _ := isPeriodicToken(rc, secret)
			if !isPeriodic {
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
		if err != nil {
			// SECURITY: Malformed TTL is suspicious - reject token
			// P0 Issue #31 Fix: Don't skip validation on error (regression from previous fix)
			// Original code with `ttlSeconds, _ := ttlRaw.Int64()` got 0 on error → rejected
			// Changed to `if err == nil` → skipped validation → accepted invalid token
			// Now: explicitly reject tokens with malformed TTL
			logger.Warn("⚠️  Token has malformed TTL field (rejecting token)",
				zap.String("ttl_raw_type", fmt.Sprintf("%T", ttlRaw)),
				zap.Int("ttl_raw_length", len(string(ttlRaw))),
				zap.Error(err))
			return fmt.Errorf("token has malformed TTL field: %w", err)
		}

		ttlDuration := time.Duration(ttlSeconds) * time.Second

		// Check if token is periodic (auto-renewable, never expires)
		// P0 Issue #12 Fix: Use centralized helper instead of duplicate logic
		// P1 Issue #32 Fix: Get period value directly, don't re-parse
		isPeriodic, periodSeconds := isPeriodicToken(rc, secret)
		if isPeriodic {
			logger.Debug("✓ Token is periodic (auto-renewable)",
				zap.Int64("current_ttl_seconds", ttlSeconds),
				zap.Int64("period_seconds", periodSeconds),
				zap.String("period_human", formatTTLDuration(periodSeconds)))
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
	} else {
		// P2 Issue #42 Fix: TTL field is missing or wrong type
		// SECURITY: Non-periodic tokens MUST have a valid TTL field
		// If token is periodic, missing TTL is OK (auto-renews)
		// If token is non-periodic, missing TTL means no expiration - REJECT
		isPeriodic, _ := isPeriodicToken(rc, secret)

		if !isPeriodic {
			// Non-periodic token without TTL field - this is a security hole
			logger.Warn("⚠️  Non-periodic token is missing TTL field (rejecting)",
				zap.Bool("periodic", isPeriodic),
				zap.Any("ttl_field_present", secret.Data["ttl"] != nil),
				zap.String("ttl_field_type", fmt.Sprintf("%T", secret.Data["ttl"])))
			return fmt.Errorf("non-periodic token must have valid TTL field (token has no expiration)")
		}

		// Periodic token without TTL field - acceptable (auto-renews)
		logger.Debug("✓ Periodic token without TTL field (auto-renews, no expiration check needed)",
			zap.Bool("periodic", isPeriodic))
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
		"sys/storage/raft/configuration",           // Raft peer configuration
		"sys/storage/raft/snapshot",                // Snapshot backup/restore
		"sys/storage/raft/autopilot/configuration", // Autopilot config
		"sys/storage/raft/autopilot/state",         // Autopilot state query
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
	// P2 Issue #25 Fix: Check Int64() error instead of ignoring it
	if ttlRaw, ok := secret.Data["ttl"].(json.Number); ok {
		ttlSeconds, err := ttlRaw.Int64()
		if err != nil {
			// SECURITY: Log malformed TTL values (could indicate attack or Vault bug)
			// P1 Issue #40 Fix: Sanitize raw input before logging to prevent log injection
			logger.Warn("⚠️  Token has malformed TTL field",
				zap.String("ttl_raw", sanitizeForLogging(string(ttlRaw))),
				zap.Error(err))
			// Skip race condition check if TTL is malformed
			// Original validation passed, so continue with operation
			return nil
		}

		// Check if token WAS periodic at start of validation
		// P1 Issue #32 Fix: Get period value (though not needed here)
		isPeriodic, _ := isPeriodicToken(rc, secret)

		// Only re-check for non-periodic tokens (periodic tokens auto-renew)
		if !isPeriodic && ttlSeconds < TTLRecheckThreshold {
			logger.Debug("Token TTL is low, re-checking after validation delay",
				zap.Int64("initial_ttl", ttlSeconds))

			// Re-check TTL to account for validation time
			secretRefresh, err := client.Auth().Token().LookupSelf()
			if err != nil {
				// P2 Issue #29 Fix: Distinguish token invalidity from network errors
				errMsg := err.Error()
				if strings.Contains(errMsg, "permission denied") ||
					strings.Contains(errMsg, "invalid token") ||
					strings.Contains(errMsg, "token not found") {
					// Token was revoked or invalidated during validation
					return fmt.Errorf("token was revoked or invalidated during validation: %w", err)
				}

				// Network error or temporary issue - log but don't fail
				logger.Warn("Could not re-check TTL after validation (network error)",
					zap.Error(err))
				// Don't fail - original TTL was acceptable
			} else if secretRefresh != nil && secretRefresh.Data != nil {
				// CRITICAL: Check if token became periodic during validation (P0 Issue #13 Fix)
				// P1 Issue #32 Fix: Get period value (though not needed here)
				isPeriodicRefresh, _ := isPeriodicToken(rc, secretRefresh)

				if isPeriodicRefresh && !isPeriodic {
					// Token became periodic during validation - this is OK, it will auto-renew
					logger.Info("✓ Token became periodic during validation - will auto-renew",
						zap.Int64("initial_ttl", ttlSeconds),
						zap.Bool("was_periodic", isPeriodic),
						zap.Bool("is_periodic_now", isPeriodicRefresh))
					return nil
				}

				// P1 Issue #22 Fix: Check if token LOST its periodic status during validation
				// P2 Issue #37 Fix: Track this state to reject if TTL is also malformed
				lostPeriodicStatus := !isPeriodicRefresh && isPeriodic
				if lostPeriodicStatus {
					// Token was periodic but is now non-periodic - period was revoked
					logger.Warn("⚠️  Token lost periodic status during validation",
						zap.Int64("initial_ttl", ttlSeconds),
						zap.Bool("was_periodic", isPeriodic),
						zap.Bool("is_periodic_now", isPeriodicRefresh))
					// Continue with non-periodic validation (check fresh TTL below)
					// Don't return - need to validate TTL is sufficient
				}

				if ttlRefreshRaw, ok := secretRefresh.Data["ttl"].(json.Number); ok {
					ttlRefresh, err := ttlRefreshRaw.Int64()
					if err != nil {
						// SECURITY: Log malformed TTL values (could indicate attack or Vault bug)
						// P2 Issue #25 Fix: Check Int64() error instead of ignoring it
						// P1 Issue #40 Fix: Sanitize raw input before logging to prevent log injection
						// P2 Issue #37 Fix: If token lost periodic status AND has malformed TTL, REJECT
						logger.Warn("⚠️  Refreshed token has malformed TTL field",
							zap.String("ttl_raw", sanitizeForLogging(string(ttlRefreshRaw))),
							zap.Bool("lost_periodic_status", lostPeriodicStatus),
							zap.Error(err))

						if lostPeriodicStatus {
							// SECURITY: Token lost periodic status (manual revocation or attack)
							// AND has malformed TTL field. This is highly suspicious - REJECT.
							// Rationale: We can't validate the fresh TTL, and the token can no
							// longer auto-renew. Accepting this token would bypass TTL validation.
							return fmt.Errorf("token lost periodic status and has malformed TTL field (cannot validate security)")
						}

						// Can't validate fresh TTL, but original validation passed
						return nil
					}

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
				} else if lostPeriodicStatus {
					// P2 Issue #37 Fix: Token lost periodic status but TTL field is missing
					// This is suspicious - we can't validate the token's remaining lifetime
					logger.Warn("⚠️  Token lost periodic status but TTL field is missing from refresh")
					return fmt.Errorf("token lost periodic status and TTL field is missing (cannot validate security)")
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
//
//	45 seconds  → "45s"
//	120 seconds → "2m"
//	3665 seconds → "1h1m"
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

// sanitizeForLogging truncates and sanitizes potentially malicious input before logging.
// This prevents log injection attacks and excessive log file consumption.
//
// P1 Issue #40 Fix: Malicious Vault responses could contain:
//   - Extremely long strings (DoS log files)
//   - Control characters (log injection, terminal escape sequences)
//   - ANSI escape codes (terminal manipulation)
//
// Security properties:
//   - Truncates to 100 chars max (prevents log file DoS)
//   - Removes control characters (prevents log injection)
//   - Preserves printable ASCII and common UTF-8
//   - Adds ellipsis if truncated
func sanitizeForLogging(raw string) string {
	const maxLength = 100

	// P2 Issue #43 Fix: Remove ALL control characters including newlines
	// SECURITY: Newlines allow log injection attacks (fake log entries)
	// Original code kept tab/newline/CR - WRONG for log safety
	// Remove control characters (ASCII 0-31, ASCII 127)
	// Keep ONLY: printable ASCII (32-126) and UTF-8 (128+)
	sanitized := strings.Map(func(r rune) rune {
		// ALL control characters (0-31) - including tab, newline, CR
		if r < 32 {
			return ' ' // Replace with space for readability
		}
		// DEL character (127)
		if r == 127 {
			return -1 // Remove
		}
		// ANSI escape sequences start with ESC (27) - already caught above
		return r
	}, raw)

	// P3 Issue #44 Fix: Truncate on rune boundaries (UTF-8 safe)
	// Using len() checks byte length, but UTF-8 chars can be 2-4 bytes
	// Truncating at byte boundary could split a multi-byte character
	runes := []rune(sanitized)
	if len(runes) > maxLength {
		return string(runes[:maxLength]) + "...[truncated]"
	}

	return sanitized
}

// isPeriodicToken checks if a token is periodic (auto-renewable).
// Periodic tokens have a non-zero period value and will automatically renew.
//
// This is a centralized helper to ensure consistent periodic token detection
// across multiple validation checks. It handles error cases consistently:
// - nil secret or nil Data returns (false, 0)
// - type assertion failure returns (false, 0)
// - Int64() conversion error returns (false, 0) with warning logged
// - period <= 0 returns (false, 0)
//
// P0 Issue #12 Fix: Replaces 3 duplicate isPeriodic checks with inconsistent error handling.
// P0 Issue #21 Fix: Logs errors when Int64() conversion fails (detects malformed/attack responses).
// P1 Issue #32 Fix: Returns period value to avoid re-parsing at call sites.
//
// Returns: (isPeriodic bool, periodSeconds int64)
//   - (true, 14400) for periodic token with 4h period
//   - (false, 0) for non-periodic or error cases
func isPeriodicToken(rc *eos_io.RuntimeContext, secret *api.Secret) (bool, int64) {
	// P0 Issue #38 Fix: Prevent panic from nil RuntimeContext
	// If rc is nil, we can't log warnings, so return false defensively
	if rc == nil || secret == nil || secret.Data == nil {
		return false, 0
	}

	if periodRaw, ok := secret.Data["period"].(json.Number); ok {
		periodSeconds, err := periodRaw.Int64()
		if err != nil {
			// SECURITY: Log malformed period values (could indicate attack or Vault bug)
			// P0 Issue #21 Fix: Don't silently return false - log for forensics
			// P1 Issue #40 Fix: Sanitize raw input before logging to prevent log injection
			logger := otelzap.Ctx(rc.Ctx)
			logger.Warn("⚠️  Token has malformed period field (treating as non-periodic)",
				zap.String("period_raw", sanitizeForLogging(string(periodRaw))),
				zap.Error(err))
			return false, 0
		}
		// Only return true if conversion succeeded AND period > 0
		isPeriodic := periodSeconds > 0
		return isPeriodic, periodSeconds
	}

	return false, 0
}
