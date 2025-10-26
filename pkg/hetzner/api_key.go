// pkg/hetzner/api_key.go
//
// Secure API key management for Hetzner DNS operations.
// Integrates with SecretManager (Vault-backed) for credential storage.
// Uses crypto.SecureString to prevent logging leaks.

package hetzner

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetAPIKeyFromEnv retrieves Hetzner DNS API key from environment variable.
//
// Behavior:
//   - ASSESS: Check HETZNER_DNS_TOKEN environment variable
//   - EVALUATE: Return SecureString if found
//
// Environment Variable:
//
//	HETZNER_DNS_TOKEN: Hetzner DNS API token
//
// Error Handling:
//   - Returns error if environment variable not set
//   - Does NOT log the token value (SecureString prevents logging leaks)
//
// Returns:
//
//	*crypto.SecureString: API token wrapped in SecureString
//	error: Non-nil if environment variable not set
func GetAPIKeyFromEnv() (*crypto.SecureString, error) {
	token := os.Getenv("HETZNER_DNS_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("HETZNER_DNS_TOKEN environment variable not set")
	}

	return crypto.NewSecureString(token), nil
}

// GetAPIKeyFromSecretManager retrieves Hetzner DNS API key from SecretManager (Vault).
//
// Behavior:
//   - ASSESS: Query SecretManager for secret/hetzner/dns_token
//   - EVALUATE: Return SecureString if found
//
// Secret Path:
//
//	secret/hetzner/dns_token
//
// Error Handling:
//   - Returns error if SecretManager query fails
//   - Returns error if dns_token not found in secrets
//   - Logs debug message (no secret value logged)
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	sm: SecretManager instance (Vault-backed)
//
// Returns:
//
//	*crypto.SecureString: API token wrapped in SecureString
//	error: Non-nil if secret not found
func GetAPIKeyFromSecretManager(rc *eos_io.RuntimeContext, sm *secrets.SecretManager) (*crypto.SecureString, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Query SecretManager for hetzner DNS token
	token, err := sm.GetSecret("hetzner", "dns_token")
	if err != nil {
		logger.Debug("Hetzner API key not found in SecretManager",
			zap.Error(err))
		return nil, fmt.Errorf("API key not in SecretManager: %w", err)
	}

	if token == "" {
		return nil, fmt.Errorf("dns_token not found in secret/hetzner/dns_token")
	}

	return crypto.NewSecureString(token), nil
}

// PromptForAPIKey interactively prompts user for Hetzner DNS API token.
//
// Behavior:
//   - INFORM: Display information about where to get API key
//   - INTERVENE: Prompt user for API key via eos_io.PromptInput
//   - EVALUATE: Validate token is not empty
//
// User Experience:
//   - Displays link to Hetzner DNS API token page
//   - Uses secure input (characters not hidden, but value not logged)
//   - Clear error message if user provides empty input
//
// Error Handling:
//   - Returns eos_err.NewUserError if token is empty (user can fix)
//   - Returns error if input read fails (system error)
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//
// Returns:
//
//	*crypto.SecureString: API token wrapped in SecureString
//	error: Non-nil if prompt failed or token empty
func PromptForAPIKey(rc *eos_io.RuntimeContext) (*crypto.SecureString, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// INFORM: Display instructions
	logger.Info("Hetzner DNS API key required")
	logger.Info("Get your API key from: https://dns.hetzner.com/settings/api-token")
	logger.Info("")

	// INTERVENE: Prompt user
	token, err := eos_io.PromptInput(rc, "Enter Hetzner DNS API token: ", "hetzner_dns_token")
	if err != nil {
		return nil, fmt.Errorf("failed to read API key: %w", err)
	}

	// EVALUATE: Validate not empty
	if strings.TrimSpace(token) == "" {
		return nil, eos_err.NewUserError("API key cannot be empty")
	}

	return crypto.NewSecureString(token), nil
}

// StoreAPIKey stores Hetzner DNS API key in SecretManager for future use.
//
// Behavior:
//   - INTERVENE: Store token at secret/hetzner/dns_token
//   - EVALUATE: Log success or warning
//
// Secret Path:
//
//	secret/hetzner/dns_token
//
// Error Handling:
//   - Logs warning if storage fails (non-fatal)
//   - Returns error to caller for decision on how to handle
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	sm: SecretManager instance (Vault-backed)
//	token: API token wrapped in SecureString
//
// Returns:
//
//	error: Non-nil if storage failed
func StoreAPIKey(rc *eos_io.RuntimeContext, sm *secrets.SecretManager, token *crypto.SecureString) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Store in SecretManager at secret/hetzner/dns_token
	if err := sm.StoreSecret("hetzner", "dns_token", token.Value(), secrets.SecretTypeAPIKey); err != nil {
		logger.Warn("Failed to store API key in SecretManager",
			zap.Error(err))
		return fmt.Errorf("failed to store API key: %w", err)
	}

	logger.Info("Hetzner DNS API key stored in SecretManager")
	return nil
}

// GetOrPromptAPIKey orchestrates API key retrieval from multiple sources.
//
// This is the main entry point for getting a Hetzner DNS API key.
// Tries sources in order of precedence:
//  1. Environment variable (HETZNER_DNS_TOKEN)
//  2. SecretManager (Vault at secret/hetzner/dns_token)
//  3. Interactive user prompt
//
// Behavior:
//   - ASSESS: Try environment variable first (CI/CD compatibility)
//   - ASSESS: Try SecretManager second (persistent storage)
//   - INTERVENE: Prompt user if not found anywhere
//   - INTERVENE: Store in SecretManager for future use
//   - EVALUATE: Return token for use
//
// Precedence Rationale:
//   - Environment variable: Highest precedence for CI/CD, explicit overrides
//   - SecretManager: Persistent storage, works across sessions
//   - User prompt: Last resort, stores result for next time
//
// Error Handling:
//   - Returns error if all sources fail
//   - Warns if SecretManager storage fails (non-fatal)
//   - Uses SecureString to prevent logging leaks
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	sm: SecretManager instance (Vault-backed)
//
// Returns:
//
//	*crypto.SecureString: API token wrapped in SecureString
//	error: Non-nil if token could not be obtained
func GetOrPromptAPIKey(rc *eos_io.RuntimeContext, sm *secrets.SecretManager) (*crypto.SecureString, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Try environment variable first (highest precedence)
	if token, err := GetAPIKeyFromEnv(); err == nil {
		logger.Debug("Using Hetzner API key from environment variable")
		return token, nil
	}

	// ASSESS: Try SecretManager second (persistent storage)
	if token, err := GetAPIKeyFromSecretManager(rc, sm); err == nil {
		logger.Debug("Using Hetzner API key from SecretManager")
		return token, nil
	}

	// INTERVENE: Prompt user as last resort
	logger.Info("Hetzner DNS API key not found, prompting user")
	token, err := PromptForAPIKey(rc)
	if err != nil {
		return nil, err
	}

	// EVALUATE: Store for future use (non-fatal if fails)
	if err := StoreAPIKey(rc, sm, token); err != nil {
		logger.Warn("Could not store API key for future use",
			zap.Error(err),
			zap.String("remediation", "You will be prompted again next time"))
		// Non-fatal - continue with token we have
	}

	return token, nil
}

// VerifyAPIKeyAuthorization verifies API key has access to domain's zone.
//
// This function checks that:
//  1. API key is valid (not 401/403)
//  2. Zone exists in Hetzner account
//  3. API key has permission to access the zone
//
// Behavior:
//   - ASSESS: Extract zone name from domain (e.g., "example.com" from "app.example.com")
//   - ASSESS: Query Hetzner API for zone ID
//   - EVALUATE: Check for authorization errors
//
// Error Handling:
//   - Returns eos_err.NewUserError for 401/403 (user can fix by checking API key)
//   - Returns error for other failures (zone not found, network error)
//   - Provides actionable remediation steps in error message
//
// Remediation Steps (401/403):
//  1. Check API key is valid at https://dns.hetzner.com/settings/api-token
//  2. Verify zone exists in your Hetzner account
//  3. Verify API key has permission for DNS zones
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	token: API key wrapped in SecureString (value extracted internally)
//	domain: Fully qualified domain name (e.g., "app.example.com")
//
// Returns:
//
//	error: Non-nil if authorization failed
func VerifyAPIKeyAuthorization(rc *eos_io.RuntimeContext, token *crypto.SecureString, domain string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Verifying API key authorization",
		zap.String("domain", domain))

	// ASSESS: Extract zone name from domain
	zoneName := ExtractZoneName(domain)

	// ASSESS: Try to get zone ID (verifies access)
	zoneID, err := GetZoneIDForDomain(rc, token.Value(), zoneName)
	if err != nil {
		// Check for authorization errors
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
			return eos_err.NewUserError(
				"Hetzner API key unauthorized for domain %s\n"+
					"Verify:\n"+
					"  1. API key is valid (check https://dns.hetzner.com/settings/api-token)\n"+
					"  2. Zone %s exists in your Hetzner account\n"+
					"  3. API key has permission for DNS zones",
				domain, zoneName)
		}

		// Other error (network, zone not found, etc.)
		return fmt.Errorf("zone lookup failed for %s: %w", zoneName, err)
	}

	// EVALUATE: Success
	logger.Info("API key authorized",
		zap.String("zone", zoneName),
		zap.String("zone_id", zoneID))

	return nil
}
