// pkg/vault/auth_core.go
//
// Core Vault authentication logic - context-agnostic, no user prompts
//
// This file contains pure authentication functions that:
// - Return tokens or errors
// - Have NO user-facing prompts
// - Have NO context-specific messages
// - Are composable building blocks for context-aware wrappers
//
// Philosophy:
// - Separation of concerns: auth logic vs UX
// - Single Responsibility: each function does ONE thing
// - Composability: used by context-aware wrappers in auth_interactive.go
//
// Used by:
// - auth_interactive.go: Context-aware wrappers (setup, runtime, debug, login)
// - auth_security.go: SecureAuthenticationOrchestrator
// - auth_userpass.go: EnableVaultUserpass

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// coreUserpassAuth authenticates to Vault using username/password
// Returns: token string on success, error on failure
// Does NOT prompt for credentials - caller must provide them
// Handles MFA challenges automatically by prompting for TOTP code if required
func coreUserpassAuth(rc *eos_io.RuntimeContext, client *api.Client, username, password string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Attempting userpass authentication",
		zap.String("username", username),
		zap.String("auth_path", "auth/userpass/login"))

	// Step 1: Initial authentication with username/password
	secret, err := client.Logical().Write(
		fmt.Sprintf("auth/userpass/login/%s", username),
		map[string]interface{}{"password": password})

	if err != nil {
		log.Debug("Userpass authentication failed",
			zap.String("username", username),
			zap.Error(err))
		return "", cerr.Wrap(err, "userpass login failed")
	}

	if secret == nil {
		log.Debug("Userpass authentication returned nil secret",
			zap.String("username", username))
		return "", fmt.Errorf("userpass login returned nil secret")
	}

	// Step 2: Check for MFA challenge
	// When MFA is enforced, secret.Auth will be nil and secret.Data contains mfa_request_id
	if secret.Auth == nil {
		// Check if this is an MFA challenge
		if secret.Data != nil {
			if mfaRequestID, ok := secret.Data["mfa_request_id"].(string); ok && mfaRequestID != "" {
				log.Info("MFA required for authentication - TOTP challenge detected",
					zap.String("username", username))
				return handleMFAChallenge(rc, client, mfaRequestID)
			}
		}

		// Not an MFA challenge, genuinely nil auth
		log.Debug("Userpass authentication returned nil auth (not MFA challenge)",
			zap.String("username", username))
		return "", fmt.Errorf("userpass login returned nil auth")
	}

	// Step 3: No MFA required, return token directly
	log.Debug("Userpass authentication successful (no MFA required)",
		zap.String("username", username),
		zap.String("token_accessor", secret.Auth.Accessor))

	return secret.Auth.ClientToken, nil
}

// coreAppRoleAuth authenticates to Vault using AppRole credentials from disk
// Returns: token string on success, error on failure
// Reads credentials from /var/lib/eos/secret/role_id and secret_id
func coreAppRoleAuth(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Reading AppRole credentials from disk",
		zap.String("role_id_path", shared.AppRolePaths.RoleID),
		zap.String("secret_id_path", shared.AppRolePaths.SecretID))

	roleID, secretID, err := readAppRoleCredsFromDisk(rc, client)
	if err != nil {
		log.Debug("Failed to read AppRole credentials",
			zap.Error(err))
		return "", cerr.Wrap(err, "read AppRole credentials from disk")
	}

	log.Debug("Attempting AppRole authentication",
		zap.String("auth_path", "auth/approle/login"))

	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})

	if err != nil || secret == nil || secret.Auth == nil {
		log.Debug("AppRole authentication failed",
			zap.Error(err))
		return "", fmt.Errorf("approle login failed")
	}

	log.Debug("AppRole authentication successful",
		zap.String("token_accessor", secret.Auth.Accessor))

	return secret.Auth.ClientToken, nil
}

// coreAgentTokenAuth reads and validates a Vault Agent token from disk
// Returns: token string on success, error on failure
// Path is typically /run/eos/vault_agent_eos.token
func coreAgentTokenAuth(rc *eos_io.RuntimeContext, client *api.Client, tokenPath string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Reading Vault Agent token from disk",
		zap.String("path", tokenPath))

	// Use existing retry logic for agent tokens (handles race condition)
	token, err := readAgentTokenWithRetry(rc, tokenPath)
	if err != nil {
		log.Debug("Failed to read agent token",
			zap.String("path", tokenPath),
			zap.Error(err))
		return "", cerr.Wrap(err, "read agent token from disk")
	}

	if token == "" {
		return "", fmt.Errorf("agent token file is empty")
	}

	log.Debug("Vault Agent token read successfully",
		zap.String("path", tokenPath))

	return token, nil
}

// coreRootTokenAuth validates a root token (caller must provide token)
// Returns: token string on success, error on failure
// Does NOT load from disk or prompt - pure validation only
// Used during Vault setup when no other auth methods exist yet
//
// Philosophy: Core auth functions do ONE thing (validate token format)
// Disk I/O and prompting belong in wrapper functions (auth.go:tryRootToken)
func coreRootTokenAuth(rc *eos_io.RuntimeContext, client *api.Client, rootToken string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Validating root token (caller-provided)")

	if rootToken == "" {
		return "", fmt.Errorf("root token is empty")
	}

	// Basic format validation (Vault tokens are typically non-empty strings)
	// Actual validation happens when the token is used
	log.Debug("Root token validation passed")

	return rootToken, nil
}

// handleMFAChallenge processes MFA challenges for userpass authentication
// Returns: token string on success, error on failure
// Prompts user for TOTP code and validates with Vault
//
// This function handles Vault Identity-based MFA flow:
//  1. User authenticates with username/password
//  2. Vault responds with mfa_request_id (instead of token)
//  3. User provides TOTP code from authenticator app
//  4. Vault validates TOTP and returns actual token
//
// Used automatically by coreUserpassAuth when MFA is enforced
func handleMFAChallenge(rc *eos_io.RuntimeContext, client *api.Client, mfaRequestID string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("")
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info("Multi-Factor Authentication Required")
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info("")
	log.Info("Your administrator has enabled MFA for this Vault instance.")
	log.Info("Please open your authenticator app (Google Authenticator, Authy, etc.)")
	log.Info("and enter the 6-digit TOTP code shown for this Vault instance.")
	log.Info("")

	// Prompt user for TOTP code
	log.Debug("Prompting for TOTP code",
		zap.String("mfa_request_id", mfaRequestID))

	totpCodes, err := interaction.PromptSecrets(rc.Ctx, "TOTP Code (6 digits)", 1)
	if err != nil {
		log.Error("Failed to prompt for TOTP code", zap.Error(err))
		return "", cerr.Wrap(err, "failed to prompt for TOTP code")
	}

	totpCode := totpCodes[0]

	// Validate TOTP code with Vault
	log.Debug("Validating TOTP code with Vault",
		zap.String("mfa_request_id", mfaRequestID))

	mfaPayload := map[string]interface{}{
		"mfa_request_id": mfaRequestID,
		"mfa_payload": map[string][]string{
			"totp": {totpCode},
		},
	}

	secret, err := client.Logical().Write("sys/mfa/validate", mfaPayload)
	if err != nil {
		log.Error("MFA validation failed",
			zap.Error(err),
			zap.String("mfa_request_id", mfaRequestID))
		log.Error("")
		log.Error("Common causes:")
		log.Error("  • TOTP code expired (codes are valid for 30 seconds)")
		log.Error("  • Incorrect code entered")
		log.Error("  • Authenticator app time drift (check device clock)")
		log.Error("")
		return "", cerr.Wrap(err, "MFA validation failed")
	}

	if secret == nil || secret.Auth == nil {
		log.Error("MFA validation returned no auth token")
		return "", fmt.Errorf("MFA validation returned no auth token")
	}

	log.Info("")
	log.Info("✓ MFA validation successful")
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info("")

	log.Debug("MFA authentication successful",
		zap.String("token_accessor", secret.Auth.Accessor))

	return secret.Auth.ClientToken, nil
}
