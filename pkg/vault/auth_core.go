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
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// coreUserpassAuth authenticates to Vault using username/password
// Returns: token string on success, error on failure
// Does NOT prompt for credentials - caller must provide them
func coreUserpassAuth(rc *eos_io.RuntimeContext, client *api.Client, username, password string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Attempting userpass authentication",
		zap.String("username", username),
		zap.String("auth_path", "auth/userpass/login"))

	secret, err := client.Logical().Write(
		fmt.Sprintf("auth/userpass/login/%s", username),
		map[string]interface{}{"password": password})

	if err != nil {
		log.Debug("Userpass authentication failed",
			zap.String("username", username),
			zap.Error(err))
		return "", cerr.Wrap(err, "userpass login failed")
	}

	if secret == nil || secret.Auth == nil {
		log.Debug("Userpass authentication returned nil secret",
			zap.String("username", username))
		return "", fmt.Errorf("userpass login returned nil secret")
	}

	log.Debug("Userpass authentication successful",
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
