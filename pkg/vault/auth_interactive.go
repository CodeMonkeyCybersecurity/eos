// pkg/vault/auth_interactive.go
//
// Context-aware interactive authentication wrappers
//
// This file provides UX-appropriate prompts for different authentication contexts.
// Each context has different messaging and user expectations:
//
// AuthContextSetup    - User is setting up Vault (eos create vault --enable-userpass)
//                       Prompt: "Do you want to enable userpass authentication?"
//
// AuthContextRuntime  - User is running normal operations (eos sync consul, eos create service)
//                       Automated auth failed, offering interactive fallback
//                       Prompt: "Authenticate with username/password?"
//                       Shows diagnostic info about WHY automated auth failed
//
// AuthContextDebug    - User is debugging Vault (eos debug vault)
//                       Needs auth for diagnostic access
//                       Prompt: "Authenticate for debug access?"
//
// AuthContextLogin    - User explicitly wants to authenticate (eos login vault)
//                       No prompt needed, user already chose this action
//
// Architecture:
// - These functions wrap core auth logic from auth_core.go
// - They add context-appropriate UX (prompts, explanations, remediation)
// - They compose pure auth functions with user interaction
//
// Philosophy:
// - Separation: UX logic here, auth logic in auth_core.go
// - Composability: Different contexts reuse same core auth functions
// - Human-centric: Clear explanations, actionable remediation

package vault

import (
	"errors"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// InteractiveAuthContext determines the UX for interactive authentication prompts
type InteractiveAuthContext string

const (
	// AuthContextSetup - User is setting up Vault, explicitly enabling auth method
	// Example: eos create vault --enable-userpass
	// UX: "Do you want to enable userpass authentication?"
	AuthContextSetup InteractiveAuthContext = "setup"

	// AuthContextRuntime - Normal operations where automated auth failed
	// Examples: eos sync consul, eos create grafana, eos backup vault
	// UX: Show diagnostic info, suggest remediation, offer interactive fallback
	AuthContextRuntime InteractiveAuthContext = "runtime"

	// AuthContextDebug - Debugging Vault, needs auth for diagnostic access
	// Example: eos debug vault
	// UX: "Authenticate for debug access?"
	AuthContextDebug InteractiveAuthContext = "debug"

	// AuthContextLogin - User explicitly wants to authenticate
	// Example: eos login vault
	// UX: No prompt needed, user already chose this
	AuthContextLogin InteractiveAuthContext = "login"
)

// tryUserpassInteractive prompts for userpass authentication with context-appropriate messaging
// This wraps coreUserpassAuth from auth_core.go with UX appropriate for the context
func tryUserpassInteractive(rc *eos_io.RuntimeContext, client *api.Client, context InteractiveAuthContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Context-specific prompting and messaging
	switch context {
	case AuthContextSetup:
		// Vault setup flow - user is explicitly enabling auth method
		log.Info("Setting up userpass authentication")
		log.Info("This will create a username/password auth method in Vault")

		if !interaction.PromptYesNo(rc.Ctx, "Do you want to enable userpass authentication?", false) {
			log.Info("Userpass setup skipped by user")
			return "", errors.New("userpass setup skipped by user")
		}

	case AuthContextRuntime:
		// Normal operation - automated auth failed, offering fallback

		// CRITICAL P1: Check if we're in a non-interactive environment (CI/CD, background job)
		// Prompting in non-TTY environments causes hangs
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			log.Error("")
			log.Error("═══════════════════════════════════════════════════════════")
			log.Error("Automated Vault authentication failed (non-interactive environment)")
			log.Error("═══════════════════════════════════════════════════════════")
			log.Error("")
			log.Error("Cannot prompt for credentials: no TTY detected")
			log.Error("This environment does not support interactive input (CI/CD, cron, background job)")
			log.Error("")
			log.Error("REMEDIATION:")
			log.Error("  1. Run this command with sudo (for vault-agent token access)")
			log.Error("  2. Fix Vault Agent service: systemctl status vault-agent-eos")
			log.Error("  3. Ensure AppRole credentials are readable")
			log.Error("")
			return "", fmt.Errorf("automated authentication failed in non-interactive environment (no TTY)")
		}

		log.Warn("")
		log.Warn("═══════════════════════════════════════════════════════════")
		log.Warn("Automated Vault authentication failed")
		log.Warn("═══════════════════════════════════════════════════════════")
		log.Warn("")
		log.Warn("Common causes:")
		log.Warn("  • Running without sudo (vault-agent token requires root)")
		log.Warn("  • AppRole credentials missing or unreadable")
		log.Warn("  • Vault Agent service not running")
		log.Warn("")
		log.Warn("Recommended actions:")
		log.Warn("  1. Check if permission errors appear above")
		log.Warn("  2. If yes: Run this command with sudo")
		log.Warn("  3. If no: Check Vault Agent status: systemctl status vault-agent-eos")
		log.Warn("")
		log.Warn("Alternative:")
		log.Warn("  Authenticate interactively with username/password (if userpass is enabled)")
		log.Warn("")

		if !interaction.PromptYesNo(rc.Ctx, "Authenticate interactively with username/password?", false) {
			log.Info("Interactive authentication declined by user")
			return "", errors.New("interactive authentication declined by user")
		}

	case AuthContextDebug:
		// Debug mode - needs auth for diagnostic access
		log.Info("Debug mode requires Vault authentication")
		log.Info("This will authenticate to access Vault diagnostic information")

		if !interaction.PromptYesNo(rc.Ctx, "Authenticate with username/password for debug access?", false) {
			log.Info("Debug authentication declined by user")
			return "", errors.New("debug authentication declined")
		}

	case AuthContextLogin:
		// Explicit login command - no prompt needed, user already chose this
		log.Info("Authenticating to Vault with username/password")
		log.Info("You will be prompted for credentials")

	default:
		return "", fmt.Errorf("unknown authentication context: %s", context)
	}

	// Common logic: prompt for credentials and authenticate
	return promptAndAuthenticateUserpass(rc, client)
}

// promptAndAuthenticateUserpass handles credential prompting and calls core auth logic
// This is the common path used by all contexts after context-specific prompting
//
// P0 FIX: Added MFA enforcement verification before prompting for credentials
func promptAndAuthenticateUserpass(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Prompting for Vault username")
	usernames, err := interaction.PromptSecrets(rc.Ctx, "Username", 1)
	if err != nil {
		log.Warn("Failed to prompt for username", zap.Error(err))
		return "", fmt.Errorf("prompt username: %w", err)
	}

	username := usernames[0]

	// P0 FIX: Check MFA enforcement BEFORE prompting for password
	// This prevents security theater where we accept password without MFA
	log.Debug("Checking MFA enforcement status for user",
		zap.String("username", username))

	mfaEnforced, mfaCheckErr := checkUserpassMFAEnforcement(rc, client, username)
	if mfaCheckErr != nil {
		log.Warn("Cannot verify MFA enforcement status - proceeding with caution",
			zap.Error(mfaCheckErr),
			zap.String("username", username))
		log.Warn("If MFA is required, authentication will prompt for TOTP code")
	} else if !mfaEnforced {
		// MFA is NOT enforced - warn user about security risk
		log.Warn("")
		log.Warn("═══════════════════════════════════════════════════════════")
		log.Warn("SECURITY WARNING: MFA Not Enforced")
		log.Warn("═══════════════════════════════════════════════════════════")
		log.Warn("")
		log.Warn("Userpass authentication does NOT require MFA for this user.")
		log.Warn("This is a security risk - passwords alone are not sufficient.")
		log.Warn("")
		log.Warn("Recommended: Enable MFA enforcement")
		log.Warn("  1. Run: sudo eos create vault --enable-mfa")
		log.Warn("  2. Or manually configure MFA policies in Vault")
		log.Warn("")

		if !interaction.PromptYesNo(rc.Ctx, "Continue with unprotected userpass auth?", false) {
			return "", errors.New("userpass authentication declined due to missing MFA")
		}
		log.Warn("")
	} else {
		log.Info("✓ MFA enforcement verified for user", zap.String("username", username))
	}

	log.Debug("Prompting for Vault password")
	passwords, err := interaction.PromptSecrets(rc.Ctx, "Password", 1)
	if err != nil {
		log.Warn("Failed to prompt for password", zap.Error(err))
		return "", fmt.Errorf("prompt password: %w", err)
	}

	password := passwords[0]

	log.Debug("Calling core userpass authentication",
		zap.String("username", username))

	// Call core authentication logic (no prompts, pure auth)
	// This will automatically handle MFA challenge if enforced
	token, err := coreUserpassAuth(rc, client, username, password)
	if err != nil {
		log.Warn("Userpass authentication failed",
			zap.String("username", username),
			zap.Error(err))
		return "", fmt.Errorf("userpass authentication failed: %w", err)
	}

	log.Info("Userpass authentication successful",
		zap.String("username", username))

	return token, nil
}

// tryAppRoleInteractive wraps AppRole auth with context-appropriate error messages
// This is less interactive (no prompts) but still provides context-specific diagnostics
func tryAppRoleInteractive(rc *eos_io.RuntimeContext, client *api.Client, context InteractiveAuthContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Attempting AppRole authentication",
		zap.String("context", string(context)))

	token, err := coreAppRoleAuth(rc, client)
	if err != nil {
		// Provide context-specific error messages
		switch context {
		case AuthContextRuntime:
			log.Debug("AppRole authentication failed (normal operations)",
				zap.Error(err),
				zap.String("note", "Will try next authentication method"))
		case AuthContextSetup:
			log.Debug("AppRole authentication failed (Vault setup)",
				zap.Error(err),
				zap.String("note", "This is expected during initial Vault setup"))
		default:
			log.Debug("AppRole authentication failed",
				zap.Error(err))
		}
		return "", err
	}

	log.Debug("AppRole authentication successful",
		zap.String("context", string(context)))

	return token, nil
}

// tryAgentTokenInteractive wraps agent token auth with context-appropriate error messages
func tryAgentTokenInteractive(rc *eos_io.RuntimeContext, client *api.Client, tokenPath string, context InteractiveAuthContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Attempting Vault Agent token authentication",
		zap.String("path", tokenPath),
		zap.String("context", string(context)))

	token, err := coreAgentTokenAuth(rc, client, tokenPath)
	if err != nil {
		// Provide context-specific error messages
		switch context {
		case AuthContextRuntime:
			log.Debug("Vault Agent token authentication failed",
				zap.Error(err),
				zap.String("note", "This usually means permission denied or agent not running"))
		case AuthContextSetup:
			log.Debug("Vault Agent token authentication failed",
				zap.Error(err),
				zap.String("note", "This is expected during initial Vault setup"))
		default:
			log.Debug("Vault Agent token authentication failed",
				zap.Error(err))
		}
		return "", err
	}

	log.Debug("Vault Agent token authentication successful",
		zap.String("context", string(context)))

	return token, nil
}

// checkUserpassMFAEnforcement checks if MFA is enforced for userpass authentication
// Returns true if MFA enforcement policy exists and targets users, false otherwise
//
// P0 FIX: Pre-flight check to detect MFA bypass vulnerability
func checkUserpassMFAEnforcement(rc *eos_io.RuntimeContext, client *api.Client, username string) (bool, error) {
	log := otelzap.Ctx(rc.Ctx)

	// List all MFA login enforcement policies
	listResp, err := client.Logical().List("identity/mfa/login-enforcement")
	if err != nil {
		log.Debug("Cannot list MFA enforcement policies", zap.Error(err))
		return false, fmt.Errorf("cannot list MFA enforcement policies: %w", err)
	}

	if listResp == nil || listResp.Data == nil {
		log.Debug("No MFA enforcement policies found")
		return false, nil
	}

	keys, ok := listResp.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		log.Debug("No MFA enforcement policy keys found")
		return false, nil
	}

	// Check each policy for userpass enforcement with entity IDs
	for _, keyInterface := range keys {
		policyName, ok := keyInterface.(string)
		if !ok {
			continue
		}

		policyPath := fmt.Sprintf("identity/mfa/login-enforcement/%s", policyName)
		policyResp, err := client.Logical().Read(policyPath)
		if err != nil || policyResp == nil || policyResp.Data == nil {
			continue
		}

		// Check if policy targets userpass auth method
		authMethodTypes, ok := policyResp.Data["auth_method_types"].([]interface{})
		if !ok {
			continue
		}

		hasUserpass := false
		for _, authType := range authMethodTypes {
			if authTypeStr, ok := authType.(string); ok && authTypeStr == "userpass" {
				hasUserpass = true
				break
			}
		}

		if !hasUserpass {
			continue
		}

		// Check if policy has entity IDs (enforcement is active)
		entityIDs, ok := policyResp.Data["identity_entity_ids"].([]interface{})
		if ok && len(entityIDs) > 0 {
			log.Debug("Found MFA enforcement policy for userpass with entity targeting",
				zap.String("policy", policyName),
				zap.Int("entity_count", len(entityIDs)))
			return true, nil
		}
	}

	log.Debug("No active MFA enforcement found for userpass (no policies with entity IDs)")
	return false, nil
}

// checkUserpassAdminEligibility checks if a user can obtain admin-level tokens via userpass
// Returns true if the user has eos-admin-policy assigned, false otherwise
//
// P1 FIX: Pre-flight check to avoid wasting user's time entering credentials
func checkUserpassAdminEligibility(rc *eos_io.RuntimeContext, client *api.Client, username string) (bool, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Try to lookup entity by userpass alias
	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		log.Debug("Cannot list auth mounts for entity lookup", zap.Error(err))
		return false, fmt.Errorf("cannot list auth mounts: %w", err)
	}

	userpassMount, exists := authMounts["userpass/"]
	if !exists {
		log.Debug("Userpass auth method not found")
		return false, fmt.Errorf("userpass auth method not enabled")
	}

	// Lookup entity by alias
	aliasLookupData := map[string]interface{}{
		"alias_name":           username,
		"alias_mount_accessor": userpassMount.Accessor,
	}

	aliasResp, err := client.Logical().Write("identity/lookup/entity", aliasLookupData)
	if err != nil || aliasResp == nil || aliasResp.Data == nil {
		log.Debug("Entity not found for user", zap.String("username", username), zap.Error(err))
		return false, nil // No entity = no admin policy
	}

	// Check entity policies
	policies, ok := aliasResp.Data["policies"].([]interface{})
	if !ok {
		log.Debug("No policies found for entity")
		return false, nil
	}

	// Check for admin policy
	for _, policyInterface := range policies {
		if policy, ok := policyInterface.(string); ok {
			if policy == shared.EosAdminPolicyName || policy == "root" {
				log.Debug("User has admin policy",
					zap.String("username", username),
					zap.String("policy", policy))
				return true, nil
			}
		}
	}

	log.Debug("User lacks admin policy", zap.String("username", username))
	return false, nil
}

// tryRootTokenInteractive prompts for root token usage with appropriate warnings
// P0 FIX: Add root token as emergency authentication method before userpass
func tryRootTokenInteractive(rc *eos_io.RuntimeContext, client *api.Client, context InteractiveAuthContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Verify running as root (sudo)
	if os.Geteuid() != 0 {
		log.Debug("Root token auth requires sudo")
		return "", fmt.Errorf("root token authentication requires sudo access")
	}

	// Context-specific prompting
	switch context {
	case AuthContextRuntime:
		log.Warn("")
		log.Warn("═══════════════════════════════════════════════════════════")
		log.Warn("Emergency Root Token Authentication")
		log.Warn("═══════════════════════════════════════════════════════════")
		log.Warn("")
		log.Warn("All automated authentication methods have failed.")
		log.Warn("")
		log.Warn("OPTION 1: Use root token (immediate fix)")
		log.Warn("  • Bypasses audit logging")
		log.Warn("  • Should only be used in emergencies")
		log.Warn("  • More secure than userpass without MFA")
		log.Warn("")
		log.Warn("OPTION 2: Fix Vault Agent service (recommended)")
		log.Warn("  • sudo systemctl restart vault-agent-eos")
		log.Warn("  • Then re-run this command")
		log.Warn("")

		if !interaction.PromptYesNo(rc.Ctx, "Use emergency root token authentication?", false) {
			log.Info("Root token authentication declined by user")
			return "", errors.New("root token authentication declined by user")
		}

	case AuthContextSetup:
		log.Info("Using root token for Vault setup")

	case AuthContextDebug:
		log.Info("Debug mode using root token for diagnostic access")
		if !interaction.PromptYesNo(rc.Ctx, "Use root token for debug access?", false) {
			return "", errors.New("root token debug access declined")
		}

	case AuthContextLogin:
		log.Info("Authenticating with root token")
		log.Warn("⚠️  Root token bypasses audit logging")

	default:
		return "", fmt.Errorf("unknown authentication context: %s", context)
	}

	// Try to read root token
	log.Info("Reading root token from initialization file")
	token, err := tryRootToken(rc, client)
	if err != nil {
		log.Warn("Failed to read root token from disk", zap.Error(err))

		// Offer manual input
		if context == AuthContextRuntime || context == AuthContextLogin {
			if interaction.PromptYesNo(rc.Ctx, "Enter root token manually?", false) {
				tokens, promptErr := interaction.PromptSecrets(rc.Ctx, "Root Token", 1)
				if promptErr != nil {
					return "", fmt.Errorf("failed to prompt for root token: %w", promptErr)
				}

				manualToken, validateErr := coreRootTokenAuth(rc, client, tokens[0])
				if validateErr != nil {
					return "", fmt.Errorf("root token validation failed: %w", validateErr)
				}

				log.Warn("✓ Root token authenticated successfully")
				log.Warn("⚠️  Root token bypasses audit logging")
				return manualToken, nil
			}
		}

		return "", fmt.Errorf("root token not available: %w", err)
	}

	log.Warn("✓ Root token authenticated successfully")
	log.Warn("⚠️  Root token bypasses audit logging")
	if context == AuthContextRuntime {
		log.Warn("⚠️  Fix Vault Agent to avoid future root token use:")
		log.Warn("     sudo systemctl restart vault-agent-eos")
	}
	log.Warn("")

	return token, nil
}
