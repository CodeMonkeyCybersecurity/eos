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
func promptAndAuthenticateUserpass(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Prompting for Vault username")
	usernames, err := interaction.PromptSecrets(rc.Ctx, "Username", 1)
	if err != nil {
		log.Warn("Failed to prompt for username", zap.Error(err))
		return "", fmt.Errorf("prompt username: %w", err)
	}

	log.Debug("Prompting for Vault password")
	passwords, err := interaction.PromptSecrets(rc.Ctx, "Password", 1)
	if err != nil {
		log.Warn("Failed to prompt for password", zap.Error(err))
		return "", fmt.Errorf("prompt password: %w", err)
	}

	username := usernames[0]
	password := passwords[0]

	log.Debug("Calling core userpass authentication",
		zap.String("username", username))

	// Call core authentication logic (no prompts, pure auth)
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
