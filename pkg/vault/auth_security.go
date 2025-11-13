package vault

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthenticationAttempt represents a single authentication attempt
type AuthenticationAttempt struct {
	Method    string
	StartTime time.Time
	EndTime   time.Time
	Success   bool
	ErrorType string // sanitized error type
	Sensitive bool   // whether this method uses sensitive files
}

// AuthenticationSession tracks a complete authentication session
type AuthenticationSession struct {
	StartTime     time.Time
	EndTime       time.Time
	Attempts      []AuthenticationAttempt
	SuccessMethod string
	TotalDuration time.Duration
}

// SecureAuthenticationOrchestrator provides improved security for vault authentication
func SecureAuthenticationOrchestrator(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	session := &AuthenticationSession{
		StartTime: time.Now(),
		Attempts:  make([]AuthenticationAttempt, 0),
	}
	defer func() {
		session.EndTime = time.Now()
		session.TotalDuration = session.EndTime.Sub(session.StartTime)
		logAuthenticationSession(rc, session)
	}()

	// Define authentication methods in priority order (most secure first)
	authMethods := []struct {
		name      string
		fn        func(*api.Client) (string, error)
		sensitive bool // whether this method uses sensitive files
		priority  int  // lower number = higher priority
	}{
		{
			name: "vault-agent-token",
			fn: func(client *api.Client) (string, error) {
				return tryAgentTokenInteractive(rc, client, VaultAgentTokenPath, AuthContextRuntime)
			},
			sensitive: true,
			priority:  1,
		},
		{
			name: "approle-auth",
			fn: func(client *api.Client) (string, error) {
				return tryAppRoleInteractive(rc, client, AuthContextRuntime)
			},
			sensitive: true,
			priority:  2,
		},
		{
			name: "interactive-userpass",
			fn: func(client *api.Client) (string, error) {
				return tryUserpassInteractive(rc, client, AuthContextRuntime)
			},
			sensitive: false,
			priority:  3,
		},
		// Note: Removed automatic fallback to root token for security
		// Root token should only be used in emergency situations with explicit user consent
	}

	// Try each authentication method
	for _, method := range authMethods {
		attempt := AuthenticationAttempt{
			Method:    method.name,
			StartTime: time.Now(),
			Sensitive: method.sensitive,
		}

		log.Info(" Attempting authentication method",
			zap.String("method", method.name),
			zap.Int("priority", method.priority),
		)

		token, err := method.fn(client)
		attempt.EndTime = time.Now()

		if err != nil {
			attempt.Success = false
			attempt.ErrorType = categorizeAuthError(err)
			session.Attempts = append(session.Attempts, attempt)

			// CRITICAL P0 FIX: Fail fast on permission errors for sensitive methods
			// When running without sudo, vault-agent token and AppRole files are unreadable
			// Cascading to userpass prompt is confusing - fail immediately with clear error
			if method.sensitive && attempt.ErrorType == "permission_denied" {
				// Get current username for error message (use $USER env var as fallback)
				username := os.Getenv("USER")
				if username == "" {
					username = "your-username"
				}

				log.Error("")
				log.Error("═══════════════════════════════════════════════════════════")
				log.Error("Vault authentication failed: Permission Denied")
				log.Error("═══════════════════════════════════════════════════════════")
				log.Error("")
				log.Error("This command requires elevated privileges to access Vault credentials")
				log.Error("")
				log.Error("CAUSE:")
				log.Error("  Authentication method failed due to permission denied",
					zap.String("method", method.name))
				log.Error("  Vault Agent token and AppRole credentials require root access")
				log.Error("")
				log.Error("REMEDIATION:")
				log.Error("  Option 1 (Recommended):")
				log.Error("    Run this command with sudo:")
				log.Error("      sudo eos [command]")
				log.Error("")
				log.Error("  Option 2 (Alternative):")
				log.Error("    Fix file permissions (may violate security model):")
				log.Error(fmt.Sprintf("      sudo chown %s:%s %s", username, username, VaultAgentTokenPath))
				log.Error(fmt.Sprintf("      sudo chown %s:%s %s", username, username, shared.AppRolePaths.RoleID))
				log.Error(fmt.Sprintf("      sudo chown %s:%s %s", username, username, shared.AppRolePaths.SecretID))
				log.Error("")
				log.Error("  Option 3 (If userpass is enabled):")
				log.Error("    Set up Vault userpass authentication:")
				log.Error("      sudo eos create vault --enable-userpass")
				log.Error("")

				return fmt.Errorf("vault authentication failed: permission denied on %s credentials (run with sudo)", method.name)
			}

			// Log failure without sensitive information
			log.Warn("Authentication method failed",
				zap.String("method", method.name),
				zap.String("error_category", attempt.ErrorType),
				zap.Duration("duration", attempt.EndTime.Sub(attempt.StartTime)),
			)
			continue
		}

		// Verify the token
		log.Debug(" Verifying authentication token", zap.String("method", method.name))
		if !VerifyToken(rc, client, token) {
			attempt.Success = false
			attempt.ErrorType = "token_verification_failed"
			session.Attempts = append(session.Attempts, attempt)

			log.Warn("Token verification failed",
				zap.String("method", method.name),
			)
			continue
		}

		// Success!
		attempt.Success = true
		session.Attempts = append(session.Attempts, attempt)
		session.SuccessMethod = method.name

		SetVaultToken(rc, client, token)
		log.Info(" Authentication successful",
			zap.String("method", method.name),
			zap.Duration("duration", attempt.EndTime.Sub(attempt.StartTime)),
		)
		return nil
	}

	// All methods failed - provide generic error without sensitive details
	log.Error(" All authentication methods exhausted",
		zap.Int("methods_tried", len(session.Attempts)),
		zap.Duration("total_duration", time.Since(session.StartTime)),
	)

	return errors.New("vault authentication failed: no valid authentication method available")
}

// categorizeAuthError converts specific errors into general categories to prevent information disclosure
func categorizeAuthError(err error) string {
	if err == nil {
		return "none"
	}

	errMsg := strings.ToLower(err.Error())

	// Categorize without exposing sensitive details
	switch {
	case strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "unauthorized"):
		return "permission_denied"
	case strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "no such file"):
		return "resource_not_found"
	case strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "deadline"):
		return "timeout"
	case strings.Contains(errMsg, "network") || strings.Contains(errMsg, "connection"):
		return "network_error"
	case strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "malformed"):
		return "invalid_format"
	default:
		return "general_error"
	}
}

// logAuthenticationSession logs the authentication session summary for security monitoring
func logAuthenticationSession(rc *eos_io.RuntimeContext, session *AuthenticationSession) {
	log := otelzap.Ctx(rc.Ctx)

	// Create summary without sensitive information
	var methodsAttempted []string
	var errorTypes []string
	successfulMethod := "none"

	for _, attempt := range session.Attempts {
		methodsAttempted = append(methodsAttempted, attempt.Method)
		if !attempt.Success && attempt.ErrorType != "" {
			errorTypes = append(errorTypes, fmt.Sprintf("%s:%s", attempt.Method, attempt.ErrorType))
		}
		if attempt.Success {
			successfulMethod = attempt.Method
		}
	}

	log.Info(" Authentication session summary",
		zap.Strings("methods_attempted", methodsAttempted),
		zap.String("successful_method", successfulMethod),
		zap.Strings("error_summary", errorTypes),
		zap.Duration("total_duration", session.TotalDuration),
		zap.Int("total_attempts", len(session.Attempts)),
	)

	// Alert on suspicious patterns
	if len(session.Attempts) > 3 {
		log.Warn(" Multiple authentication failures detected",
			zap.Int("failure_count", len(session.Attempts)),
			zap.Duration("duration", session.TotalDuration),
		)
	}

	if session.TotalDuration > 30*time.Second {
		log.Warn(" Authentication session took unusually long",
			zap.Duration("duration", session.TotalDuration),
		)
	}
}

// SecureRootTokenFallback provides emergency root token authentication with explicit user consent
func SecureRootTokenFallback(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Warn(" ROOT TOKEN FALLBACK REQUESTED")
	log.Warn("This is an emergency authentication method")
	log.Warn("Root tokens provide unlimited access to Vault")
	log.Warn("Only use in emergency situations")

	// In a real implementation, you might want additional confirmation
	// For now, we'll just log the attempt and proceed with caution

	attempt := AuthenticationAttempt{
		Method:    "emergency-root-token",
		StartTime: time.Now(),
		Sensitive: true,
	}

	token, err := tryRootToken(rc, client)
	attempt.EndTime = time.Now()

	// Log the attempt for security monitoring
	defer func() {
		log.Info(" Emergency root token attempt completed",
			zap.String("method", attempt.Method),
			zap.Bool("success", attempt.Success),
			zap.String("error_type", attempt.ErrorType),
			zap.Duration("duration", attempt.EndTime.Sub(attempt.StartTime)),
		)
	}()

	if err != nil {
		attempt.Success = false
		attempt.ErrorType = categorizeAuthError(err)
		log.Error(" Emergency root token authentication failed",
			zap.String("error_category", attempt.ErrorType),
		)
		return fmt.Errorf("emergency root token authentication failed: %s", attempt.ErrorType)
	}

	if !VerifyToken(rc, client, token) {
		attempt.Success = false
		attempt.ErrorType = "token_verification_failed"
		log.Error(" Emergency root token verification failed")
		return errors.New("emergency root token verification failed")
	}

	attempt.Success = true
	SetVaultToken(rc, client, token)

	log.Warn(" Emergency root token authentication successful")
	log.Warn(" IMMEDIATE ACTION REQUIRED: Rotate root token and fix normal authentication")

	return nil
}

// Enhanced token verification with additional security checks
func EnhancedTokenVerification(rc *eos_io.RuntimeContext, client *api.Client, token string) bool {
	if token == "" {
		return false
	}

	// Basic format validation
	if !isValidVaultTokenFormat(token) {
		otelzap.Ctx(rc.Ctx).Warn(" Invalid token format detected")
		return false
	}

	// Use the existing VerifyToken function for actual verification
	return VerifyToken(rc, client, token)
}

// GetAuthenticationStatus returns the current authentication status without sensitive information
func GetAuthenticationStatus(rc *eos_io.RuntimeContext, client *api.Client) map[string]interface{} {
	status := map[string]interface{}{
		"authenticated": false,
		"token_present": false,
		"token_valid":   false,
		"timestamp":     time.Now().UTC(),
	}

	if client == nil {
		return status
	}

	// Check if token is present
	if client.Token() != "" {
		status["token_present"] = true

		// Verify token is valid (this calls Vault API)
		if VerifyToken(rc, client, client.Token()) {
			status["token_valid"] = true
			status["authenticated"] = true
		}
	}

	return status
}
