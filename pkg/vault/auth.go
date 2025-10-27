package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func Authn(rc *eos_io.RuntimeContext) (*api.Client, error) {
	client, err := GetVaultClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Vault client unavailable", zap.Error(err))
		return nil, err
	}

	if err := OrchestrateVaultAuth(rc, client); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Vault authentication failed", zap.Error(err))
		return nil, err
	}

	ValidateAndCache(rc, client)
	SetVaultClient(rc, client)
	return client, nil
}

func OrchestrateVaultAuth(rc *eos_io.RuntimeContext, client *api.Client) error {
	// Use the new secure authentication orchestrator
	return SecureAuthenticationOrchestrator(rc, client)
}

// readAgentTokenWithRetry handles the race condition where the agent token file exists but is empty
// because the agent hasn't finished authentication yet. We retry with backoff up to 30 seconds.
// P0 FIX 7: Detect when Vault Agent has renewed token during retry (HashiCorp pattern)
func readAgentTokenWithRetry(rc *eos_io.RuntimeContext, path string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	const (
		maxAttempts = 15              // 15 attempts
		retryDelay  = 2 * time.Second // 2 seconds between attempts = 30 seconds total
	)

	log.Info("Waiting for Vault Agent to authenticate and write token file",
		zap.String("path", path),
		zap.Int("max_attempts", maxAttempts),
		zap.Duration("retry_delay", retryDelay),
		zap.Duration("max_wait_time", time.Duration(maxAttempts)*retryDelay))

	// P0 FIX 7: Record initial file mtime to detect token renewals
	// If token file is old, we want to know if Vault Agent updated it during retry
	initialMtime := time.Time{}
	if info, err := os.Stat(path); err == nil {
		initialMtime = info.ModTime()
		log.Debug("Initial token file modification time recorded",
			zap.Time("initial_mtime", initialMtime),
			zap.String("path", path))
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		log.Debug("Attempting to read agent token file",
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", maxAttempts),
			zap.String("path", path))

		// Try to read the token file
		token, err := SecureReadTokenFile(rc, path)

		// Check for file not found (agent not started yet)
		if err != nil && strings.Contains(err.Error(), "no such file or directory") {
			log.Debug("Agent token file not found yet, will retry",
				zap.Int("attempt", attempt),
				zap.Duration("retry_in", retryDelay))

			if attempt < maxAttempts {
				select {
				case <-time.After(retryDelay):
					continue
				case <-rc.Ctx.Done():
					return "", fmt.Errorf("context cancelled while waiting for agent token: %w", rc.Ctx.Err())
				}
			}
			continue
		}

		// Check for other errors (permission denied, etc.) - these are deterministic, don't retry
		if err != nil {
			log.Error("Agent token file read error (not retryable)",
				zap.String("path", path),
				zap.Error(err),
				zap.String("remediation", "Check file permissions and agent service status"))
			return "", fmt.Errorf("failed to read agent token file: %w", err)
		}

		// Check if token is empty (agent hasn't written yet)
		if token == "" {
			log.Debug("Agent token file is empty, agent still authenticating",
				zap.Int("attempt", attempt),
				zap.Duration("retry_in", retryDelay))

			if attempt < maxAttempts {
				select {
				case <-time.After(retryDelay):
					continue
				case <-rc.Ctx.Done():
					return "", fmt.Errorf("context cancelled while waiting for agent token: %w", rc.Ctx.Err())
				}
			}
			continue
		}

		// P0 FIX 7: Check if file was updated by Vault Agent during retry
		// This helps diagnose if we successfully waited for a token renewal
		if attempt > 1 && !initialMtime.IsZero() {
			if info, err := os.Stat(path); err == nil {
				currentMtime := info.ModTime()
				if currentMtime.After(initialMtime) {
					log.Info("Vault Agent renewed token during retry (file was updated)",
						zap.Int("attempt", attempt),
						zap.Time("initial_mtime", initialMtime),
						zap.Time("current_mtime", currentMtime),
						zap.Duration("renewal_detected_after", currentMtime.Sub(initialMtime)))
				}
			}
		}

		// Success! Token is present and non-empty
		log.Info("Agent token file read successfully",
			zap.String("path", path),
			zap.Int("attempt", attempt),
			zap.Duration("wait_time", time.Duration(attempt-1)*retryDelay))
		return token, nil
	}

	// All attempts exhausted
	log.Error("Agent token file still empty after all retry attempts",
		zap.String("path", path),
		zap.Int("total_attempts", maxAttempts),
		zap.Duration("total_wait_time", time.Duration(maxAttempts)*retryDelay),
		zap.String("remediation", "Check Vault Agent service status: systemctl status vault-agent-eos"))

	return "", fmt.Errorf("agent token file empty after %d attempts (%v): agent may have failed to authenticate",
		maxAttempts, time.Duration(maxAttempts)*retryDelay)
}

func readTokenFile(rc *eos_io.RuntimeContext, path string) func(*api.Client) (string, error) {
	return func(_ *api.Client) (string, error) {
		log := otelzap.Ctx(rc.Ctx)

		// SECURITY FIX P0-4: Add retry logic to handle agent startup race condition
		// The token file is created empty by prepareTokenSink(), then the agent writes to it
		// We need to wait for the agent to actually write the token before reading

		// For agent token files, implement retry with timeout
		isAgentToken := strings.Contains(path, "vault_agent_eos.token")

		if isAgentToken {
			log.Debug("Reading agent token file with retry logic (agent may still be starting)",
				zap.String("path", path))
			return readAgentTokenWithRetry(rc, path)
		}

		// For non-agent tokens, read immediately (no race condition)
		token, err := SecureReadTokenFile(rc, path)
		if err != nil {
			log.Warn(" Failed to securely read token file", zap.String("path", path), zap.Error(err))
			return "", fmt.Errorf("secure read token file %s: %w", path, err)
		}

		// Additional security: Don't log successful reads in production to avoid token leakage
		log.Debug(" Token file read successfully with security validation", zap.String("path", path))
		return token, nil
	}
}

// DEPRECATED: This function is replaced by tryAppRoleInteractive in auth_interactive.go
// Kept for backward compatibility with existing code that may still call it directly
// TODO: Remove after migrating all callers to use tryAppRoleInteractive
func tryAppRole(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	return coreAppRoleAuth(rc, client)
}

// DEPRECATED: This function is replaced by tryUserpassInteractive in auth_interactive.go
// The old prompt "Do you want to enable userpass auth?" was confusing in non-setup contexts
// New code should use tryUserpassInteractive with appropriate AuthContext
// TODO: Remove after migrating all callers to use tryUserpassInteractive
func tryUserpassWithPrompt(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	// Use runtime context by default (preserves old behavior but with better UX)
	return tryUserpassInteractive(rc, client, AuthContextRuntime)
}

// DEPRECATED: This function is replaced by coreUserpassAuth + promptAndAuthenticateUserpass
// Kept for backward compatibility
// TODO: Remove after migrating all callers
func tryUserpass(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	return promptAndAuthenticateUserpass(rc, client)
}

// tryRootToken loads root token from vault_init.json and validates it
// This wraps coreRootTokenAuth with disk I/O logic
// NOTE: This function includes prompting logic (LoadOrPromptInitResult) which may be interactive
func tryRootToken(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Loading root token from vault_init.json")

	// Load from disk (may prompt if file is missing/invalid)
	initRes, err := LoadOrPromptInitResult(rc)
	if err != nil {
		log.Warn("Failed to load or prompt init result", zap.Error(err))
		return "", fmt.Errorf("load or prompt init result: %w", err)
	}

	// Use core validation (no disk I/O, pure validation)
	token, err := coreRootTokenAuth(rc, client, initRes.RootToken)
	if err != nil {
		log.Warn("Root token validation failed", zap.Error(err))
		return "", fmt.Errorf("root token validation: %w", err)
	}

	log.Debug("Root token loaded and validated successfully")
	return token, nil
}

// authStateKey is a context key for storing authentication state
// This prevents global mutable state and enables testing
type authStateKey struct{}

// AuthState tracks authentication attempt state within a context
// Prevents infinite prompting loops without using global variables
type AuthState struct {
	PromptAttemptCount int
	LastPromptTime     time.Time
}

const maxPromptAttempts = 1 // Only allow ONE manual prompt per context

// getAuthState retrieves or initializes auth state from context
// This ensures state is isolated per request/command execution
func getAuthState(rc *eos_io.RuntimeContext) *AuthState {
	if state, ok := rc.Ctx.Value(authStateKey{}).(*AuthState); ok {
		return state
	}
	// Initialize on first access
	state := &AuthState{}
	rc.Ctx = context.WithValue(rc.Ctx, authStateKey{}, state)
	return state
}

func LoadOrPromptInitResult(rc *eos_io.RuntimeContext) (*api.InitResponse, error) {
	log := otelzap.Ctx(rc.Ctx)

	// CIRCUIT BREAKER P0: Prevent infinite prompt loops (context-based, not global)
	// This addresses the bug where each phase prompts independently
	authState := getAuthState(rc)

	if authState.PromptAttemptCount >= maxPromptAttempts {
		log.Error(" Circuit breaker activated: manual prompt limit exceeded",
			zap.Int("attempts", authState.PromptAttemptCount),
			zap.Int("max_attempts", maxPromptAttempts),
			zap.Time("last_attempt", authState.LastPromptTime))
		log.Error("This indicates vault_init.json is missing or invalid")
		log.Info("Recovery options:")
		log.Info("  1. Run: sudo eos read vault-init --status-only")
		log.Info("  2. Check if /var/lib/eos/secret/vault_init.json exists")
		log.Info("  3. Run: sudo eos create vault (will detect and offer recovery)")
		return nil, fmt.Errorf("authentication prompt limit exceeded (%d attempts): vault_init.json missing or invalid", authState.PromptAttemptCount)
	}

	// Try multiple paths for vault_init.json (new location + legacy fallback)
	initPaths := []string{
		"/run/eos/vault_init_output.json", // New location (tmpfs, faster, survives restarts via systemd)
		shared.VaultInitPath,               // Legacy: /var/lib/eos/secret/vault_init.json
	}

	var res api.InitResponse
	var lastErr error
	var foundPath string

	for _, path := range initPaths {
		if err := ReadFallbackJSON(rc, path, &res); err == nil {
			// Success! Found valid init data
			foundPath = path
			log.Debug("Loaded vault init data from disk",
				zap.String("path", path))
			break
		} else {
			lastErr = err
			log.Debug("Vault init data not found at path",
				zap.String("path", path),
				zap.Error(err))
		}
	}

	// All paths failed - need to prompt user
	if foundPath == "" {
		log.Warn("Fallback file missing from all locations, prompting user once only",
			zap.Error(lastErr),
			zap.Strings("paths_checked", initPaths),
			zap.Int("attempt_count", authState.PromptAttemptCount+1))

		// Increment attempt counter BEFORE prompting
		authState.PromptAttemptCount++
		authState.LastPromptTime = time.Now()

		return PromptForInitResult(rc)
	}

	// Verify the loaded init result
	if err := VerifyInitResult(rc, &res); err != nil {
		log.Warn("Loaded init result invalid, prompting user once only",
			zap.Error(err),
			zap.Int("attempt_count", authState.PromptAttemptCount+1))

		// Increment attempt counter BEFORE prompting
		authState.PromptAttemptCount++
		authState.LastPromptTime = time.Now()

		return PromptForInitResult(rc)
	}

	// Reset counter on successful load
	authState.PromptAttemptCount = 0
	return &res, nil
}

func VerifyInitResult(rc *eos_io.RuntimeContext, r *api.InitResponse) error {
	if r == nil {
		err := errors.New("init result is nil")
		otelzap.Ctx(rc.Ctx).Warn(" Invalid init result", zap.Error(err))
		return err
	}
	if len(r.KeysB64) < 3 {
		err := fmt.Errorf("expected at least 3 unseal keys, got %d", len(r.KeysB64))
		otelzap.Ctx(rc.Ctx).Warn(" Invalid init result", zap.Error(err))
		return err
	}
	if strings.TrimSpace(r.RootToken) == "" {
		err := errors.New("root token is missing or empty")
		otelzap.Ctx(rc.Ctx).Warn(" Invalid init result", zap.Error(err))
		return err
	}
	return nil
}

func VerifyRootToken(rc *eos_io.RuntimeContext, client *api.Client, token string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Verifying token with Vault",
		zap.String("vault_addr", client.Address()))

	client.SetToken(token)

	log.Info(" Making token lookup-self API call to Vault")
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		log.Error(" Token lookup-self API call failed",
			zap.Error(err),
			zap.String("vault_addr", client.Address()))
		return fmt.Errorf("token validation failed: %w", err)
	}
	if secret == nil {
		log.Error(" Token lookup returned nil secret")
		return fmt.Errorf("token validation failed: nil secret returned")
	}

	// Extract token metadata safely
	tokenType := "unknown"
	if typeVal, ok := secret.Data["type"]; ok && typeVal != nil {
		tokenType = typeVal.(string)
	}

	// P0 FIX 3: Check if token is renewable (HashiCorp recommended pattern)
	renewable := secret.Renewable
	if renewableData, ok := secret.Data["renewable"].(bool); ok {
		renewable = renewableData
	}

	if !renewable {
		log.Warn("Token is not renewable - will need re-authentication at expiry",
			zap.String("token_type", tokenType))
	}

	// P0 FIX 4: Check num_uses (use_limit) - HashiCorp pattern
	// If token has limited uses, it may be consumed after this operation
	numUses := int64(0)
	if numUsesData, ok := secret.Data["num_uses"]; ok && numUsesData != nil {
		switch v := numUsesData.(type) {
		case float64:
			numUses = int64(v)
		case int:
			numUses = int64(v)
		case int64:
			numUses = v
		}

		if numUses > 0 {
			log.Warn("Token has use_limit - may be consumed after use",
				zap.Int64("remaining_uses", numUses),
				zap.String("token_type", tokenType))
		}
	}

	// P0 FIX 5: Check TTL sufficiency (HashiCorp recommendation)
	// Ensure token has enough TTL remaining for the operation
	ttl := int64(0)
	if ttlData, ok := secret.Data["ttl"]; ok && ttlData != nil {
		switch v := ttlData.(type) {
		case float64:
			ttl = int64(v)
		case int:
			ttl = int64(v)
		case int64:
			ttl = v
		}
	}

	const minRequiredTTL = 60 // 1 minute minimum (HashiCorp pattern)

	if ttl > 0 && ttl < minRequiredTTL {
		log.Error("Token TTL too low - insufficient time for operation",
			zap.Int64("ttl_seconds", ttl),
			zap.Int64("min_required_ttl", minRequiredTTL),
			zap.String("remediation", "Wait for Vault Agent to renew token or re-authenticate"))

		return fmt.Errorf("token TTL too low (%ds remaining, need at least %ds) - wait for renewal or re-authenticate",
			ttl, minRequiredTTL)
	}

	log.Info(" Token validated successfully",
		zap.String("token_type", tokenType),
		zap.Any("policies", secret.Data["policies"]),
		zap.Any("path", secret.Data["path"]),
		zap.Any("accessor", secret.Data["accessor"]),
		zap.Bool("renewable", renewable),
		zap.Int64("ttl_seconds", ttl),
		zap.Int64("num_uses", numUses))
	return nil
}

func VerifyToken(rc *eos_io.RuntimeContext, client *api.Client, token string) bool {
	err := VerifyRootToken(rc, client, token)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn(" Token verification failed", zap.Error(err))
		return false
	}
	otelzap.Ctx(rc.Ctx).Debug(" Token verified successfully")
	return true
}

type AppRoleLoginInput struct {
	RoleID      string
	SecretID    string
	MountPath   string
	UseWrapping bool // If true, use response-wrapped secret ID token
}

func buildSecretID(input AppRoleLoginInput) *approle.SecretID {
	return &approle.SecretID{
		FromString: input.SecretID,
	}
}

func buildAppRoleAuth(input AppRoleLoginInput) (*approle.AppRoleAuth, error) {
	opts := []approle.LoginOption{}

	if input.MountPath != "" {
		opts = append(opts, approle.WithMountPath(input.MountPath))
	}
	if input.UseWrapping {
		opts = append(opts, approle.WithWrappingToken())
	}

	auth, err := approle.NewAppRoleAuth(input.RoleID, buildSecretID(input), opts...)
	if err != nil {
		return nil, cerr.Wrap(err, "failed to create AppRoleAuth")
	}
	return auth, nil
}

func LoginWithAppRole(rc *eos_io.RuntimeContext, client *api.Client, input AppRoleLoginInput) (*api.Secret, error) {
	log := otelzap.Ctx(rc.Ctx)

	auth, err := buildAppRoleAuth(input)
	if err != nil {
		log.Error(" Failed to build AppRoleAuth", zap.Error(err))
		return nil, err
	}

	secret, err := client.Auth().Login(rc.Ctx, auth)
	if err != nil {
		log.Error(" AppRole login failed", zap.Error(err))
		return nil, cerr.Wrap(err, "Vault AppRole login failed")
	}

	if secret == nil || secret.Auth == nil {
		return nil, cerr.New("no secret or auth info returned by Vault")
	}

	log.Info(" Vault AppRole login successful")
	return secret, nil
}
