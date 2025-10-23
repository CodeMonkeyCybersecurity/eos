package vault

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
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

func tryAppRole(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	roleID, secretID, err := readAppRoleCredsFromDisk(rc, client)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn(" Failed to read AppRole credentials", zap.Error(err))
		return "", fmt.Errorf("read AppRole creds: %w", err)
	}
	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id": roleID, "secret_id": secretID,
	})
	if err != nil || secret == nil || secret.Auth == nil {
		otelzap.Ctx(rc.Ctx).Warn(" AppRole login failed", zap.Error(err))
		return "", fmt.Errorf("approle login failed") // Don't leak the underlying error
	}
	otelzap.Ctx(rc.Ctx).Debug(" AppRole login successful")
	return secret.Auth.ClientToken, nil
}

func tryUserpassWithPrompt(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	if !interaction.PromptYesNo(rc.Ctx, "Do you want to enable userpass auth?", false) {
		otelzap.Ctx(rc.Ctx).Info(" Skipping userpass (user chose 'no')")
		return "", errors.New("userpass skipped by user")
	}
	return tryUserpass(rc, client)
}

func tryUserpass(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	usernames, err := interaction.PromptSecrets(rc.Ctx, "Username", 1)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn(" Failed to prompt username", zap.Error(err))
		return "", fmt.Errorf("prompt username: %w", err)
	}
	passwords, err := interaction.PromptSecrets(rc.Ctx, "Password", 1)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn(" Failed to prompt password", zap.Error(err))
		return "", fmt.Errorf("prompt password: %w", err)
	}
	username, password := usernames[0], passwords[0]
	secret, err := client.Logical().Write(fmt.Sprintf("auth/userpass/login/%s", username),
		map[string]interface{}{"password": password})
	if err != nil || secret == nil || secret.Auth == nil {
		otelzap.Ctx(rc.Ctx).Warn(" Userpass login failed", zap.String("username", username), zap.Error(err))
		return "", fmt.Errorf("userpass login failed: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Debug(" Userpass login successful", zap.String("username", username))
	return secret.Auth.ClientToken, nil
}

func tryRootToken(rc *eos_io.RuntimeContext, _ *api.Client) (string, error) {
	initRes, err := LoadOrPromptInitResult(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn(" Failed to load or prompt init result", zap.Error(err))
		return "", fmt.Errorf("load or prompt init result: %w", err)
	}
	if strings.TrimSpace(initRes.RootToken) == "" {
		errMsg := "root token is missing in init result"
		otelzap.Ctx(rc.Ctx).Warn(errMsg)
		return "", errors.New(errMsg)
	}
	otelzap.Ctx(rc.Ctx).Debug(" Root token loaded successfully")
	return initRes.RootToken, nil
}

// Global circuit breaker to prevent infinite prompting loops
var (
	promptAttemptCount    = 0
	maxPromptAttempts     = 1 // Only allow ONE manual prompt per process
	lastPromptAttemptTime time.Time
)

func LoadOrPromptInitResult(rc *eos_io.RuntimeContext) (*api.InitResponse, error) {
	log := otelzap.Ctx(rc.Ctx)

	// CIRCUIT BREAKER P0: Prevent infinite prompt loops
	// This addresses the bug where each phase prompts independently
	if promptAttemptCount >= maxPromptAttempts {
		log.Error(" Circuit breaker activated: manual prompt limit exceeded",
			zap.Int("attempts", promptAttemptCount),
			zap.Int("max_attempts", maxPromptAttempts),
			zap.Time("last_attempt", lastPromptAttemptTime))
		log.Error("This indicates vault_init.json is missing or invalid")
		log.Info("Recovery options:")
		log.Info("  1. Run: sudo eos read vault-init --status-only")
		log.Info("  2. Check if /var/lib/eos/secret/vault_init.json exists")
		log.Info("  3. Run: sudo eos create vault (will detect and offer recovery)")
		return nil, fmt.Errorf("authentication prompt limit exceeded (%d attempts): vault_init.json missing or invalid", promptAttemptCount)
	}

	var res api.InitResponse
	if err := ReadFallbackJSON(rc, shared.VaultInitPath, &res); err != nil {
		log.Warn("Fallback file missing, prompting user once only",
			zap.Error(err),
			zap.Int("attempt_count", promptAttemptCount+1))

		// Increment attempt counter BEFORE prompting
		promptAttemptCount++
		lastPromptAttemptTime = time.Now()

		return PromptForInitResult(rc)
	}
	if err := VerifyInitResult(rc, &res); err != nil {
		log.Warn("Loaded init result invalid, prompting user once only",
			zap.Error(err),
			zap.Int("attempt_count", promptAttemptCount+1))

		// Increment attempt counter BEFORE prompting
		promptAttemptCount++
		lastPromptAttemptTime = time.Now()

		return PromptForInitResult(rc)
	}

	// Reset counter on successful load
	promptAttemptCount = 0
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

	log.Info(" Token validated successfully",
		zap.String("token_type", tokenType),
		zap.Any("policies", secret.Data["policies"]),
		zap.Any("path", secret.Data["path"]),
		zap.Any("accessor", secret.Data["accessor"]),
		zap.Bool("renewable", secret.Renewable),
		zap.Any("ttl", secret.Data["ttl"]))
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
