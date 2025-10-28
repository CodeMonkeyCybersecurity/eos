// pkg/hecate/bootstrap_credentials.go
// Manages Authentik bootstrap credentials with Consul KV storage

package hecate

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// Consul KV paths for Authentik bootstrap credentials
	ConsulAuthentikBootstrapEmail    = ConsulHecatePrefix + "secrets/authentik/bootstrap_email"
	ConsulAuthentikBootstrapPassword = ConsulHecatePrefix + "secrets/authentik/bootstrap_password"
	ConsulAuthentikBootstrapToken    = ConsulHecatePrefix + "secrets/authentik/bootstrap_token"

	// NOTE: AUTHENTIK_API_TOKEN is NOT stored in Consul for now
	// RATIONALE: API tokens are created manually via Authentik UI (upstream limitation)
	// STORAGE: Stored in /opt/hecate/.env (one-time manual setup)
	// TODO (ROADMAP - 6-12 months): Migrate to Vault when we add full Vault integration
	//
	// When we do migrate to Vault, the path should be:
	// ConsulAuthentikAPIToken = ConsulHecatePrefix + "secrets/authentik/api_token"
)

// AuthentikBootstrapCredentials holds the bootstrap credentials for Authentik first-time setup
type AuthentikBootstrapCredentials struct {
	Email    string
	Password string
	Token    string
}

// PromptAndGenerateBootstrapCredentials prompts user for admin email and auto-generates password/token
func PromptAndGenerateBootstrapCredentials(rc *eos_io.RuntimeContext) (*AuthentikBootstrapCredentials, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prompt for admin email
	logger.Info("")
	logger.Info("terminal prompt: Authentik Bootstrap Configuration")
	logger.Info("terminal prompt: Enter admin email for Authentik:")

	email, err := eos_io.ReadInput(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read admin email: %w", err)
	}

	if email == "" {
		return nil, fmt.Errorf("admin email is required")
	}

	logger.Info("Using admin email", zap.String("email", email))

	// INTERVENE - Auto-generate secure alphanumeric-only credentials
	logger.Info("Generating secure bootstrap credentials (alphanumeric-only)...")

	// Use alphanumeric-only for maximum compatibility (no shell/URL escaping issues)
	password, err := crypto.GenerateURLSafePassword(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap password: %w", err)
	}

	token, err := crypto.GenerateToken(64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap token: %w", err)
	}

	credentials := &AuthentikBootstrapCredentials{
		Email:    email,
		Password: password,
		Token:    token,
	}

	// EVALUATE - Display generated credentials to user
	logger.Info("")
	logger.Info("terminal prompt: ========================================")
	logger.Info("terminal prompt: Authentik Bootstrap Credentials")
	logger.Info("terminal prompt: ========================================")
	logger.Info("terminal prompt: Admin Email:    " + email)
	logger.Info("terminal prompt: Admin Password: " + password)
	logger.Info("terminal prompt: Bootstrap Token: " + token)
	logger.Info("terminal prompt: ========================================")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: IMPORTANT: Save these credentials securely!")
	logger.Info("terminal prompt: The password will be stored in Consul/Vault.")
	logger.Info("terminal prompt: You will need these to log in to Authentik.")
	logger.Info("terminal prompt: ")

	return credentials, nil
}

// StoreBootstrapCredentials stores bootstrap credentials in Consul KV (preferred) or returns for .env fallback
func StoreBootstrapCredentials(rc *eos_io.RuntimeContext, creds *AuthentikBootstrapCredentials) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Try to use Consul
	consulMgr, err := NewConsulConfigManager(rc)
	if err != nil {
		logger.Warn("Consul not available, credentials will be stored in .env file",
			zap.Error(err))
		return nil // Not an error - caller will handle .env fallback
	}

	// INTERVENE - Store in Consul KV
	logger.Info("Storing bootstrap credentials in Consul KV")

	if err := consulMgr.setKey(ConsulAuthentikBootstrapEmail, creds.Email); err != nil {
		return fmt.Errorf("failed to store bootstrap email in Consul: %w", err)
	}

	if err := consulMgr.setKey(ConsulAuthentikBootstrapPassword, creds.Password); err != nil {
		return fmt.Errorf("failed to store bootstrap password in Consul: %w", err)
	}

	if err := consulMgr.setKey(ConsulAuthentikBootstrapToken, creds.Token); err != nil {
		return fmt.Errorf("failed to store bootstrap token in Consul: %w", err)
	}

	// EVALUATE - Verify storage
	logger.Info("Bootstrap credentials stored successfully in Consul",
		zap.String("email", creds.Email))

	return nil
}

// LoadBootstrapCredentials retrieves bootstrap credentials from Consul KV
func LoadBootstrapCredentials(rc *eos_io.RuntimeContext) (*AuthentikBootstrapCredentials, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Connect to Consul
	consulMgr, err := NewConsulConfigManager(rc)
	if err != nil {
		return nil, fmt.Errorf("Consul not available: %w", err)
	}

	logger.Info("Loading bootstrap credentials from Consul")

	// INTERVENE - Retrieve credentials
	email, err := consulMgr.getKey(ConsulAuthentikBootstrapEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to load bootstrap email: %w", err)
	}

	password, err := consulMgr.getKey(ConsulAuthentikBootstrapPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load bootstrap password: %w", err)
	}

	token, err := consulMgr.getKey(ConsulAuthentikBootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("failed to load bootstrap token: %w", err)
	}

	credentials := &AuthentikBootstrapCredentials{
		Email:    email,
		Password: password,
		Token:    token,
	}

	// EVALUATE - Verify loaded
	logger.Info("Bootstrap credentials loaded from Consul",
		zap.String("email", email))

	return credentials, nil
}
