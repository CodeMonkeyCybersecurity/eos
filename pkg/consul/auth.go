// pkg/consul/auth.go

package consul

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TokenSource represents where an ACL token was found
type TokenSource string

const (
	TokenSourceFlag        TokenSource = "flag"
	TokenSourceEnvironment TokenSource = "environment"
	TokenSourceVault       TokenSource = "vault"
	TokenSourceConsulKV    TokenSource = "consul-kv"
	TokenSourceFile        TokenSource = "file"
	TokenSourceNone        TokenSource = "none"
)

// TokenResult contains the token and metadata about where it was found
type TokenResult struct {
	Token  string
	Source TokenSource
	Path   string // File path or KV path where token was found
}

// GetConsulACLToken retrieves Consul ACL token from multiple sources with priority
//
// TOKEN ARCHITECTURE:
// Consul tokens must be created via Consul's ACL API (consul.ACL().Bootstrap() or consul.ACL().TokenCreate()).
// We NEVER generate random UUIDs locally and call them Consul tokens.
//
// Bootstrap token path: secret/consul/bootstrap-token (created by 'eos update consul --bootstrap-token')
//
// Priority order:
//  1. Flag (--acl-token) - Explicit user override
//  2. Environment (CONSUL_HTTP_TOKEN) - Session-specific
//  3. Vault (secret/consul/bootstrap-token) - Secure storage (if Vault available)
//  4. Consul KV (eos/consul/acl_token) - Bootstrap fallback (stored during consul creation)
//  5. File (/etc/consul.d/acl-token) - Legacy/backward compatibility
//
// If no token found, user must run: eos update consul --bootstrap-token
func GetConsulACLToken(rc *eos_io.RuntimeContext, flagToken string) (*TokenResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Starting ACL token retrieval", zap.String("priority_order", "flag > env > vault > consul-kv > file"))

	// 1. Check flag (highest priority - explicit user override)
	if flagToken != "" {
		logger.Info("Using ACL token from --acl-token flag")
		return &TokenResult{
			Token:  flagToken,
			Source: TokenSourceFlag,
			Path:   "command flag",
		}, nil
	}

	// 2. Check environment variable (session-specific)
	if token := os.Getenv("CONSUL_HTTP_TOKEN"); token != "" {
		logger.Info("Using ACL token from CONSUL_HTTP_TOKEN environment variable")
		return &TokenResult{
			Token:  token,
			Source: TokenSourceEnvironment,
			Path:   "CONSUL_HTTP_TOKEN",
		}, nil
	}

	// 3. Try Vault (if available) - Secure storage
	logger.Debug("Checking Vault for ACL token")
	if token, path, err := getTokenFromVault(rc); err == nil && token != "" {
		logger.Info("Using ACL token from Vault", zap.String("path", path))
		return &TokenResult{
			Token:  token,
			Source: TokenSourceVault,
			Path:   path,
		}, nil
	} else if err != nil {
		logger.Debug("Vault token retrieval failed (Vault may not be installed yet)",
			zap.Error(err),
			zap.String("note", "This is expected if Vault hasn't been installed"))
	}

	// 4. Try Consul KV (bootstrap storage) - Stored during 'eos create consul'
	logger.Debug("Checking Consul KV for ACL token")
	if token, path, err := getTokenFromConsulKV(rc); err == nil && token != "" {
		logger.Info("Using ACL token from Consul KV", zap.String("path", path))
		return &TokenResult{
			Token:  token,
			Source: TokenSourceConsulKV,
			Path:   path,
		}, nil
	} else if err != nil {
		logger.Debug("Consul KV token retrieval failed",
			zap.Error(err),
			zap.String("note", "Token may not have been stored during bootstrap"))
	}

	// 5. Check file (legacy/backward compatibility)
	logger.Debug("Checking file for ACL token")
	if token, path, err := getTokenFromFile(rc); err == nil && token != "" {
		logger.Info("Using ACL token from file", zap.String("path", path))
		return &TokenResult{
			Token:  token,
			Source: TokenSourceFile,
			Path:   path,
		}, nil
	}

	// None found - return helpful error with all attempted sources
	logger.Error("No ACL token found in any source",
		zap.Strings("sources_checked", []string{"flag", "CONSUL_HTTP_TOKEN", "vault", "consul-kv", "file"}))

	return nil, eos_err.NewUserError(
		"ACL token not found\n" +
			"Consul has ACLs enabled but no token was provided.\n\n" +
			"Provide token via:\n" +
			"  1. Environment: export CONSUL_HTTP_TOKEN=<token>\n" +
			"  2. File: Save token to /etc/consul.d/acl-token\n" +
			"  3. Flag: --acl-token=<token>\n\n" +
			"Get token: consul acl token list")
}

// getTokenFromVault retrieves Consul ACL token from Vault
//
// TOKEN LIFECYCLE (CORRECT PATTERN):
//  1. User runs: eos update consul --bootstrap-token
//  2. Eos calls Consul API: consul.ACL().Bootstrap()
//  3. Consul creates real bootstrap token with global-management policy
//  4. Eos stores token in Vault at: secret/consul/bootstrap-token
//  5. Future operations retrieve token from Vault
//
// This retrieves EXISTING tokens created by Consul's ACL system.
// We NEVER generate random UUIDs and call them "Consul tokens".
//
// Path: secret/consul/bootstrap-token (uses consul.VaultConsulBootstrapTokenPath constant)
//
// If token not found, returns error. User must run:
//
//	eos update consul --bootstrap-token
func getTokenFromVault(rc *eos_io.RuntimeContext) (string, string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Discover environment to get Vault address
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return "", "", fmt.Errorf("failed to discover environment: %w", err)
	}

	// Check if Vault is actually available
	if envConfig.VaultAddr == "" {
		logger.Debug("Vault not configured in environment")
		return "", "", fmt.Errorf("vault not available")
	}

	// TODO: This function uses the OLD deprecated Vault path (secret/consul/bootstrap-token)
	// instead of the new environment-aware path (secret/services/{env}/consul/bootstrap-token).
	// Cannot be updated due to circular import: pkg/consul cannot import pkg/consul/environment.
	// This is acceptable because:
	// 1. This is a fallback mechanism in the auth cascade
	// 2. Failures here gracefully fall through to other auth methods
	// 3. Primary auth flows (eos update consul, eos read consul-token) use new paths
	// FUTURE: Consider refactoring to eliminate circular dependency

	// Create Vault client (use centralized client creation)
	config := vaultapi.DefaultConfig()
	config.Address = envConfig.VaultAddr

	// Handle self-signed certificates (VAULT_SKIP_VERIFY)
	tlsConfig := &vaultapi.TLSConfig{
		Insecure: true,
	}
	_ = config.ConfigureTLS(tlsConfig)

	vaultClient, err := vaultapi.NewClient(config)
	if err != nil {
		return "", "", fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Get token from Vault agent token file
	agentTokenPath := "/run/eos/vault_agent_eos.token"
	tokenData, err := os.ReadFile(agentTokenPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read Vault agent token: %w", err)
	}
	vaultClient.SetToken(strings.TrimSpace(string(tokenData)))

	// Read bootstrap token from Vault (uses constant from consul package)
	// Path: consul/bootstrap-token (KVv2 SDK adds secret/data/ prefix automatically)
	secret, err := vaultClient.KVv2("secret").Get(rc.Ctx, VaultConsulBootstrapTokenPath)
	if err != nil {
		logger.Debug("Bootstrap token not found in Vault",
			zap.String("path", VaultConsulBootstrapTokenPath),
			zap.Error(err))
		return "", "", fmt.Errorf("bootstrap token not found in Vault at %s: %w", VaultConsulBootstrapTokenPath, err)
	}

	if secret == nil || secret.Data == nil {
		return "", "", fmt.Errorf("bootstrap token secret is empty at %s", VaultConsulBootstrapTokenPath)
	}

	// Extract token field
	tokenRaw, ok := secret.Data["token"]
	if !ok {
		return "", "", fmt.Errorf("'token' field not found in Vault secret at %s", VaultConsulBootstrapTokenPath)
	}

	token, ok := tokenRaw.(string)
	if !ok {
		return "", "", fmt.Errorf("'token' field is not a string at %s", VaultConsulBootstrapTokenPath)
	}

	if token == "" {
		return "", "", fmt.Errorf("bootstrap token is empty at %s", VaultConsulBootstrapTokenPath)
	}

	// Return full path for logging (includes secret/data/ prefix)
	fullPath := GetVaultConsulBootstrapTokenFullPath()
	logger.Debug("Retrieved Consul ACL bootstrap token from Vault",
		zap.String("path", fullPath))

	return token, fullPath, nil
}

// getTokenFromConsulKV retrieves token from Consul's own KV store
// This is used during bootstrap when Vault isn't available yet
// Uses anonymous access to read from a well-known path
func getTokenFromConsulKV(rc *eos_io.RuntimeContext) (string, string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create Consul client with default config (no token - anonymous access)
	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err != nil {
		return "", "", fmt.Errorf("failed to create consul client: %w", err)
	}

	// Path in Consul KV: eos/consul/acl_token
	// This should be readable by anonymous token if ACL policy allows
	kvPath := "eos/consul/acl_token"

	logger.Debug("Attempting to read ACL token from Consul KV",
		zap.String("path", kvPath),
		zap.String("note", "Using anonymous access - may fail if ACLs restrict read"))

	pair, _, err := client.KV().Get(kvPath, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to read from consul kv: %w", err)
	}

	if pair == nil || len(pair.Value) == 0 {
		return "", "", fmt.Errorf("key not found or empty")
	}

	token := strings.TrimSpace(string(pair.Value))
	if token == "" {
		return "", "", fmt.Errorf("token is empty")
	}

	return token, kvPath, nil
}

// getTokenFromFile retrieves token from filesystem
func getTokenFromFile(_ *eos_io.RuntimeContext) (string, string, error) {
	tokenPath := "/etc/consul.d/acl-token"

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", "", fmt.Errorf("token file is empty")
	}

	return token, tokenPath, nil
}

// ConfigureConsulClient creates a Consul API client with proper token authentication
// Automatically retrieves token from available sources
func ConfigureConsulClient(rc *eos_io.RuntimeContext, flagToken string) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get token from prioritized sources
	tokenResult, err := GetConsulACLToken(rc, flagToken)
	if err != nil {
		// Check if ACLs are actually enabled
		// Try to create client without token first
		config := api.DefaultConfig()
		testClient, clientErr := api.NewClient(config)
		if clientErr == nil {
			// Try a simple operation to see if ACLs are required
			_, testErr := testClient.Agent().Self()
			if testErr == nil {
				// No ACLs required - anonymous access works
				logger.Info("Consul ACLs not enabled - using anonymous access")
				return testClient, nil
			}
		}

		// ACLs are enabled but no token found
		return nil, err
	}

	// Create Consul client with token
	config := api.DefaultConfig()
	config.Token = tokenResult.Token

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	logger.Info("Consul client configured with ACL token",
		zap.String("source", string(tokenResult.Source)),
		zap.String("path", tokenResult.Path))

	// Verify token works
	_, err = client.Agent().Self()
	if err != nil {
		return nil, fmt.Errorf("ACL token authentication failed: %w\n"+
			"Token source: %s (%s)\n"+
			"Verify token is valid: consul acl token read -id <token>",
			err, tokenResult.Source, tokenResult.Path)
	}

	logger.Debug("ACL token verified successfully")

	return client, nil
}

// StoreTokenInConsulKV stores the ACL token in Consul's KV store for bootstrap
// This is called during 'eos create consul' when Vault isn't available yet
// The token is stored with a policy that allows anonymous read access
func StoreTokenInConsulKV(rc *eos_io.RuntimeContext, token string, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	kvPath := "eos/consul/acl_token"

	logger.Info("Storing ACL token in Consul KV for bootstrap",
		zap.String("path", kvPath),
		zap.String("note", "Token will be accessible for other nodes to join cluster"))

	// Store token in KV
	pair := &api.KVPair{
		Key:   kvPath,
		Value: []byte(token),
	}

	_, err := client.KV().Put(pair, nil)
	if err != nil {
		return fmt.Errorf("failed to store token in consul kv: %w", err)
	}

	logger.Info("ACL token stored successfully in Consul KV",
		zap.String("path", kvPath),
		zap.String("retrieval", "Other nodes can retrieve with 'eos sync consul'"))

	return nil
}

// MigrateTokenToVault moves the ACL token from Consul KV to Vault
// This is called during 'eos create vault' to migrate bootstrap tokens to secure storage
func MigrateTokenToVault(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Attempting to migrate Consul ACL token from Consul KV to Vault")

	// Get token from Consul KV
	_, kvPath, err := getTokenFromConsulKV(rc)
	if err != nil {
		logger.Debug("No token found in Consul KV to migrate", zap.Error(err))
		return nil // Not an error - token might not exist or already migrated
	}

	logger.Info("Found ACL token in Consul KV", zap.String("path", kvPath))

	// Store in Vault - Note: SecretManager doesn't expose a direct Store method
	// The token should be manually stored in Vault after installation
	// This function documents the migration path for future automation

	logger.Warn("Consul ACL token found in Consul KV - should be migrated to Vault",
		zap.String("current_location", kvPath+" (Consul KV)"),
		zap.String("target_location", "secret/consul/acl_management_token (Vault)"),
		zap.String("manual_command", "vault kv put secret/consul acl_management_token=<token-from-consul-kv>"),
		zap.String("note", "Token will continue to work from Consul KV until migrated"))

	// Optionally: Remove from Consul KV after successful migration
	// (Commented out for safety - keeps backward compatibility)
	// config := api.DefaultConfig()
	// config.Token = token
	// client, _ := api.NewClient(config)
	// client.KV().Delete(kvPath, nil)
	// logger.Info("Removed ACL token from Consul KV after migration")

	return nil
}

// GetAuthenticatedConsulClientForDiagnostics creates a Consul client with ACL token for diagnostic operations
//
// TOKEN ARCHITECTURE (CORRECT PATTERN):
// Consul tokens are created via Consul's ACL API (consul.ACL().Bootstrap()), NOT by generating random UUIDs.
// The bootstrap token is stored in Vault at: secret/consul/bootstrap-token
//
// This function provides the comprehensive authentication strategy for all Consul interactions:
//
// Authentication Sources (priority order):
//  1. Flag (--acl-token) - Explicit user override
//  2. Environment (CONSUL_HTTP_TOKEN) - Session-specific
//  3. Vault (secret/consul/bootstrap-token) - Secure storage from bootstrap (RECOMMENDED)
//  4. Consul KV (eos/consul/acl_token) - Bootstrap fallback
//  5. File (/etc/consul.d/acl-token) - Legacy compatibility
//
// Error Handling Strategy:
//   - If ACLs NOT enabled → Returns anonymous client (no error)
//   - If ACLs enabled + token found → Returns authenticated client
//   - If ACLs enabled + no token → Returns user-friendly error with remediation
//   - If Vault unavailable → Gracefully falls back to other sources
//
// User-Friendly Remediation:
//   - Detects if token missing from Vault
//   - Guides user to run: eos update consul --bootstrap-token
//   - Explains how to retrieve token from Consul if already bootstrapped
//   - Distinguishes Vault auth failures from missing tokens
//
// Example:
//
//	client, err := consul.GetAuthenticatedConsulClientForDiagnostics(rc, "")
//	if err != nil {
//	    return fmt.Errorf("failed to create Consul client: %w", err)
//	}
//	// Use client for diagnostic operations
//	members, err := client.Agent().Members(false)
func GetAuthenticatedConsulClientForDiagnostics(rc *eos_io.RuntimeContext, flagToken string) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating authenticated Consul client for diagnostics")

	// Use existing ConfigureConsulClient which handles:
	// - Token discovery from all sources (flag > env > vault > consul-kv > file)
	// - ACL enablement detection (tries anonymous if ACLs not enabled)
	// - Token verification
	client, err := ConfigureConsulClient(rc, flagToken)
	if err != nil {
		// Check if error is about missing token
		if strings.Contains(err.Error(), "ACL token not found") {
			// ACLs are enabled but no token found - provide helpful guidance
			logger.Error("Consul ACLs enabled but no token available",
				zap.String("remediation", "Run: eos update consul --bootstrap-token"))

			// NewUserError accepts format strings like fmt.Sprintf
			return nil, eos_err.NewUserError(
				"Consul ACL token not found\n\n"+
					"Consul has ACLs enabled, but no authentication token was found.\n\n"+
					"OPTION 1: Bootstrap ACLs and store token in Vault (RECOMMENDED)\n"+
					"  eos update consul --bootstrap-token\n\n"+
					"This will:\n"+
					"  - Reset Consul ACL bootstrap (safe operation)\n"+
					"  - Generate new bootstrap token\n"+
					"  - Store token securely in Vault at %s\n"+
					"  - Future commands will automatically retrieve from Vault\n\n"+
					"OPTION 2: If ACLs already bootstrapped, retrieve existing token\n"+
					"  1. Get bootstrap token from your Consul setup documentation\n"+
					"  2. Store in Vault manually:\n"+
					"     vault kv put %s token=<your-token>\n"+
					"  3. OR set environment variable:\n"+
					"     export CONSUL_HTTP_TOKEN=<your-token>\n\n"+
					"OPTION 3: Disable ACLs temporarily (NOT RECOMMENDED for production)\n"+
					"  - Edit /etc/consul.d/consul.hcl\n"+
					"  - Set acl.enabled = false\n"+
					"  - Restart Consul: systemctl restart consul\n\n"+
					"Original error: %v",
				GetVaultConsulBootstrapTokenFullPath(),
				GetVaultConsulBootstrapTokenFullPath(),
				err)
		}

		// Some other authentication error (Vault sealed, network issue, etc.)
		logger.Error("Failed to create authenticated Consul client",
			zap.Error(err))

		return nil, fmt.Errorf("failed to create Consul client: %w\n\n"+
			"Possible causes:\n"+
			"  - Vault is sealed or unavailable (check: vault status)\n"+
			"  - Consul is not running (check: systemctl status consul)\n"+
			"  - Network connectivity issues\n"+
			"  - Invalid token stored in Vault or environment\n\n"+
			"Debug steps:\n"+
			"  1. Check Consul status: consul members\n"+
			"  2. Check Vault status: vault status\n"+
			"  3. Check if token exists: vault kv get secret/consul/bootstrap-token\n"+
			"  4. Try manual authentication: export CONSUL_HTTP_TOKEN=<token> && consul members",
			err)
	}

	logger.Debug("Successfully created authenticated Consul client")
	return client, nil
}
