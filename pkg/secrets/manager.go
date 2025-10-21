// Package secrets provides automatic secret management across Vault and file backends
package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecretManager handles automatic secret management
type SecretManager struct {
	rc      *eos_io.RuntimeContext
	backend SecretBackend
	env     *environment.EnvironmentConfig
}

// SecretBackend defines the interface for secret storage backends
type SecretBackend interface {
	Store(path string, secret map[string]interface{}) error
	Retrieve(path string) (map[string]interface{}, error)
	Generate(path string, secretType SecretType) (string, error)
	Exists(path string) bool
}

// SecretType defines the type of secret to generate
type SecretType string

const (
	SecretTypePassword SecretType = "password"
	SecretTypeAPIKey   SecretType = "api_key"
	SecretTypeToken    SecretType = "token"
	SecretTypeJWT      SecretType = "jwt"
)

// ServiceSecrets represents secrets for a service
type ServiceSecrets struct {
	ServiceName string                 `json:"service_name"`
	Environment string                 `json:"environment"`
	Secrets     map[string]interface{} `json:"secrets"`
	CreatedAt   string                 `json:"created_at"`
	Backend     string                 `json:"backend"`
}

// NewSecretManager creates a new secret manager with automatic backend detection
func NewSecretManager(rc *eos_io.RuntimeContext, envConfig *environment.EnvironmentConfig) (*SecretManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var backend SecretBackend
	var err error

	// SECURITY: Choose backend based on environment configuration
	// Vault is the secure default for production
	// Only fall back to file backend in development/testing
	backendType := os.Getenv("EOS_SECRET_BACKEND")
	if backendType == "" {
		backendType = "vault" // Secure default
	}

	switch backendType {
	case "vault":
		backend, err = NewVaultBackend(rc, envConfig.VaultAddr)
		if err != nil {
			logger.Error("Vault backend initialization failed", zap.Error(err))
			// SECURITY: Fail-closed in production, only allow fallback in dev/test
			if os.Getenv("GO_ENV") == "development" || os.Getenv("GO_ENV") == "test" {
				logger.Warn("Development mode: falling back to file backend (INSECURE)")
				backend = NewFileBackend()
			} else {
				return nil, fmt.Errorf("vault backend required in production but initialization failed: %w", err)
			}
		}
	case "file":
		// SECURITY: Only allow file backend in development/testing
		if os.Getenv("GO_ENV") != "development" && os.Getenv("GO_ENV") != "test" {
			return nil, fmt.Errorf("file backend not allowed in production - use vault")
		}
		logger.Warn("Using insecure file backend (development only)")
		backend = NewFileBackend()
	default:
		return nil, fmt.Errorf("unsupported secret backend: %s (supported: vault, file)", backendType)
	}

	logger.Info("Secret manager initialized",
		zap.String("backend", fmt.Sprintf("%T", backend)))

	return &SecretManager{
		rc:      rc,
		backend: backend,
		env:     envConfig,
	}, nil
}

// GetOrGenerateServiceSecrets gets existing secrets or generates new ones for a service
func (sm *SecretManager) GetOrGenerateServiceSecrets(serviceName string, requiredSecrets map[string]SecretType) (*ServiceSecrets, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	secretPath := fmt.Sprintf("services/%s/%s", sm.env.Environment, serviceName)

	logger.Info("Getting or generating service secrets",
		zap.String("service", serviceName),
		zap.String("environment", sm.env.Environment),
		zap.String("path", secretPath))

	// Try to retrieve existing secrets
	if sm.backend.Exists(secretPath) {
		existing, err := sm.backend.Retrieve(secretPath)
		if err != nil {
			logger.Warn("Failed to retrieve existing secrets, generating new ones", zap.Error(err))
		} else {
			// Validate existing secrets have all required keys
			secrets := &ServiceSecrets{
				ServiceName: serviceName,
				Environment: sm.env.Environment,
				Secrets:     existing,
				Backend:     fmt.Sprintf("%T", sm.backend),
			}

			if sm.validateSecrets(secrets, requiredSecrets) {
				logger.Info("Using existing secrets", zap.String("service", serviceName))
				return secrets, nil
			}

			logger.Info("Existing secrets incomplete, generating missing secrets")
		}
	}

	// Generate new secrets
	logger.Info("Generating new secrets",
		zap.String("service", serviceName),
		zap.Int("secret_count", len(requiredSecrets)))

	secrets := &ServiceSecrets{
		ServiceName: serviceName,
		Environment: sm.env.Environment,
		Secrets:     make(map[string]interface{}),
		Backend:     fmt.Sprintf("%T", sm.backend),
	}

	// Generate each required secret
	for secretName, secretType := range requiredSecrets {
		value, err := sm.generateSecret(secretType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate %s: %w", secretName, err)
		}
		secrets.Secrets[secretName] = value

		logger.Info("Generated secret",
			zap.String("service", serviceName),
			zap.String("secret", secretName),
			zap.String("type", string(secretType)))
	}

	// Store secrets in backend
	if err := sm.backend.Store(secretPath, secrets.Secrets); err != nil {
		logger.Error("Failed to store secrets", zap.Error(err))
		// Don't fail - secrets are generated, just not persisted
	} else {
		logger.Info("Secrets stored successfully", zap.String("path", secretPath))
	}

	return secrets, nil
}

// validateSecrets checks if existing secrets contain all required keys
func (sm *SecretManager) validateSecrets(secrets *ServiceSecrets, required map[string]SecretType) bool {
	for secretName := range required {
		if _, exists := secrets.Secrets[secretName]; !exists {
			return false
		}

		// Check if secret value is not empty
		if value, ok := secrets.Secrets[secretName].(string); !ok || value == "" {
			return false
		}
	}
	return true
}

// generateSecret generates a secret of the specified type
func (sm *SecretManager) generateSecret(secretType SecretType) (string, error) {
	switch secretType {
	case SecretTypePassword:
		return sm.generatePassword(16)
	case SecretTypeAPIKey:
		return sm.generateAPIKey(32)
	case SecretTypeToken:
		return sm.generateToken(24)
	case SecretTypeJWT:
		return sm.generateJWTSecret(32)
	default:
		return sm.generatePassword(16)
	}
}

// generatePassword generates a secure random password
func (sm *SecretManager) generatePassword(length int) (string, error) {
	// Character sets for password generation
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	special := "!@#$%^&*"

	allChars := lowercase + uppercase + digits + special

	password := make([]byte, length)
	for i := range password {
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		password[i] = allChars[int(randomBytes[0])%len(allChars)]
	}

	return string(password), nil
}

// generateAPIKey generates a secure API key
func (sm *SecretManager) generateAPIKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// generateToken generates a secure token
func (sm *SecretManager) generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// generateJWTSecret generates a JWT signing secret
func (sm *SecretManager) generateJWTSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// GetBackend returns the secret backend for direct access (for advanced use cases)
// Most code should use GetOrGenerateServiceSecrets instead
func (sm *SecretManager) GetBackend() SecretBackend {
	return sm.backend
}

// Vault Backend Implementation
type VaultBackend struct {
	address string
	client  *api.Client
	rc      *eos_io.RuntimeContext // For logging in diagnostic functions
}

// NewVaultBackend creates a Vault backend using the centralized GetVaultClient()
// This ensures consistent TLS settings, VAULT_SKIP_VERIFY handling, and token management
func NewVaultBackend(rc *eos_io.RuntimeContext, address string) (*VaultBackend, error) {
	// CRITICAL FIX P0: Use centralized vault.GetVaultClient() instead of creating our own
	// This respects VAULT_SKIP_VERIFY, TLS settings, and environment variables
	// Fixes: "Client sent an HTTP request to an HTTPS server" error
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Token should be set via VAULT_TOKEN environment variable
	// or read from ~/.vault-token by the SDK (handled by GetVaultClient)

	return &VaultBackend{
		address: address,
		client:  client,
		rc:      rc,
	}, nil
}

func (vb *VaultBackend) Store(path string, secret map[string]interface{}) error {
	logger := otelzap.Ctx(vb.rc.Ctx)

	// DIAGNOSTIC: Log token information before operation
	if err := vb.logTokenDiagnostics(path); err != nil {
		logger.Warn("Failed to retrieve token diagnostics (non-critical)",
			zap.Error(err),
			zap.String("target_path", path))
	}

	// Store secret in Vault KV v2
	// Path format: secret/data/{path}
	_, err := vb.client.KVv2("secret").Put(context.Background(), path, secret)
	if err != nil {
		// Check if this is a permission denied error on service secrets path
		if strings.Contains(err.Error(), "permission denied") && strings.HasPrefix(path, "services/") {
			return fmt.Errorf("failed to store secret in Vault at %s: %w\n\n"+
				"HINT: The Vault policy may be missing service secrets access.\n"+
				"Run this command to update Vault policies:\n"+
				"  sudo eos update vault --update-policies\n\n"+
				"Then restart Vault Agent to get a new token:\n"+
				"  sudo systemctl restart vault-agent-eos", path, err)
		}
		return fmt.Errorf("failed to store secret in Vault at %s: %w", path, err)
	}
	return nil
}

// logTokenDiagnostics logs detailed information about the current Vault token
// to help diagnose permission denied errors
func (vb *VaultBackend) logTokenDiagnostics(targetPath string) error {
	logger := otelzap.Ctx(vb.rc.Ctx)

	// Lookup current token information
	tokenInfo, err := vb.client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("failed to lookup token: %w", err)
	}

	// Extract token details
	accessor := "unknown"
	if acc, ok := tokenInfo.Data["accessor"].(string); ok && len(acc) >= 8 {
		accessor = acc[:8] + "..." // Show first 8 chars for identification
	}

	policies := []string{}
	if pols, ok := tokenInfo.Data["policies"].([]interface{}); ok {
		for _, p := range pols {
			if pstr, ok := p.(string); ok {
				policies = append(policies, pstr)
			}
		}
	}

	ttl := "unknown"
	if ttlRaw, ok := tokenInfo.Data["ttl"].(json.Number); ok {
		ttl = ttlRaw.String() + "s"
	}

	// Log token diagnostics
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Vault Token Diagnostics (for permission troubleshooting)")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Token Information:",
		zap.String("accessor", accessor),
		zap.Strings("policies", policies),
		zap.String("ttl_remaining", ttl),
		zap.String("target_path", "secret/data/"+targetPath))

	// Check token capabilities on the target path
	fullPath := fmt.Sprintf("secret/data/%s", targetPath)
	caps, err := vb.client.Sys().CapabilitiesSelf(fullPath)
	if err != nil {
		logger.Warn("Failed to check token capabilities", zap.Error(err))
	} else {
		logger.Info("Token Capabilities on Target Path:",
			zap.String("path", fullPath),
			zap.Strings("capabilities", caps))

		// Analyze capabilities
		hasCreate := false
		hasUpdate := false
		for _, cap := range caps {
			if cap == "create" {
				hasCreate = true
			}
			if cap == "update" {
				hasUpdate = true
			}
		}

		if !hasCreate && !hasUpdate {
			logger.Error("❌ Token DOES NOT have 'create' or 'update' capability on target path",
				zap.String("path", fullPath),
				zap.Strings("actual_capabilities", caps))
		} else {
			logger.Info("✓ Token has required capabilities",
				zap.Bool("has_create", hasCreate),
				zap.Bool("has_update", hasUpdate))
		}
	}

	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	return nil
}

func (vb *VaultBackend) Retrieve(path string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(vb.rc.Ctx)

	// DIAGNOSTIC: Log token information before operation
	if err := vb.logTokenDiagnostics(path); err != nil {
		logger.Warn("Failed to retrieve token diagnostics (non-critical)",
			zap.Error(err),
			zap.String("target_path", path))
	}

	// Retrieve secret from Vault KV v2
	secretData, err := vb.client.KVv2("secret").Get(context.Background(), path)
	if err != nil {
		// Check if this is a permission denied error
		if strings.Contains(err.Error(), "permission denied") {
			return nil, fmt.Errorf("failed to retrieve secret from Vault at %s: %w\n\n"+
				"HINT: The Vault token may not have read permissions on this path.\n"+
				"Check the token's policies with:\n"+
				"  vault token lookup", path, err)
		}
		return nil, fmt.Errorf("failed to retrieve secret from Vault at %s: %w", path, err)
	}

	if secretData == nil || secretData.Data == nil {
		return nil, fmt.Errorf("secret not found at %s", path)
	}

	return secretData.Data, nil
}

func (vb *VaultBackend) Generate(path string, secretType SecretType) (string, error) {
	// Generate secret using local crypto (Vault doesn't generate secrets for us)
	// Then store it in Vault
	secret, err := generateSecretValue(secretType)
	if err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}

	// Store in Vault
	secretMap := map[string]interface{}{
		"value": secret,
		"type":  string(secretType),
	}

	if err := vb.Store(path, secretMap); err != nil {
		return "", fmt.Errorf("failed to store generated secret: %w", err)
	}

	return secret, nil
}

// generateSecretValue generates a secret value based on type
func generateSecretValue(secretType SecretType) (string, error) {
	bytes := make([]byte, 32) // Default 32 bytes = 256 bits

	switch secretType {
	case SecretTypeAPIKey:
		bytes = make([]byte, 44) // 44 bytes for base64 API keys
	case SecretTypeToken, SecretTypeJWT:
		bytes = make([]byte, 64) // 64 bytes for tokens
	}

	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

func (vb *VaultBackend) Exists(path string) bool {
	// Check if secret exists in Vault
	secretData, err := vb.client.KVv2("secret").Get(context.Background(), path)
	if err != nil || secretData == nil {
		return false
	}
	return secretData.Data != nil
}

// File Backend Implementation (fallback)
type FileBackend struct {
	basePath string
}

func NewFileBackend() *FileBackend {
	return &FileBackend{
		basePath: "/opt/eos/secrets",
	}
}

func (fb *FileBackend) Store(path string, secret map[string]interface{}) error {
	fullPath := filepath.Join(fb.basePath, path+".json")

	// Create directory
	if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
		return fmt.Errorf("failed to create secret directory: %w", err)
	}

	// Store as JSON
	data, err := json.MarshalIndent(secret, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secret: %w", err)
	}

	if err := os.WriteFile(fullPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write secret file: %w", err)
	}

	return nil
}

func (fb *FileBackend) Retrieve(path string) (map[string]interface{}, error) {
	fullPath := filepath.Join(fb.basePath, path+".json")

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("secret not found")
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret file: %w", err)
	}

	var secret map[string]interface{}
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, fmt.Errorf("failed to parse secret: %w", err)
	}

	return secret, nil
}

func (fb *FileBackend) Generate(path string, secretType SecretType) (string, error) {
	// File backend doesn't have built-in generation, use manual generation
	return "", fmt.Errorf("file backend generate not supported")
}

func (fb *FileBackend) Exists(path string) bool {
	fullPath := filepath.Join(fb.basePath, path+".json")
	_, err := os.Stat(fullPath)
	return err == nil
}
