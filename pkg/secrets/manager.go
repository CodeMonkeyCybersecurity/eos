// Package secrets provides automatic secret management across Vault and file backends
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
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

// SecretMetadata holds custom metadata for a secret (TTL, owner, rotation policy, etc.)
// This metadata is stored in Vault KV v2 custom_metadata and used for compliance,
// auditing, and automated rotation policies.
//
// TTL Examples: "24h", "30d", "90d", "never"
// RotateAfter Examples: "90d", "on_use", "never"
type SecretMetadata struct {
	TTL         string            `json:"ttl,omitempty"`          // Secret time-to-live (e.g., "24h", "30d", "never")
	CreatedBy   string            `json:"created_by,omitempty"`   // Who/what created this secret (e.g., "eos", "user@host")
	CreatedAt   string            `json:"created_at,omitempty"`   // ISO 8601 timestamp of creation
	Purpose     string            `json:"purpose,omitempty"`      // Human-readable purpose (e.g., "database auth", "api integration")
	Owner       string            `json:"owner,omitempty"`        // Owning service (e.g., "bionicgpt", "authentik")
	RotateAfter string            `json:"rotate_after,omitempty"` // Rotation policy (e.g., "90d", "on_use", "never")
	Custom      map[string]string `json:"custom,omitempty"`       // Arbitrary custom metadata (e.g., endpoint, model, region)
}

// GetString retrieves a secret as string (returns empty string if not found or wrong type)
// Use GetStringOrError for strict error handling
func (ss *ServiceSecrets) GetString(key string) string {
	if val, ok := ss.Secrets[key].(string); ok {
		return val
	}
	return ""
}

// GetStringOrError retrieves a secret as string with error handling
func (ss *ServiceSecrets) GetStringOrError(key string) (string, error) {
	val, exists := ss.Secrets[key]
	if !exists {
		return "", fmt.Errorf("secret '%s' not found in service '%s'", key, ss.ServiceName)
	}
	strVal, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("secret '%s' in service '%s' is not a string (type: %T)", key, ss.ServiceName, val)
	}
	return strVal, nil
}

// GetInt retrieves a secret as int (returns 0 if not found or wrong type)
func (ss *ServiceSecrets) GetInt(key string) int {
	switch val := ss.Secrets[key].(type) {
	case int:
		return val
	case float64: // JSON numbers decode as float64
		return int(val)
	case string:
		// Try to parse string as int
		var i int
		if _, err := fmt.Sscanf(val, "%d", &i); err == nil {
			return i
		}
	}
	return 0
}

// GetBool retrieves a secret as bool (returns false if not found or wrong type)
func (ss *ServiceSecrets) GetBool(key string) bool {
	switch val := ss.Secrets[key].(type) {
	case bool:
		return val
	case string:
		// Parse string as bool
		return val == "true" || val == "1" || val == "yes"
	case int:
		return val != 0
	case float64:
		return val != 0
	}
	return false
}

// Has checks if a secret exists (regardless of type)
func (ss *ServiceSecrets) Has(key string) bool {
	_, exists := ss.Secrets[key]
	return exists
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
	// P0 FIX: MUST fail if storage fails - otherwise secrets are lost on restart
	if err := sm.backend.Store(secretPath, secrets.Secrets); err != nil {
		logger.Error("Failed to store secrets in backend", zap.Error(err))
		return nil, fmt.Errorf("failed to persist secrets to backend at %s: %w", secretPath, err)
	}

	logger.Info("Secrets stored successfully", zap.String("path", secretPath))
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
// REFACTORED: Now delegates to pkg/crypto for all generation (single source of truth)
// All secrets use alphanumeric-only [a-zA-Z0-9] for maximum compatibility
func (sm *SecretManager) generateSecret(secretType SecretType) (string, error) {
	switch secretType {
	case SecretTypePassword:
		// Use 32 chars for strong security (log2(62^32) ≈ 190 bits)
		return crypto.GenerateURLSafePassword(32)
	case SecretTypeAPIKey:
		// Use 32 chars for API keys (industry standard)
		return crypto.GenerateAPIKey(32)
	case SecretTypeToken:
		// Use 32 chars for tokens (consistent with other secrets)
		return crypto.GenerateToken(32)
	case SecretTypeJWT:
		// Use 32 chars minimum (enforced by GenerateJWTSecret)
		return crypto.GenerateJWTSecret(32)
	default:
		// Default to password generation
		return crypto.GenerateURLSafePassword(32)
	}
}

// StoreSecret stores a single secret for a service (idempotent, unified path format)
// This is the recommended way to store individual secrets.
//
// Path format: services/{environment}/{service}
// Secrets stored as map: {"secret_name": "value", "secret_name_type": "password"}
//
// Example:
//
//	secretManager.StoreSecret("bionicgpt", "azure_api_key", apiKey, secrets.SecretTypeAPIKey)
func (sm *SecretManager) StoreSecret(serviceName, secretName string, value interface{}, secretType SecretType) error {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Unified path format
	secretPath := fmt.Sprintf("services/%s/%s", sm.env.Environment, serviceName)

	logger.Info("Storing secret",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("environment", sm.env.Environment),
		zap.String("path", secretPath),
		zap.String("type", string(secretType)))

	// ASSESS - Get existing secrets (if any)
	existing := make(map[string]interface{})
	if sm.backend.Exists(secretPath) {
		var err error
		existing, err = sm.backend.Retrieve(secretPath)
		if err != nil {
			logger.Warn("Could not retrieve existing secrets, will overwrite",
				zap.Error(err),
				zap.String("path", secretPath))
			existing = make(map[string]interface{})
		}
	}

	// INTERVENE - Update/add this secret
	existing[secretName] = value
	existing[secretName+"_type"] = string(secretType) // Store type metadata for validation

	// Store back to backend
	if err := sm.backend.Store(secretPath, existing); err != nil {
		logger.Error("Failed to store secret",
			zap.Error(err),
			zap.String("service", serviceName),
			zap.String("secret", secretName))
		return fmt.Errorf("failed to store secret '%s' for service '%s': %w", secretName, serviceName, err)
	}

	// EVALUATE
	logger.Info("Secret stored successfully",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("path", secretPath))

	return nil
}

// GetSecret retrieves a single secret for a service with type safety
// Returns the secret value as a string, or error if not found/wrong type.
//
// Path format: services/{environment}/{service}
//
// Example:
//
//	apiKey, err := secretManager.GetSecret("bionicgpt", "azure_api_key")
func (sm *SecretManager) GetSecret(serviceName, secretName string) (string, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Unified path format
	secretPath := fmt.Sprintf("services/%s/%s", sm.env.Environment, serviceName)

	logger.Debug("Retrieving secret",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("environment", sm.env.Environment),
		zap.String("path", secretPath))

	// ASSESS - Check if service secrets exist
	if !sm.backend.Exists(secretPath) {
		return "", fmt.Errorf("no secrets found for service '%s' in environment '%s'", serviceName, sm.env.Environment)
	}

	// Retrieve all secrets for service
	secrets, err := sm.backend.Retrieve(secretPath)
	if err != nil {
		logger.Error("Failed to retrieve secrets from backend",
			zap.Error(err),
			zap.String("path", secretPath))
		return "", fmt.Errorf("failed to retrieve secrets for service '%s': %w", serviceName, err)
	}

	// ASSESS - Check if specific secret exists
	value, exists := secrets[secretName]
	if !exists {
		return "", fmt.Errorf("secret '%s' not found for service '%s'", secretName, serviceName)
	}

	// INTERVENE - Type assertion to string
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret '%s' for service '%s' is not a string (type: %T)", secretName, serviceName, value)
	}

	// EVALUATE
	logger.Debug("Secret retrieved successfully",
		zap.String("service", serviceName),
		zap.String("secret", secretName))

	return strValue, nil
}

// UpdateSecret updates an existing secret (alias to StoreSecret for clarity)
// Returns error if secret doesn't exist - use StoreSecret to create new secrets
func (sm *SecretManager) UpdateSecret(serviceName, secretName string, newValue interface{}, secretType SecretType) error {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Check if secret exists first
	_, err := sm.GetSecret(serviceName, secretName)
	if err != nil {
		return fmt.Errorf("cannot update non-existent secret '%s' for service '%s': %w (use StoreSecret to create)", secretName, serviceName, err)
	}

	logger.Info("Updating existing secret",
		zap.String("service", serviceName),
		zap.String("secret", secretName))

	// Use StoreSecret (idempotent)
	return sm.StoreSecret(serviceName, secretName, newValue, secretType)
}

// StoreSecretWithMetadata stores a secret with custom metadata (TTL, owner, rotation policy, etc.)
// This is the recommended method for storing secrets with compliance/audit requirements.
//
// Metadata is stored using Vault KV v2 custom_metadata feature (only available for Vault backend).
// File backend silently ignores metadata (logged as debug message).
//
// Path format: services/{environment}/{service}
//
// Example:
//
//	metadata := &secrets.SecretMetadata{
//		TTL:       "90d",
//		CreatedBy: "eos create bionicgpt",
//		Purpose:   "Azure OpenAI API integration",
//		Owner:     "bionicgpt",
//		Custom: map[string]string{
//			"endpoint": "https://myazure.openai.azure.com",
//			"model":    "gpt-4",
//		},
//	}
//	err := secretManager.StoreSecretWithMetadata("bionicgpt", "azure_api_key", apiKey, secrets.SecretTypeAPIKey, metadata)
func (sm *SecretManager) StoreSecretWithMetadata(
	serviceName, secretName string,
	value interface{},
	secretType SecretType,
	metadata *SecretMetadata,
) error {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Unified path format
	secretPath := fmt.Sprintf("services/%s/%s", sm.env.Environment, serviceName)

	logger.Info("Storing secret with metadata",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("environment", sm.env.Environment),
		zap.String("path", secretPath),
		zap.String("type", string(secretType)),
		zap.String("ttl", metadata.TTL))

	// ASSESS - Get existing secrets (if any)
	existing := make(map[string]interface{})
	if sm.backend.Exists(secretPath) {
		var err error
		existing, err = sm.backend.Retrieve(secretPath)
		if err != nil {
			logger.Warn("Could not retrieve existing secrets, will overwrite",
				zap.Error(err),
				zap.String("path", secretPath))
			existing = make(map[string]interface{})
		}
	}

	// INTERVENE - Update/add this secret
	existing[secretName] = value
	existing[secretName+"_type"] = string(secretType) // Store type metadata

	// Store secret data first (KV v2 Put)
	if err := sm.backend.Store(secretPath, existing); err != nil {
		logger.Error("Failed to store secret",
			zap.Error(err),
			zap.String("service", serviceName),
			zap.String("secret", secretName))
		return fmt.Errorf("failed to store secret '%s' for service '%s': %w", secretName, serviceName, err)
	}

	// INTERVENE - Store metadata (ONLY for Vault backend)
	if vaultBackend, ok := sm.backend.(*VaultBackend); ok {
		// Add timestamp if not provided
		if metadata.CreatedAt == "" {
			metadata.CreatedAt = fmt.Sprintf("%d", time.Now().Unix())
		}

		if err := vaultBackend.StoreMetadata(secretPath, metadata); err != nil {
			logger.Warn("Failed to store secret metadata (non-critical - secret data is stored)",
				zap.Error(err),
				zap.String("secret", secretName),
				zap.String("service", serviceName))
			// Don't fail - secret is stored, metadata is optional enhancement
		} else {
			logger.Debug("Secret metadata stored successfully",
				zap.String("service", serviceName),
				zap.String("secret", secretName))
		}
	} else {
		logger.Debug("Skipping metadata storage (file backend doesn't support it)",
			zap.String("backend", fmt.Sprintf("%T", sm.backend)))
	}

	// EVALUATE
	logger.Info("Secret stored successfully",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("path", secretPath))

	return nil
}

// GetSecretWithMetadata retrieves a secret along with its metadata (if available)
// Returns the secret value and metadata. Metadata will be empty if not available or if using file backend.
//
// Example:
//
//	value, metadata, err := secretManager.GetSecretWithMetadata("bionicgpt", "azure_api_key")
//	if err != nil {
//		return err
//	}
//	fmt.Printf("API Key TTL: %s\n", metadata.TTL)
func (sm *SecretManager) GetSecretWithMetadata(serviceName, secretName string) (string, *SecretMetadata, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Get the secret value first
	value, err := sm.GetSecret(serviceName, secretName)
	if err != nil {
		return "", nil, err
	}

	// Try to get metadata (only works for Vault backend)
	metadata := &SecretMetadata{}
	if vaultBackend, ok := sm.backend.(*VaultBackend); ok {
		secretPath := fmt.Sprintf("services/%s/%s", sm.env.Environment, serviceName)
		retrievedMetadata, err := vaultBackend.GetMetadata(secretPath)
		if err != nil {
			logger.Debug("Could not retrieve secret metadata (non-critical)",
				zap.Error(err),
				zap.String("service", serviceName),
				zap.String("secret", secretName))
			// Return empty metadata, not an error
		} else {
			metadata = retrievedMetadata
		}
	}

	return value, metadata, nil
}

// DeleteSecret removes a single secret from a service's secret bundle
// This is an atomic operation - only the specified secret is removed, others are preserved.
//
// Example:
//
//	err := secretManager.DeleteSecret("bionicgpt", "old_api_key")
func (sm *SecretManager) DeleteSecret(serviceName, secretName string) error {
	logger := otelzap.Ctx(sm.rc.Ctx)

	secretPath := fmt.Sprintf("services/%s/%s", sm.env.Environment, serviceName)

	logger.Info("Deleting secret",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("environment", sm.env.Environment),
		zap.String("path", secretPath))

	// ASSESS - Check if service secrets exist
	if !sm.backend.Exists(secretPath) {
		return fmt.Errorf("no secrets found for service '%s' in environment '%s'", serviceName, sm.env.Environment)
	}

	// Retrieve all secrets
	secrets, err := sm.backend.Retrieve(secretPath)
	if err != nil {
		logger.Error("Failed to retrieve secrets from backend",
			zap.Error(err),
			zap.String("path", secretPath))
		return fmt.Errorf("failed to retrieve secrets for service '%s': %w", serviceName, err)
	}

	// ASSESS - Check if secret exists
	if _, exists := secrets[secretName]; !exists {
		return fmt.Errorf("secret '%s' not found in service '%s'", secretName, serviceName)
	}

	// INTERVENE - Remove this secret and its metadata
	delete(secrets, secretName)
	delete(secrets, secretName+"_type") // Remove type metadata too

	// Store updated bundle back to backend
	if err := sm.backend.Store(secretPath, secrets); err != nil {
		logger.Error("Failed to update secrets after deletion",
			zap.Error(err),
			zap.String("service", serviceName),
			zap.String("secret", secretName))
		return fmt.Errorf("failed to update secrets after deleting '%s': %w", secretName, err)
	}

	// EVALUATE
	logger.Info("Secret deleted successfully",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.Int("remaining_secrets", len(secrets)))

	return nil
}

// ListSecrets returns all secret names for a service (without values)
// Returns empty slice if service has no secrets.
//
// Example:
//
//	secretNames, err := secretManager.ListSecrets("bionicgpt")
//	// Returns: ["azure_api_key", "postgres_password", "jwt_secret"]
func (sm *SecretManager) ListSecrets(serviceName string) ([]string, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	secretPath := fmt.Sprintf("services/%s/%s", sm.env.Environment, serviceName)

	logger.Debug("Listing secrets",
		zap.String("service", serviceName),
		zap.String("environment", sm.env.Environment),
		zap.String("path", secretPath))

	// ASSESS - Check if service secrets exist
	if !sm.backend.Exists(secretPath) {
		logger.Debug("No secrets found for service",
			zap.String("service", serviceName),
			zap.String("environment", sm.env.Environment))
		return []string{}, nil // No secrets = empty list (not an error)
	}

	// Retrieve all secrets
	secrets, err := sm.backend.Retrieve(secretPath)
	if err != nil {
		logger.Error("Failed to retrieve secrets from backend",
			zap.Error(err),
			zap.String("path", secretPath))
		return nil, fmt.Errorf("failed to retrieve secrets for service '%s': %w", serviceName, err)
	}

	// INTERVENE - Extract secret names (filter out metadata keys)
	secretNames := []string{}
	for key := range secrets {
		// Skip metadata keys (end with "_type")
		if !strings.HasSuffix(key, "_type") {
			secretNames = append(secretNames, key)
		}
	}

	// EVALUATE
	logger.Debug("Listed secrets",
		zap.String("service", serviceName),
		zap.Int("count", len(secretNames)))

	return secretNames, nil
}

// SecretExists checks if a specific secret exists for a service (without retrieving it)
// This is more efficient than GetSecret if you only need to check existence.
//
// Example:
//
//	if secretManager.SecretExists("bionicgpt", "azure_api_key") {
//		// Secret exists, safe to update
//	}
func (sm *SecretManager) SecretExists(serviceName, secretName string) bool {
	logger := otelzap.Ctx(sm.rc.Ctx)

	secretPath := fmt.Sprintf("services/%s/%s", sm.env.Environment, serviceName)

	// Check if service has any secrets
	if !sm.backend.Exists(secretPath) {
		return false
	}

	// Retrieve all secrets to check for specific key
	secrets, err := sm.backend.Retrieve(secretPath)
	if err != nil {
		logger.Debug("Failed to retrieve secrets while checking existence",
			zap.Error(err),
			zap.String("service", serviceName),
			zap.String("secret", secretName))
		return false
	}

	_, exists := secrets[secretName]
	return exists
}

// GetBackend returns the secret backend for direct access (for advanced use cases)
// Most code should use StoreSecret/GetSecret instead
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
// REFACTORED: Now delegates to pkg/crypto for all generation (single source of truth)
// All secrets use alphanumeric-only [a-zA-Z0-9] for maximum compatibility
func generateSecretValue(secretType SecretType) (string, error) {
	switch secretType {
	case SecretTypePassword:
		return crypto.GenerateURLSafePassword(32)
	case SecretTypeAPIKey:
		return crypto.GenerateAPIKey(32)
	case SecretTypeToken:
		return crypto.GenerateToken(32)
	case SecretTypeJWT:
		return crypto.GenerateJWTSecret(32)
	default:
		return crypto.GenerateURLSafePassword(32)
	}
}

func (vb *VaultBackend) Exists(path string) bool {
	// Check if secret exists in Vault
	secretData, err := vb.client.KVv2("secret").Get(context.Background(), path)
	if err != nil || secretData == nil {
		return false
	}
	return secretData.Data != nil
}

// StoreMetadata stores custom metadata for a secret path using Vault KV v2 metadata API
// This leverages Vault's custom_metadata feature to attach TTL, owner, rotation policies, etc.
//
// SECURITY NOTE: Metadata is NOT encrypted, but it's audit-logged.
// NEVER put sensitive data in metadata - use secret data storage instead.
//
// Path format: Metadata is stored at secret/metadata/{path}
// Secret data is at secret/data/{path} (handled by Store method)
func (vb *VaultBackend) StoreMetadata(path string, metadata *SecretMetadata) error {
	logger := otelzap.Ctx(vb.rc.Ctx)

	// Convert SecretMetadata struct to map[string]string for Vault
	customMetadata := make(map[string]string)
	if metadata.TTL != "" {
		customMetadata["ttl"] = metadata.TTL
	}
	if metadata.CreatedBy != "" {
		customMetadata["created_by"] = metadata.CreatedBy
	}
	if metadata.CreatedAt != "" {
		customMetadata["created_at"] = metadata.CreatedAt
	}
	if metadata.Purpose != "" {
		customMetadata["purpose"] = metadata.Purpose
	}
	if metadata.Owner != "" {
		customMetadata["owner"] = metadata.Owner
	}
	if metadata.RotateAfter != "" {
		customMetadata["rotate_after"] = metadata.RotateAfter
	}

	// Add any custom fields
	for k, v := range metadata.Custom {
		// Prefix custom fields to avoid collision with standard fields
		customMetadata["custom_"+k] = v
	}

	// Vault KV v2 metadata path
	metadataPath := fmt.Sprintf("secret/metadata/%s", path)

	logger.Debug("Writing secret metadata to Vault",
		zap.String("path", metadataPath),
		zap.Int("metadata_fields", len(customMetadata)))

	// Write to Vault using logical client (metadata endpoint)
	_, err := vb.client.Logical().WriteWithContext(vb.rc.Ctx, metadataPath, map[string]interface{}{
		"custom_metadata": customMetadata,
	})

	if err != nil {
		logger.Error("Failed to store secret metadata",
			zap.Error(err),
			zap.String("path", metadataPath))
		return fmt.Errorf("failed to write metadata to %s: %w", metadataPath, err)
	}

	logger.Debug("Secret metadata stored successfully",
		zap.String("path", metadataPath),
		zap.Int("fields", len(customMetadata)))

	return nil
}

// GetMetadata retrieves custom metadata for a secret path from Vault KV v2
// Returns an empty SecretMetadata struct if no metadata exists (not an error).
//
// Path format: Reads from secret/metadata/{path}
func (vb *VaultBackend) GetMetadata(path string) (*SecretMetadata, error) {
	logger := otelzap.Ctx(vb.rc.Ctx)

	// Vault KV v2 metadata path
	metadataPath := fmt.Sprintf("secret/metadata/%s", path)

	logger.Debug("Reading secret metadata from Vault",
		zap.String("path", metadataPath))

	// Read from Vault using logical client
	resp, err := vb.client.Logical().ReadWithContext(vb.rc.Ctx, metadataPath)
	if err != nil {
		logger.Debug("Failed to read metadata (may not exist)",
			zap.Error(err),
			zap.String("path", metadataPath))
		return &SecretMetadata{}, nil // Return empty metadata, not error
	}

	// No metadata exists - return empty struct
	if resp == nil || resp.Data == nil {
		logger.Debug("No metadata found at path",
			zap.String("path", metadataPath))
		return &SecretMetadata{}, nil
	}

	// Extract custom_metadata field
	customMetadataRaw, ok := resp.Data["custom_metadata"]
	if !ok {
		logger.Debug("No custom_metadata field in response",
			zap.String("path", metadataPath))
		return &SecretMetadata{}, nil
	}

	// Type assert to map[string]interface{} (Vault returns this type)
	customMetadataMap, ok := customMetadataRaw.(map[string]interface{})
	if !ok {
		logger.Warn("custom_metadata is not a map",
			zap.String("path", metadataPath),
			zap.String("type", fmt.Sprintf("%T", customMetadataRaw)))
		return &SecretMetadata{}, nil
	}

	// Convert map to SecretMetadata struct
	metadata := &SecretMetadata{
		Custom: make(map[string]string),
	}

	// Extract standard fields
	if ttl, ok := customMetadataMap["ttl"].(string); ok {
		metadata.TTL = ttl
	}
	if createdBy, ok := customMetadataMap["created_by"].(string); ok {
		metadata.CreatedBy = createdBy
	}
	if createdAt, ok := customMetadataMap["created_at"].(string); ok {
		metadata.CreatedAt = createdAt
	}
	if purpose, ok := customMetadataMap["purpose"].(string); ok {
		metadata.Purpose = purpose
	}
	if owner, ok := customMetadataMap["owner"].(string); ok {
		metadata.Owner = owner
	}
	if rotateAfter, ok := customMetadataMap["rotate_after"].(string); ok {
		metadata.RotateAfter = rotateAfter
	}

	// Extract custom fields (prefixed with "custom_")
	for k, v := range customMetadataMap {
		if strings.HasPrefix(k, "custom_") {
			if strVal, ok := v.(string); ok {
				// Remove "custom_" prefix
				metadata.Custom[strings.TrimPrefix(k, "custom_")] = strVal
			}
		}
	}

	logger.Debug("Secret metadata retrieved successfully",
		zap.String("path", metadataPath),
		zap.Int("fields", len(customMetadataMap)))

	return metadata, nil
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
