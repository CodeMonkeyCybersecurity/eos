// Package secrets provides automatic secret management across Vault and file backends
package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Manager handles automatic secret management
// NOTE: Renamed from SecretManager for consistency with SecretStore naming
type Manager struct {
	rc      *eos_io.RuntimeContext
	backend SecretStore // REFACTORED: Uses new SecretStore interface
	env     *environment.EnvironmentConfig
}

// SecretManager is a deprecated alias for Manager
// DEPRECATED: Use Manager instead. Will be removed in Eos v2.0.0 (approximately 6 months)
type SecretManager = Manager

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

// NewManager creates a new secret manager with automatic backend detection
// REFACTORED: Now uses SecretStore interface and new VaultStore/ConsulStore implementations
func NewManager(rc *eos_io.RuntimeContext, envConfig *environment.EnvironmentConfig) (*Manager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var backend SecretStore

	// SECURITY: Choose backend based on environment configuration
	// Vault is the secure default for production
	// Consul KV fallback for Hecate when Vault unavailable (legacy compatibility)
	backendType := os.Getenv("EOS_SECRET_BACKEND")
	if backendType == "" {
		backendType = "vault" // Secure default
	}

	switch backendType {
	case "vault":
		// Create Vault client using centralized GetVaultClient()
		vaultClient, err := vault.GetVaultClient(rc)
		if err != nil {
			logger.Error("Vault client initialization failed", zap.Error(err))
			// SECURITY: Fail-closed in production, only allow fallback in dev/test
			if os.Getenv("GO_ENV") == "development" || os.Getenv("GO_ENV") == "test" {
				logger.Warn("Development mode: falling back to Consul KV backend (INSECURE - plaintext storage)")
				// Try Consul fallback
				consulConfig := consulapi.DefaultConfig()
				consulClient, consulErr := consulapi.NewClient(consulConfig)
				if consulErr != nil {
					return nil, fmt.Errorf("vault backend failed and consul fallback unavailable: vault error: %w, consul error: %v", err, consulErr)
				}
				backend = NewConsulStore(consulClient)
			} else {
				return nil, fmt.Errorf("vault backend required in production but initialization failed: %w", err)
			}
		} else {
			backend = NewVaultStore(vaultClient, "secret")
		}
	case "consul":
		// SECURITY: Only allow Consul KV backend in development/testing or for Hecate legacy compatibility
		if os.Getenv("GO_ENV") != "development" && os.Getenv("GO_ENV") != "test" {
			logger.Warn("Using Consul KV backend in production (PLAINTEXT storage - not recommended)")
		}
		consulConfig := consulapi.DefaultConfig()
		consulClient, err := consulapi.NewClient(consulConfig)
		if err != nil {
			return nil, fmt.Errorf("consul client initialization failed: %w", err)
		}
		logger.Warn("Using insecure Consul KV backend (plaintext storage)")
		backend = NewConsulStore(consulClient)
	default:
		return nil, fmt.Errorf("unsupported secret backend: %s (supported: vault, consul)", backendType)
	}

	logger.Info("Secret manager initialized",
		zap.String("backend", backend.Name()),
		zap.Bool("supports_versioning", backend.SupportsVersioning()),
		zap.Bool("supports_metadata", backend.SupportsMetadata()))

	return &Manager{
		rc:      rc,
		backend: backend,
		env:     envConfig,
	}, nil
}

// NewSecretManager is a deprecated alias for NewManager
// DEPRECATED: Use NewManager instead. Will be removed in Eos v2.0.0 (approximately 6 months)
func NewSecretManager(rc *eos_io.RuntimeContext, envConfig *environment.EnvironmentConfig) (*Manager, error) {
	return NewManager(rc, envConfig)
}

// EnsureServiceSecrets ensures that all required secrets exist for a service
// If secrets exist in the backend, they are retrieved. If any are missing, new ones are generated and stored.
// This is the recommended method for service secret management.
//
// REFACTORED: Renamed from GetOrGenerateServiceSecrets to clarify that this function:
//  1. GETs existing secrets from backend
//  2. GENERATEs missing secrets
//  3. STOREs new/updated secrets to backend
//
// The name "Ensure" makes it clear that the function guarantees the final state (all secrets exist).
func (m *Manager) EnsureServiceSecrets(ctx context.Context, serviceName string, requiredSecrets map[string]SecretType) (*ServiceSecrets, error) {
	logger := otelzap.Ctx(ctx)

	secretPath := fmt.Sprintf("services/%s/%s", m.env.Environment, serviceName)

	logger.Info("Ensuring service secrets exist",
		zap.String("service", serviceName),
		zap.String("environment", m.env.Environment),
		zap.String("path", secretPath))

	// ASSESS: Try to retrieve existing secrets
	exists, err := m.backend.Exists(ctx, secretPath)
	if err != nil {
		logger.Warn("Failed to check if secrets exist, will generate new ones", zap.Error(err))
		exists = false
	}

	if exists {
		existing, err := m.backend.Get(ctx, secretPath)
		if err != nil {
			logger.Warn("Failed to retrieve existing secrets, generating new ones", zap.Error(err))
		} else {
			// Validate existing secrets have all required keys
			secrets := &ServiceSecrets{
				ServiceName: serviceName,
				Environment: m.env.Environment,
				Secrets:     existing,
				Backend:     m.backend.Name(),
			}

			if m.validateSecrets(secrets, requiredSecrets) {
				logger.Info("Using existing secrets", zap.String("service", serviceName))
				return secrets, nil
			}

			logger.Info("Existing secrets incomplete, generating missing secrets")
		}
	}

	// INTERVENE: Generate new secrets
	logger.Info("Generating new secrets",
		zap.String("service", serviceName),
		zap.Int("secret_count", len(requiredSecrets)))

	secrets := &ServiceSecrets{
		ServiceName: serviceName,
		Environment: m.env.Environment,
		Secrets:     make(map[string]interface{}),
		Backend:     m.backend.Name(),
	}

	// Generate each required secret
	for secretName, secretType := range requiredSecrets {
		value, err := m.generateSecret(secretType)
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
	if err := m.backend.Put(ctx, secretPath, secrets.Secrets); err != nil {
		logger.Error("Failed to store secrets in backend", zap.Error(err))
		return nil, fmt.Errorf("failed to persist secrets to backend at %s: %w", secretPath, err)
	}

	// EVALUATE
	logger.Info("Secrets stored successfully", zap.String("path", secretPath))
	return secrets, nil
}

// GetOrGenerateServiceSecrets is a deprecated alias for EnsureServiceSecrets
// DEPRECATED: Use EnsureServiceSecrets instead. Will be removed in Eos v2.0.0 (approximately 6 months)
//
// This function exists for backward compatibility. New code should use EnsureServiceSecrets(ctx, ...)
func (m *Manager) GetOrGenerateServiceSecrets(serviceName string, requiredSecrets map[string]SecretType) (*ServiceSecrets, error) {
	return m.EnsureServiceSecrets(m.rc.Ctx, serviceName, requiredSecrets)
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
//	secretManager.StoreSecret(ctx, "bionicgpt", "azure_api_key", apiKey, secrets.SecretTypeAPIKey)
func (m *Manager) StoreSecret(ctx context.Context, serviceName, secretName string, value interface{}, secretType SecretType) error {
	logger := otelzap.Ctx(ctx)

	// Unified path format
	secretPath := fmt.Sprintf("services/%s/%s", m.env.Environment, serviceName)

	logger.Info("Storing secret",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("environment", m.env.Environment),
		zap.String("path", secretPath),
		zap.String("type", string(secretType)))

	// ASSESS - Get existing secrets (if any)
	existing := make(map[string]interface{})
	exists, err := m.backend.Exists(ctx, secretPath)
	if err != nil {
		logger.Warn("Could not check if secrets exist, will create new",
			zap.Error(err),
			zap.String("path", secretPath))
	} else if exists {
		existing, err = m.backend.Get(ctx, secretPath)
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
	if err := m.backend.Put(ctx, secretPath, existing); err != nil {
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
//	apiKey, err := secretManager.GetSecret(ctx, "bionicgpt", "azure_api_key")
func (m *Manager) GetSecret(ctx context.Context, serviceName, secretName string) (string, error) {
	logger := otelzap.Ctx(ctx)

	// Unified path format
	secretPath := fmt.Sprintf("services/%s/%s", m.env.Environment, serviceName)

	logger.Debug("Retrieving secret",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("environment", m.env.Environment),
		zap.String("path", secretPath))

	// ASSESS - Check if service secrets exist
	exists, err := m.backend.Exists(ctx, secretPath)
	if err != nil {
		return "", fmt.Errorf("failed to check if secrets exist for service '%s': %w", serviceName, err)
	}
	if !exists {
		return "", fmt.Errorf("no secrets found for service '%s' in environment '%s'", serviceName, m.env.Environment)
	}

	// Retrieve all secrets for service
	secrets, err := m.backend.Get(ctx, secretPath)
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
func (m *Manager) UpdateSecret(ctx context.Context, serviceName, secretName string, newValue interface{}, secretType SecretType) error {
	logger := otelzap.Ctx(ctx)

	// Check if secret exists first
	_, err := m.GetSecret(ctx, serviceName, secretName)
	if err != nil {
		return fmt.Errorf("cannot update non-existent secret '%s' for service '%s': %w (use StoreSecret to create)", secretName, serviceName, err)
	}

	logger.Info("Updating existing secret",
		zap.String("service", serviceName),
		zap.String("secret", secretName))

	// Use StoreSecret (idempotent)
	return m.StoreSecret(ctx, serviceName, secretName, newValue, secretType)
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
//	err := secretManager.StoreSecretWithMetadata(ctx, "bionicgpt", "azure_api_key", apiKey, secrets.SecretTypeAPIKey, metadata)
func (m *Manager) StoreSecretWithMetadata(
	ctx context.Context,
	serviceName, secretName string,
	value interface{},
	secretType SecretType,
	metadata *SecretMetadata,
) error {
	logger := otelzap.Ctx(ctx)

	// Unified path format
	secretPath := fmt.Sprintf("services/%s/%s", m.env.Environment, serviceName)

	logger.Info("Storing secret with metadata",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("environment", m.env.Environment),
		zap.String("path", secretPath),
		zap.String("type", string(secretType)),
		zap.String("ttl", metadata.TTL))

	// ASSESS - Get existing secrets (if any)
	existing := make(map[string]interface{})
	exists, err := m.backend.Exists(ctx, secretPath)
	if err != nil {
		logger.Warn("Could not check if secrets exist, will create new",
			zap.Error(err),
			zap.String("path", secretPath))
	} else if exists {
		existing, err = m.backend.Get(ctx, secretPath)
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
	if err := m.backend.Put(ctx, secretPath, existing); err != nil {
		logger.Error("Failed to store secret",
			zap.Error(err),
			zap.String("service", serviceName),
			zap.String("secret", secretName))
		return fmt.Errorf("failed to store secret '%s' for service '%s': %w", secretName, serviceName, err)
	}

	// INTERVENE - Store metadata (ONLY if backend supports it)
	if m.backend.SupportsMetadata() {
		// Add timestamp if not provided
		if metadata.CreatedAt == "" {
			metadata.CreatedAt = fmt.Sprintf("%d", time.Now().Unix())
		}

		// Convert our SecretMetadata to store.Metadata format
		storeMetadata := &Metadata{
			TTL:         metadata.TTL,
			CreatedBy:   metadata.CreatedBy,
			CreatedAt:   metadata.CreatedAt,
			Purpose:     metadata.Purpose,
			Owner:       metadata.Owner,
			RotateAfter: metadata.RotateAfter,
			Custom:      make(map[string]string),
		}
		// Add custom fields
		for k, v := range metadata.Custom {
			storeMetadata.Custom["custom_"+k] = v
		}

		if err := m.backend.PutMetadata(ctx, secretPath, storeMetadata); err != nil {
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
		logger.Debug("Skipping metadata storage (backend doesn't support it)",
			zap.String("backend", m.backend.Name()))
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
//	value, metadata, err := secretManager.GetSecretWithMetadata(ctx, "bionicgpt", "azure_api_key")
//	if err != nil {
//		return err
//	}
//	fmt.Printf("API Key TTL: %s\n", metadata.TTL)
func (m *Manager) GetSecretWithMetadata(ctx context.Context, serviceName, secretName string) (string, *SecretMetadata, error) {
	logger := otelzap.Ctx(ctx)

	// Get the secret value first
	value, err := m.GetSecret(ctx, serviceName, secretName)
	if err != nil {
		return "", nil, err
	}

	// Try to get metadata (only if backend supports it)
	metadata := &SecretMetadata{}
	if m.backend.SupportsMetadata() {
		secretPath := fmt.Sprintf("services/%s/%s", m.env.Environment, serviceName)
		storeMetadata, err := m.backend.GetMetadata(ctx, secretPath)
		if err != nil {
			logger.Debug("Could not retrieve secret metadata (non-critical)",
				zap.Error(err),
				zap.String("service", serviceName),
				zap.String("secret", secretName))
			// Return empty metadata, not an error
		} else if storeMetadata != nil {
			// Convert store.Metadata to our SecretMetadata
			metadata.TTL = storeMetadata.TTL
			metadata.CreatedBy = storeMetadata.CreatedBy
			metadata.CreatedAt = storeMetadata.CreatedAt
			metadata.Purpose = storeMetadata.Purpose
			metadata.Owner = storeMetadata.Owner
			metadata.RotateAfter = storeMetadata.RotateAfter

			// Extract custom fields
			metadata.Custom = make(map[string]string)
			for k, v := range storeMetadata.Custom {
				if strings.HasPrefix(k, "custom_") {
					metadata.Custom[strings.TrimPrefix(k, "custom_")] = v
				}
			}
		}
	}

	return value, metadata, nil
}

// DeleteSecret removes a single secret from a service's secret bundle
// This is an atomic operation - only the specified secret is removed, others are preserved.
//
// Example:
//
//	err := secretManager.DeleteSecret(ctx, "bionicgpt", "old_api_key")
func (m *Manager) DeleteSecret(ctx context.Context, serviceName, secretName string) error {
	logger := otelzap.Ctx(ctx)

	secretPath := fmt.Sprintf("services/%s/%s", m.env.Environment, serviceName)

	logger.Info("Deleting secret",
		zap.String("service", serviceName),
		zap.String("secret", secretName),
		zap.String("environment", m.env.Environment),
		zap.String("path", secretPath))

	// ASSESS - Check if service secrets exist
	exists, err := m.backend.Exists(ctx, secretPath)
	if err != nil {
		return fmt.Errorf("failed to check if secrets exist for service '%s': %w", serviceName, err)
	}
	if !exists {
		return fmt.Errorf("no secrets found for service '%s' in environment '%s'", serviceName, m.env.Environment)
	}

	// Retrieve all secrets
	secrets, err := m.backend.Get(ctx, secretPath)
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
	if err := m.backend.Put(ctx, secretPath, secrets); err != nil {
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
//	secretNames, err := secretManager.ListSecrets(ctx, "bionicgpt")
//	// Returns: ["azure_api_key", "postgres_password", "jwt_secret"]
func (m *Manager) ListSecrets(ctx context.Context, serviceName string) ([]string, error) {
	logger := otelzap.Ctx(ctx)

	secretPath := fmt.Sprintf("services/%s/%s", m.env.Environment, serviceName)

	logger.Debug("Listing secrets",
		zap.String("service", serviceName),
		zap.String("environment", m.env.Environment),
		zap.String("path", secretPath))

	// ASSESS - Check if service secrets exist
	exists, err := m.backend.Exists(ctx, secretPath)
	if err != nil {
		logger.Warn("Failed to check if secrets exist",
			zap.Error(err),
			zap.String("service", serviceName))
		return []string{}, nil // Return empty list on error (graceful degradation)
	}
	if !exists {
		logger.Debug("No secrets found for service",
			zap.String("service", serviceName),
			zap.String("environment", m.env.Environment))
		return []string{}, nil // No secrets = empty list (not an error)
	}

	// Retrieve all secrets
	secrets, err := m.backend.Get(ctx, secretPath)
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
//	if secretManager.SecretExists(ctx, "bionicgpt", "azure_api_key") {
//		// Secret exists, safe to update
//	}
func (m *Manager) SecretExists(ctx context.Context, serviceName, secretName string) bool {
	logger := otelzap.Ctx(ctx)

	secretPath := fmt.Sprintf("services/%s/%s", m.env.Environment, serviceName)

	// Check if service has any secrets
	exists, err := m.backend.Exists(ctx, secretPath)
	if err != nil || !exists {
		return false
	}

	// Retrieve all secrets to check for specific key
	secrets, err := m.backend.Get(ctx, secretPath)
	if err != nil {
		logger.Debug("Failed to retrieve secrets while checking existence",
			zap.Error(err),
			zap.String("service", serviceName),
			zap.String("secret", secretName))
		return false
	}

	_, exists = secrets[secretName]
	return exists
}

// GetBackend returns the secret backend for direct access (for advanced use cases)
// Most code should use StoreSecret/GetSecret instead
// DEPRECATED: Direct backend access will be removed in Eos v2.0.0
func (m *Manager) GetBackend() SecretStore {
	return m.backend
}
