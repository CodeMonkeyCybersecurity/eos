// Package secrets provides automatic secret management across Vault, , and file backends
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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

	// Choose backend based on environment configuration
	// Use Vault as default backend (HashiCorp migration)
	switch "vault" {
	case "vault":
		backend, err = NewVaultBackend(envConfig.VaultAddr)
		if err != nil {
			logger.Warn("Vault backend failed, falling back to ", zap.Error(err))
			if err != nil {
				logger.Warn(" backend failed, falling back to file", zap.Error(err))
				backend = NewFileBackend()
			}
		}

	default:
		backend = NewFileBackend()
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

// Vault Backend Implementation
type VaultBackend struct {
	address string
	client  interface{} // Would be actual Vault client
}

func NewVaultBackend(address string) (*VaultBackend, error) {
	// Implementation would create actual Vault client
	return &VaultBackend{address: address}, nil
}

func (vb *VaultBackend) Store(path string, secret map[string]interface{}) error {
	// Implementation would store in Vault
	return fmt.Errorf("vault backend not fully implemented")
}

func (vb *VaultBackend) Retrieve(path string) (map[string]interface{}, error) {
	// Implementation would retrieve from Vault
	return nil, fmt.Errorf("vault backend not fully implemented")
}

func (vb *VaultBackend) Generate(path string, secretType SecretType) (string, error) {
	// Implementation would use Vault's secret generation
	return "", fmt.Errorf("vault backend not fully implemented")
}

func (vb *VaultBackend) Exists(path string) bool {
	// Implementation would check if path exists in Vault
	return false
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
