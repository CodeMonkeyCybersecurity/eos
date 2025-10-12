package hecate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecretBackend represents the type of secret management backend in use
type SecretBackend string

const (
	SecretBackendVault   SecretBackend = "vault"
	SecretBackendConsul  SecretBackend = "consul"
	SecretBackendUnknown SecretBackend = "unknown"
)

// SecretManager provides a unified interface for secret management
type SecretManager struct {
	backend SecretBackend
	rc      *eos_io.RuntimeContext
}

// NewSecretManager creates a new secret manager with automatic backend detection
func NewSecretManager(rc *eos_io.RuntimeContext) (*SecretManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	sm := &SecretManager{
		rc: rc,
	}

	// Detect which backend is available
	backend, err := sm.detectBackend()
	if err != nil {
		return nil, fmt.Errorf("failed to detect secret backend: %w", err)
	}

	sm.backend = backend
	logger.Info("Secret manager initialized", zap.String("backend", string(backend)))

	return sm, nil
}

// detectBackend determines which secret management backend to use
func (sm *SecretManager) detectBackend() (SecretBackend, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// First try Vault
	logger.Debug("Checking Vault availability")
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8179"
	}

	// Test Vault connectivity with timeout
	ctx, cancel := context.WithTimeout(sm.rc.Ctx, 5*time.Second)
	defer cancel()

	// Set environment variable for Vault
	oldVaultAddr := os.Getenv("VAULT_ADDR")
	_ = os.Setenv("VAULT_ADDR", vaultAddr)
	defer func() {
		if oldVaultAddr != "" {
			_ = os.Setenv("VAULT_ADDR", oldVaultAddr)
		} else {
			_ = os.Unsetenv("VAULT_ADDR")
		}
	}()

	_, err := execute.Run(ctx, execute.Options{
		Command: "vault",
		Args:    []string{"status"},
		Capture: true,
	})

	if err == nil {
		logger.Debug("Vault is available and accessible")
		return SecretBackendVault, nil
	}

	logger.Debug("Vault not available, using Consul KV fallback", zap.Error(err))

	// Use Consul KV as fallback for HashiCorp integration
	return SecretBackendConsul, nil
}

// GetSecret retrieves a secret using the configured backend
func (sm *SecretManager) GetSecret(service, key string) (string, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Debug("Retrieving secret",
		zap.String("service", service),
		zap.String("key", key),
		zap.String("backend", string(sm.backend)))

	switch sm.backend {
	case SecretBackendVault:
		return sm.getVaultSecret(service, key)
	case SecretBackendConsul:
		return sm.getConsulSecret(service, key)
	default:
		return "", fmt.Errorf("unknown secret backend: %s", sm.backend)
	}
}

// getVaultSecret retrieves a secret from Vault
func (sm *SecretManager) getVaultSecret(service, key string) (string, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8179"
	}

	var vaultPath, field string

	switch service {
	case "postgres":
		switch key {
		case "password":
			vaultPath = "secret/hecate/postgres/password"
			field = "value"
		case "root_password":
			vaultPath = "secret/hecate/postgres/root_password"
			field = "value"
		default:
			return "", fmt.Errorf("unknown postgres secret key: %s", key)
		}
	case "redis":
		switch key {
		case "password":
			vaultPath = "secret/hecate/redis/password"
			field = "value"
		default:
			return "", fmt.Errorf("unknown redis secret key: %s", key)
		}
	case "authentik":
		switch key {
		case "secret_key":
			vaultPath = "secret/hecate/authentik/secret_key"
			field = "value"
		case "admin_password":
			vaultPath = "secret/hecate/authentik/admin"
			field = "password"
		case "admin_username":
			vaultPath = "secret/hecate/authentik/admin"
			field = "username"
		default:
			return "", fmt.Errorf("unknown authentik secret key: %s", key)
		}
	case "dns":
		// DNS provider credentials
		vaultPath = fmt.Sprintf("secret/hecate/dns/%s", key)
		field = "value"
	default:
		return "", fmt.Errorf("unknown service: %s", service)
	}

	logger.Debug("Retrieving secret from Vault",
		zap.String("path", vaultPath),
		zap.String("field", field))

	// Set environment variable for Vault
	oldVaultAddr := os.Getenv("VAULT_ADDR")
	_ = os.Setenv("VAULT_ADDR", vaultAddr)
	defer func() {
		if oldVaultAddr != "" {
			_ = os.Setenv("VAULT_ADDR", oldVaultAddr)
		} else {
			_ = os.Unsetenv("VAULT_ADDR")
		}
	}()

	output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"kv", "get", "-field=" + field, vaultPath},
		Capture: true,
	})

	if err != nil {
		return "", fmt.Errorf("failed to get secret from Vault: %w", err)
	}

	return strings.TrimSpace(output), nil
}

// getConsulSecret retrieves a secret from HashiCorp Consul KV store
func (sm *SecretManager) getConsulSecret(service, key string) (string, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)
	
	// Build Consul KV path for the secret
	consulPath := fmt.Sprintf("hecate/secrets/%s/%s", service, key)
	
	logger.Debug("Retrieving secret from Consul KV",
		zap.String("path", consulPath),
		zap.String("service", service),
		zap.String("key", key))

	// Use consul command to retrieve the secret
	output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"kv", "get", consulPath},
		Capture: true,
	})

	if err != nil {
		// If secret doesn't exist in Consul, provide helpful error message
		logger.Debug("Secret not found in Consul KV, may need to be stored by administrator",
			zap.String("path", consulPath),
			zap.Error(err))
		return "", fmt.Errorf("secret not found in Consul KV at %s - administrator may need to store this secret using: consul kv put %s <value>", consulPath, consulPath)
	}

	secretValue := strings.TrimSpace(output)
	if secretValue == "" {
		return "", fmt.Errorf("empty secret value found in Consul KV at %s", consulPath)
	}

	logger.Debug("Successfully retrieved secret from Consul KV",
		zap.String("path", consulPath))

	return secretValue, nil
}

// GetBackend returns the current secret management backend
func (sm *SecretManager) GetBackend() SecretBackend {
	return sm.backend
}

// IsVaultAvailable checks if Vault is available and accessible
func (sm *SecretManager) IsVaultAvailable() bool {
	return sm.backend == SecretBackendVault
}

// GenerateSecrets triggers secret generation using the appropriate backend
func (sm *SecretManager) GenerateSecrets() error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Generating secrets", zap.String("backend", string(sm.backend)))

	switch sm.backend {
	case SecretBackendVault:
		return sm.generateVaultSecrets()
	case SecretBackendConsul:
		return sm.generateConsulSecrets()
	default:
		return fmt.Errorf("cannot generate secrets with backend: %s", sm.backend)
	}
}

// generateVaultSecrets creates secrets in Vault
func (sm *SecretManager) generateVaultSecrets() error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Generating secrets in Vault")

	// Apply the existing vault_secrets  state
	_, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "-call",
		Args:    []string{"state.apply", "hecate.vault_secrets"},
		Capture: false, // Show output to user
	})

	if err != nil {
		return fmt.Errorf("failed to generate Vault secrets: %w", err)
	}

	logger.Info("Vault secrets generated successfully")
	return nil
}

// generateConsulSecrets creates secrets using HashiCorp Consul KV
func (sm *SecretManager) generateConsulSecrets() error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Generating secrets using HashiCorp Consul KV")

	// Generate secrets and store them in Consul KV
	secrets := map[string]string{
		"hecate/secrets/postgres/password":      sm.generateRandomSecret(32),
		"hecate/secrets/postgres/root_password": sm.generateRandomSecret(32),
		"hecate/secrets/redis/password":         sm.generateRandomSecret(32),
		"hecate/secrets/authentik/secret_key":   sm.generateRandomSecret(64),
		"hecate/secrets/authentik/admin_password": sm.generateRandomSecret(16),
	}

	// Store each secret in Consul KV
	for path, value := range secrets {
		_, err := execute.Run(sm.rc.Ctx, execute.Options{
			Command: "consul",
			Args:    []string{"kv", "put", path, value},
			Capture: true,
		})
		
		if err != nil {
			logger.Error("Failed to store secret in Consul KV",
				zap.String("path", path),
				zap.Error(err))
			return fmt.Errorf("failed to store secret %s in Consul KV: %w", path, err)
		}
		
		logger.Debug("Secret stored in Consul KV", zap.String("path", path))
	}

	logger.Info("HashiCorp Consul KV secrets generated successfully",
		zap.Int("secrets_count", len(secrets)))
	return nil
}

// ValidateSecrets checks that all required secrets are available
func (sm *SecretManager) ValidateSecrets() error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Validating secrets availability")

	requiredSecrets := []struct {
		service string
		key     string
	}{
		{"postgres", "root_password"},
		{"postgres", "password"},
		{"redis", "password"},
		{"authentik", "secret_key"},
		{"authentik", "admin_password"},
		{"authentik", "admin_username"},
	}

	for _, secret := range requiredSecrets {
		_, err := sm.GetSecret(secret.service, secret.key)
		if err != nil {
			return fmt.Errorf("validation failed for %s.%s: %w", secret.service, secret.key, err)
		}
		logger.Debug("Secret validation passed",
			zap.String("service", secret.service),
			zap.String("key", secret.key))
	}

	logger.Info("All secrets validated successfully")
	return nil
}

// generateRandomSecret creates a cryptographically secure random secret
func (sm *SecretManager) generateRandomSecret(length int) string {
	// Generate random bytes
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to a deterministic but unique secret if crypto/rand fails
		logger := otelzap.Ctx(sm.rc.Ctx)
		logger.Warn("Failed to generate cryptographically secure random secret, using fallback",
			zap.Error(err))
		
		// Use timestamp-based fallback (not cryptographically secure but unique)
		fallback := fmt.Sprintf("eos-secret-%d-%d", time.Now().Unix(), length)
		if len(fallback) > length {
			return fallback[:length]
		}
		return fallback
	}
	
	// Encode to base64 and trim to desired length
	encoded := base64.URLEncoding.EncodeToString(bytes)
	if len(encoded) > length {
		return encoded[:length]
	}
	return encoded
}
