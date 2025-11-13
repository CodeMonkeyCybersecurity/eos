// pkg/hecate/secret_manager.go
//
// Hecate secret management using Vault and Consul SDK.
// Migrated from shell commands to SDK calls for improved reliability.
//
// Last Updated: 2025-01-25

package hecate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	consulsdk "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/sdk"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	vaultsdk "github.com/CodeMonkeyCybersecurity/eos/pkg/vault/sdk"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
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
	backend      SecretBackend
	rc           *eos_io.RuntimeContext
	vaultClient  *vaultapi.Client
	consulClient *consulapi.Client
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

	// Initialize SDK clients based on backend
	if backend == SecretBackendVault {
		vaultClient, err := vaultsdk.NewClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %w", err)
		}
		sm.vaultClient = vaultClient
	}

	// Always create Consul client as it may be used for fallback
	consulClient, err := consulsdk.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}
	sm.consulClient = consulClient

	logger.Info("Secret manager initialized", zap.String("backend", string(backend)))

	return sm, nil
}

// detectBackend determines which secret management backend to use
func (sm *SecretManager) detectBackend() (SecretBackend, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// First try Vault
	logger.Debug("Checking Vault availability")
	vaultAddr := shared.GetVaultAddrWithEnv()

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

	// Try to create Vault client and check health using SDK with timeout
	ctx, cancel := context.WithTimeout(sm.rc.Ctx, 5*time.Second)
	defer cancel()

	vaultClient, err := vaultsdk.NewClient()
	if err == nil {
		// Check if Vault is reachable
		_, err = vaultClient.Sys().HealthWithContext(ctx)
		if err == nil {
			logger.Debug("Vault is available and accessible")
			return SecretBackendVault, nil
		}
		logger.Debug("Vault client created but health check failed", zap.Error(err))
	} else {
		logger.Debug("Failed to create Vault client", zap.Error(err))
	}

	logger.Debug("Vault not available, using Consul KV fallback")

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

// getVaultSecret retrieves a secret from Vault using SDK
func (sm *SecretManager) getVaultSecret(service, key string) (string, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

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

	// Use SDK to get the secret field
	value, err := vaultsdk.KVGetField(sm.rc.Ctx, sm.vaultClient, vaultPath, field)
	if err != nil {
		return "", fmt.Errorf("failed to get secret from Vault: %w", err)
	}

	if value == "" {
		return "", fmt.Errorf("secret field %s not found at %s", field, vaultPath)
	}

	return strings.TrimSpace(value), nil
}

// getConsulSecret retrieves a secret from HashiCorp Consul KV store using SDK
func (sm *SecretManager) getConsulSecret(service, key string) (string, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Build Consul KV path for the secret
	consulPath := fmt.Sprintf("hecate/secrets/%s/%s", service, key)

	logger.Debug("Retrieving secret from Consul KV",
		zap.String("path", consulPath),
		zap.String("service", service),
		zap.String("key", key))

	// Use SDK to retrieve the secret
	data, err := consulsdk.KVGet(sm.rc.Ctx, sm.consulClient, consulPath)
	if err != nil {
		return "", fmt.Errorf("failed to get secret from Consul KV: %w", err)
	}

	if data == nil {
		// If secret doesn't exist in Consul, provide helpful error message
		logger.Debug("Secret not found in Consul KV, may need to be stored by administrator",
			zap.String("path", consulPath))
		return "", fmt.Errorf("secret not found in Consul KV at %s - administrator may need to store this secret using: consul kv put %s <value>", consulPath, consulPath)
	}

	secretValue := strings.TrimSpace(string(data))
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

// generateConsulSecrets creates secrets using HashiCorp Consul KV SDK
func (sm *SecretManager) generateConsulSecrets() error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Generating secrets using HashiCorp Consul KV")

	// Generate secrets and store them in Consul KV
	secrets := map[string]string{
		"hecate/secrets/postgres/password":        sm.generateRandomSecret(32),
		"hecate/secrets/postgres/root_password":   sm.generateRandomSecret(32),
		"hecate/secrets/redis/password":           sm.generateRandomSecret(32),
		"hecate/secrets/authentik/secret_key":     sm.generateRandomSecret(64),
		"hecate/secrets/authentik/admin_password": sm.generateRandomSecret(16),
	}

	// Store each secret in Consul KV using SDK
	for path, value := range secrets {
		err := consulsdk.KVPut(sm.rc.Ctx, sm.consulClient, path, []byte(value))
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
