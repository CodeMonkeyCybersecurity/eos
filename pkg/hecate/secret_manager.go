package hecate

import (
	"bufio"
	"context"
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
	SecretBackendVault      SecretBackend = "vault"
	SecretBackendSaltPillar SecretBackend = "salt-pillar"
	SecretBackendUnknown    SecretBackend = "unknown"
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
	os.Setenv("VAULT_ADDR", vaultAddr)
	defer func() {
		if oldVaultAddr != "" {
			os.Setenv("VAULT_ADDR", oldVaultAddr)
		} else {
			os.Unsetenv("VAULT_ADDR")
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
	
	logger.Debug("Vault not available, using Salt pillar fallback", zap.Error(err))
	
	// Use Salt pillar as fallback
	return SecretBackendSaltPillar, nil
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
	case SecretBackendSaltPillar:
		return sm.getSaltSecret(service, key)
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
	os.Setenv("VAULT_ADDR", vaultAddr)
	defer func() {
		if oldVaultAddr != "" {
			os.Setenv("VAULT_ADDR", oldVaultAddr)
		} else {
			os.Unsetenv("VAULT_ADDR")
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

// getSaltSecret retrieves a secret from Salt pillar files
func (sm *SecretManager) getSaltSecret(service, key string) (string, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)
	
	var envFile, envKey string
	
	switch service {
	case "postgres":
		envFile = "/opt/hecate/secrets/postgres.env"
		switch key {
		case "password":
			envKey = "POSTGRES_PASSWORD"
		case "root_password":
			envKey = "POSTGRES_ROOT_PASSWORD"
		default:
			return "", fmt.Errorf("unknown postgres secret key: %s", key)
		}
	case "redis":
		envFile = "/opt/hecate/secrets/redis.env"
		switch key {
		case "password":
			envKey = "REDIS_PASSWORD"
		default:
			return "", fmt.Errorf("unknown redis secret key: %s", key)
		}
	case "authentik":
		envFile = "/opt/hecate/secrets/authentik.env"
		switch key {
		case "secret_key":
			envKey = "AUTHENTIK_SECRET_KEY"
		case "admin_password":
			envKey = "AUTHENTIK_ADMIN_PASSWORD"
		case "admin_username":
			envKey = "AUTHENTIK_ADMIN_USERNAME"
		default:
			return "", fmt.Errorf("unknown authentik secret key: %s", key)
		}
	case "dns":
		envFile = "/opt/hecate/secrets/dns.env"
		// DNS provider tokens use the key as-is in uppercase
		envKey = strings.ToUpper(strings.ReplaceAll(key, "_", "_"))
		if envKey == "" {
			return "", fmt.Errorf("invalid DNS secret key: %s", key)
		}
	default:
		return "", fmt.Errorf("unknown service: %s", service)
	}
	
	logger.Debug("Retrieving secret from Salt pillar file", 
		zap.String("file", envFile), 
		zap.String("key", envKey))
	
	// Read the environment file
	file, err := os.Open(envFile)
	if err != nil {
		return "", fmt.Errorf("failed to open secret file %s: %w", envFile, err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, envKey+"=") {
			value := strings.TrimPrefix(line, envKey+"=")
			return value, nil
		}
	}
	
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading secret file: %w", err)
	}
	
	return "", fmt.Errorf("secret key %s not found in %s", envKey, envFile)
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
	case SecretBackendSaltPillar:
		return sm.generateSaltSecrets()
	default:
		return fmt.Errorf("cannot generate secrets with backend: %s", sm.backend)
	}
}

// generateVaultSecrets creates secrets in Vault
func (sm *SecretManager) generateVaultSecrets() error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Generating secrets in Vault")
	
	// Apply the existing vault_secrets Salt state
	_, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"state.apply", "hecate.vault_secrets"},
		Capture: false, // Show output to user
	})
	
	if err != nil {
		return fmt.Errorf("failed to generate Vault secrets: %w", err)
	}
	
	logger.Info("Vault secrets generated successfully")
	return nil
}

// generateSaltSecrets creates secrets using Salt pillar
func (sm *SecretManager) generateSaltSecrets() error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Generating secrets using Salt pillar")
	
	// Apply the hybrid_secrets Salt state with pillar mode
	_, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"state.apply", "hecate.hybrid_secrets", "--pillar-root=/opt/eos/salt/pillar"},
		Capture: false, // Show output to user
	})
	
	if err != nil {
		return fmt.Errorf("failed to generate Salt pillar secrets: %w", err)
	}
	
	logger.Info("Salt pillar secrets generated successfully")
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