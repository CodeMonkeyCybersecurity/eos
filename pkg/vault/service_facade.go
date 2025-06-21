// Package vault provides backward compatibility facade for the new clean architecture
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	domain "github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	infra "github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceFacade provides a backward-compatible interface to the new vault architecture
type ServiceFacade struct {
	vaultService  *domain.Service
	secretStore   domain.SecretStore
	client        *api.Client
	logger        *zap.Logger
	initialized   bool
	mu            sync.RWMutex
}

var (
	// Global service facade for backward compatibility
	globalFacade *ServiceFacade
	facadeMutex  sync.RWMutex
)

// InitializeServiceFacade initializes the global service facade
func InitializeServiceFacade(rc *eos_io.RuntimeContext) error {
	facadeMutex.Lock()
	defer facadeMutex.Unlock()

	if globalFacade != nil && globalFacade.initialized {
		return nil // Already initialized
	}

	logger := otelzap.Ctx(rc.Ctx)

	// Create vault client
	client, err := NewClient(rc)
	if err != nil {
		logger.Warn("Failed to create vault client, using fallback only", zap.Error(err))
	}

	// Extract zap logger from otelzap wrapper
	zapLogger := logger.ZapLogger()

	// Create secret stores
	var primaryStore domain.SecretStore
	if client != nil {
		primaryStore = infra.NewAPISecretStore(client, shared.VaultMountKV, zapLogger)
	}

	fallbackStore := infra.NewFallbackSecretStore(shared.SecretsDir, zapLogger)

	// Create composite store
	var secretStore domain.SecretStore
	if primaryStore != nil {
		secretStore = infra.NewCompositeSecretStore(primaryStore, fallbackStore, zapLogger)
	} else {
		secretStore = fallbackStore
	}

	// Create domain service (using nil for unimplemented interfaces for now)
	// TODO: Implement remaining interfaces as we migrate more functionality
	vaultService := domain.NewService(
		secretStore,
		nil, // authenticator - implement as needed
		nil, // manager - implement as needed  
		nil, // configRepo - implement as needed
		nil, // auditRepo - implement as needed
		zapLogger,
	)

	globalFacade = &ServiceFacade{
		vaultService: vaultService,
		secretStore:  secretStore,
		client:       client,
		logger:       zapLogger,
		initialized:  true,
	}

	logger.Info("Vault service facade initialized", 
		zap.Bool("has_vault_client", client != nil))

	return nil
}

// GetServiceFacade returns the global service facade
func GetServiceFacade() *ServiceFacade {
	facadeMutex.RLock()
	defer facadeMutex.RUnlock()
	return globalFacade
}

// GetSecretCompat provides backward compatibility for the old Get function
func GetSecretCompat(key string) (string, error) {
	facade := GetServiceFacade()
	if facade == nil || !facade.initialized {
		// Fallback to old behavior
		return Get(key)
	}

	ctx := context.Background()
	secret, err := facade.secretStore.Get(ctx, key)
	if err != nil {
		return "", err
	}

	return secret.Value, nil
}

// SetSecretCompat provides a new function for setting secrets
func SetSecretCompat(key, value string) error {
	facade := GetServiceFacade()
	if facade == nil || !facade.initialized {
		return fmt.Errorf("vault service facade not initialized")
	}

	ctx := context.Background()
	secret := &domain.Secret{
		Key:   key,
		Value: value,
	}

	return facade.secretStore.Set(ctx, key, secret)
}

// ReadCompat provides backward compatibility for the Read function
func ReadCompat(rc *eos_io.RuntimeContext, client *api.Client, name string, out any) error {
	// First try the new architecture
	facade := GetServiceFacade()
	if facade != nil && facade.initialized {
		secret, err := facade.secretStore.Get(rc.Ctx, name)
		if err == nil {
			// Try to unmarshal the secret value into out
			if jsonStr := secret.Value; jsonStr != "" {
				return unmarshalSecretValue(jsonStr, out)
			}
		}
		// If new architecture fails, fall back to old method
		facade.logger.Debug("New architecture failed, falling back to old Read method", 
			zap.String("name", name), 
			zap.Error(err))
	}

	// Fallback to original Read function
	return Read(rc, client, name, out)
}

// GetDomainService returns the domain service for advanced usage
func (f *ServiceFacade) GetDomainService() *domain.Service {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.vaultService
}

// GetSecretStore returns the secret store for direct access
func (f *ServiceFacade) GetSecretStore() domain.SecretStore {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.secretStore
}

// GetVaultClient returns the vault client for legacy usage
func (f *ServiceFacade) GetVaultClient() *api.Client {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.client
}

// IsInitialized returns whether the facade is initialized
func (f *ServiceFacade) IsInitialized() bool {
	if f == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.initialized
}

// HealthCheck performs a health check on the vault service
func (f *ServiceFacade) HealthCheck(ctx context.Context) error {
	if !f.IsInitialized() {
		return fmt.Errorf("vault service facade not initialized")
	}

	// Try to check if a test secret exists
	exists, err := f.secretStore.Exists(ctx, "__health_check__")
	f.logger.Debug("Vault health check completed", 
		zap.Bool("exists_check_passed", err == nil),
		zap.Bool("test_secret_exists", exists),
		zap.Error(err))

	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	return nil
}

// Helper function to unmarshal secret values
func unmarshalSecretValue(jsonStr string, out any) error {
	// This is a placeholder - implement based on how secrets are stored
	// For now, assume it's JSON stored in the value field
	return json.Unmarshal([]byte(jsonStr), out)
}

// Migration helper functions

// MigrateToNewArchitecture helps migrate existing vault usage to new architecture
func MigrateToNewArchitecture(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting migration to new vault architecture")

	// Initialize the new service facade
	if err := InitializeServiceFacade(rc); err != nil {
		return fmt.Errorf("failed to initialize service facade: %w", err)
	}

	facade := GetServiceFacade()
	if facade == nil {
		return fmt.Errorf("service facade not available after initialization")
	}

	// Perform health check
	if err := facade.HealthCheck(rc.Ctx); err != nil {
		logger.Warn("Vault health check failed, but facade is initialized", zap.Error(err))
	}

	logger.Info("Migration to new vault architecture completed")
	return nil
}

// GetSecretWithFallback provides a transition function that tries new architecture first
func GetSecretWithFallback(rc *eos_io.RuntimeContext, key string) (string, error) {
	// Try new architecture first
	facade := GetServiceFacade()
	if facade != nil && facade.IsInitialized() {
		secret, err := facade.secretStore.Get(rc.Ctx, key)
		if err == nil {
			facade.logger.Debug("Secret retrieved using new architecture", zap.String("key", key))
			return secret.Value, nil
		}
		facade.logger.Debug("New architecture failed, falling back to old method", 
			zap.String("key", key), 
			zap.Error(err))
	}

	// Fallback to old function
	return Get(key)
}

// SetSecretWithMigration sets a secret using new architecture and syncs to old if needed
func SetSecretWithMigration(rc *eos_io.RuntimeContext, key, value string) error {
	facade := GetServiceFacade()
	if facade == nil || !facade.IsInitialized() {
		return fmt.Errorf("vault service facade not initialized")
	}

	secret := &domain.Secret{
		Key:   key,
		Value: value,
	}

	err := facade.secretStore.Set(rc.Ctx, key, secret)
	if err != nil {
		facade.logger.Error("Failed to set secret using new architecture", 
			zap.String("key", key), 
			zap.Error(err))
		return err
	}

	facade.logger.Debug("Secret set successfully using new architecture", zap.String("key", key))
	return nil
}