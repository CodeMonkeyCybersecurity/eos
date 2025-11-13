// Package vault provides simplified vault operations replacing the complex facade pattern
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceFacade provides simplified vault operations (replacing complex domain layer)
type ServiceFacade struct {
	client      *api.Client
	logger      *zap.Logger
	initialized bool
	mu          sync.RWMutex
}

var (
	// Global service facade for backward compatibility
	globalFacade *ServiceFacade
	facadeMutex  sync.RWMutex
)

// InitializeServiceFacade initializes the global service facade with simplified architecture
func InitializeServiceFacade(rc *eos_io.RuntimeContext) error {
	facadeMutex.Lock()
	defer facadeMutex.Unlock()

	if globalFacade != nil && globalFacade.initialized {
		return nil // Already initialized
	}

	logger := otelzap.Ctx(rc.Ctx)

	// Create vault client using admin authentication (HashiCorp best practice)
	// During initial setup, this will fallback to root token if admin AppRole not yet configured
	client, err := GetAdminClient(rc)
	if err != nil {
		logger.Warn("Failed to create vault client, operations will be limited", zap.Error(err))
	}

	// Extract zap logger from otelzap wrapper
	zapLogger := logger.ZapLogger()

	globalFacade = &ServiceFacade{
		client:      client,
		logger:      zapLogger,
		initialized: true,
	}

	logger.Info("Service facade initialized with simplified architecture")
	return nil
}

// GetServiceFacade returns the global service facade
func GetServiceFacade() *ServiceFacade {
	facadeMutex.RLock()
	defer facadeMutex.RUnlock()
	return globalFacade
}

// NewServiceFacade creates a new service facade instance
func NewServiceFacade(rc *eos_io.RuntimeContext) (*ServiceFacade, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Use admin client (HashiCorp best practice)
	// During initial setup, this will fallback to root token if admin AppRole not yet configured
	client, err := GetAdminClient(rc)
	if err != nil {
		logger.Warn("Failed to create vault client", zap.Error(err))
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	return &ServiceFacade{
		client:      client,
		logger:      logger.ZapLogger(),
		initialized: true,
	}, nil
}

// GetVaultClient returns the underlying vault client
func (f *ServiceFacade) GetVaultClient() *api.Client {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.client
}

// IsInitialized returns whether the facade is initialized
func (f *ServiceFacade) IsInitialized() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.initialized
}

// StoreSecret stores a secret using simplified vault operations
func (f *ServiceFacade) StoreSecret(ctx context.Context, path string, data map[string]interface{}) error {
	f.mu.RLock()
	client := f.client
	f.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("vault client not available")
	}

	// Use existing vault write functionality
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		f.logger.Error("Failed to store secret", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("failed to store secret: %w", err)
	}

	f.logger.Info("Secret stored successfully", zap.String("path", path))
	return nil
}

// RetrieveSecret retrieves a secret using simplified vault operations
func (f *ServiceFacade) RetrieveSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	f.mu.RLock()
	client := f.client
	f.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("vault client not available")
	}

	// Use existing vault read functionality
	secret, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		f.logger.Error("Failed to retrieve secret", zap.String("path", path), zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve secret: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", path)
	}

	f.logger.Debug("Secret retrieved successfully", zap.String("path", path))
	return secret.Data, nil
}

// DeleteSecret deletes a secret using simplified vault operations
func (f *ServiceFacade) DeleteSecret(ctx context.Context, path string) error {
	f.mu.RLock()
	client := f.client
	f.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("vault client not available")
	}

	// Use existing vault delete functionality
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		f.logger.Error("Failed to delete secret", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	f.logger.Info("Secret deleted successfully", zap.String("path", path))
	return nil
}

// ListSecrets lists secrets at a path using simplified vault operations
func (f *ServiceFacade) ListSecrets(ctx context.Context, path string) ([]string, error) {
	f.mu.RLock()
	client := f.client
	f.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("vault client not available")
	}

	// Use existing vault list functionality
	secret, err := client.Logical().ListWithContext(ctx, path)
	if err != nil {
		f.logger.Error("Failed to list secrets", zap.String("path", path), zap.Error(err))
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	// Extract keys from vault response
	if keys, ok := secret.Data["keys"].([]interface{}); ok {
		var result []string
		for _, key := range keys {
			if keyStr, ok := key.(string); ok {
				result = append(result, keyStr)
			}
		}
		return result, nil
	}

	return []string{}, nil
}

// ReadCompat provides backward compatibility for the old ReadCompat function
func ReadCompat(rc *eos_io.RuntimeContext, client *api.Client, name string, out any) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Use existing vault read functionality with KV v2 support
	secret, err := client.Logical().ReadWithContext(rc.Ctx, "secret/data/"+name)
	if err != nil {
		logger.Error("Failed to read from vault", zap.String("path", name), zap.Error(err))
		return fmt.Errorf("failed to read from vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("secret not found: %s", name)
	}

	// Handle KV v2 format
	var data map[string]interface{}
	if dataField, ok := secret.Data["data"]; ok {
		data = dataField.(map[string]interface{})
	} else {
		data = secret.Data
	}

	// Marshal to JSON and unmarshal to target type
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	if err := json.Unmarshal(jsonData, out); err != nil {
		return fmt.Errorf("failed to unmarshal secret data: %w", err)
	}

	logger.Debug("Secret read successfully", zap.String("path", name))
	return nil
}

// Backward compatibility functions that were in the old facade

// GetSecretStore returns a simple message indicating the new simplified approach
func (f *ServiceFacade) GetSecretStore() string {
	return "simplified_vault_operations"
}

// GetDomainService returns nil since we've removed the domain layer
func (f *ServiceFacade) GetDomainService() interface{} {
	return nil
}

// Helper function to maintain compatibility
func (f *ServiceFacade) CreateSecret(path string, data map[string]interface{}) error {
	return f.StoreSecret(context.Background(), path, data)
}
