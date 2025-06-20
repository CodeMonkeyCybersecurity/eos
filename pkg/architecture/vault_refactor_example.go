// Package architecture - Concrete Vault Package Refactoring Example
package architecture

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// This file demonstrates how to refactor the current pkg/vault package
// using clean architecture principles

// CURRENT PROBLEMS IN pkg/vault:
// 1. 50+ dependencies in auth.go
// 2. Mixed concerns (business logic + infrastructure + presentation)
// 3. Direct file system access throughout
// 4. Hard to test due to external dependencies
// 5. No clear separation between vault operations and system operations

// SOLUTION: Clean Architecture Refactoring

// ==============================================================================
// DOMAIN LAYER - Business Logic (No External Dependencies)
// ==============================================================================

// VaultDomainService contains pure business logic for vault operations
type VaultDomainService struct {
	secretStore SecretStore
	auditRepo   AuditRepository
	logger      *zap.Logger
}

// NewVaultDomainService creates a new vault domain service
func NewVaultDomainService(store SecretStore, audit AuditRepository, logger *zap.Logger) *VaultDomainService {
	return &VaultDomainService{
		secretStore: store,
		auditRepo:   audit,
		logger:      logger,
	}
}

// AuthenticateUser handles user authentication business logic
func (v *VaultDomainService) AuthenticateUser(ctx context.Context, userID, method string) (*AuthenticationResult, error) {
	start := time.Now()

	// Business validation
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}
	if method == "" {
		return nil, fmt.Errorf("authentication method is required")
	}

	// Check if user has valid token
	tokenSecret, err := v.secretStore.Get(ctx, fmt.Sprintf("auth/tokens/%s", userID))
	if err != nil {
		v.logger.Error("Failed to get user token", zap.String("user", userID), zap.Error(err))
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	result := &AuthenticationResult{
		UserID:      userID,
		Method:      method,
		Success:     tokenSecret != nil && tokenSecret.Value != "",
		Timestamp:   time.Now(),
		TokenExpiry: time.Now().Add(24 * time.Hour), // Business rule: 24h expiry
	}

	// Audit the authentication attempt
	_ = v.auditRepo.Record(ctx, &AuditEvent{
		ID:        generateID(),
		Timestamp: time.Now(),
		User:      userID,
		Action:    "vault.auth",
		Resource:  fmt.Sprintf("user:%s", userID),
		Details: map[string]string{
			"method":   method,
			"duration": time.Since(start).String(),
		},
		Result: func() string {
			if result.Success {
				return "success"
			}
			return "failure"
		}(),
	})

	v.logger.Info("Authentication attempt completed",
		zap.String("user", userID),
		zap.String("method", method),
		zap.Bool("success", result.Success),
	)

	return result, nil
}

// InitializeVault handles vault initialization business logic
func (v *VaultDomainService) InitializeVault(ctx context.Context, adminUserID string, config *VaultInitConfig) (*VaultInitResult, error) {
	// Business validation
	if err := v.validateInitConfig(config); err != nil {
		return nil, fmt.Errorf("invalid init config: %w", err)
	}

	// Store root token securely
	rootSecret := &Secret{
		Key:      "root_token",
		Value:    config.RootToken,
		Metadata: map[string]string{
			"initialized_by": adminUserID,
			"vault_version": config.VaultVersion,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := v.secretStore.Set(ctx, rootSecret.Key, rootSecret); err != nil {
		return nil, fmt.Errorf("failed to store root token: %w", err)
	}

	// Store unseal keys
	for i, key := range config.UnsealKeys {
		unsealSecret := &Secret{
			Key:   fmt.Sprintf("unseal_key_%d", i+1),
			Value: key,
			Metadata: map[string]string{
				"key_index": fmt.Sprintf("%d", i+1),
				"threshold": fmt.Sprintf("%d", config.SecretThreshold),
			},
			CreatedAt: time.Now(),
		}

		if err := v.secretStore.Set(ctx, unsealSecret.Key, unsealSecret); err != nil {
			v.logger.Error("Failed to store unseal key", zap.Int("key_index", i+1), zap.Error(err))
			return nil, fmt.Errorf("failed to store unseal key %d: %w", i+1, err)
		}
	}

	result := &VaultInitResult{
		Initialized:     true,
		SecretShares:    len(config.UnsealKeys),
		SecretThreshold: config.SecretThreshold,
		Timestamp:       time.Now(),
	}

	v.logger.Info("Vault initialization completed",
		zap.String("admin_user", adminUserID),
		zap.Int("secret_shares", result.SecretShares),
		zap.Int("threshold", result.SecretThreshold),
	)

	return result, nil
}

// validateInitConfig validates vault initialization configuration
func (v *VaultDomainService) validateInitConfig(config *VaultInitConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if config.RootToken == "" {
		return fmt.Errorf("root token is required")
	}
	if len(config.UnsealKeys) == 0 {
		return fmt.Errorf("unseal keys are required")
	}
	if config.SecretThreshold <= 0 || config.SecretThreshold > len(config.UnsealKeys) {
		return fmt.Errorf("invalid secret threshold: must be between 1 and %d", len(config.UnsealKeys))
	}
	return nil
}

// ==============================================================================
// INFRASTRUCTURE LAYER - External Dependencies
// ==============================================================================

// VaultAPISecretStore implements SecretStore using HashiCorp Vault API
type VaultAPISecretStore struct {
	client *api.Client
	logger *zap.Logger
}

// NewVaultAPISecretStore creates a vault secret store
func NewVaultAPISecretStore(client *api.Client, logger *zap.Logger) *VaultAPISecretStore {
	return &VaultAPISecretStore{
		client: client,
		logger: logger,
	}
}

// Get implements SecretStore interface
func (v *VaultAPISecretStore) Get(ctx context.Context, key string) (*Secret, error) {
	// Sanitize key for vault path
	path := v.sanitizePath(key)

	secret, err := v.client.KVv2("secret").Get(ctx, path)
	if err != nil {
		v.logger.Error("Failed to get secret from vault", zap.String("path", path), zap.Error(err))
		return nil, fmt.Errorf("vault get failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	value, ok := secret.Data["value"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid secret format for key: %s", key)
	}

	domainSecret := &Secret{
		Key:       key,
		Value:     value,
		Metadata:  make(map[string]string),
		CreatedAt: secret.CreatedTime,
		UpdatedAt: secret.CreatedTime, // Vault KV doesn't track separate update time
	}

	// Convert vault metadata to domain metadata
	for k, v := range secret.Data {
		if k != "value" {
			if str, ok := v.(string); ok {
				domainSecret.Metadata[k] = str
			}
		}
	}

	return domainSecret, nil
}

// Set implements SecretStore interface
func (v *VaultAPISecretStore) Set(ctx context.Context, key string, secret *Secret) error {
	path := v.sanitizePath(key)

	// Prepare vault data
	data := map[string]interface{}{
		"value": secret.Value,
	}

	// Add metadata
	for k, v := range secret.Metadata {
		data[k] = v
	}

	_, err := v.client.KVv2("secret").Put(ctx, path, data)
	if err != nil {
		v.logger.Error("Failed to set secret in vault", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("vault set failed: %w", err)
	}

	v.logger.Debug("Secret stored in vault", zap.String("path", path))
	return nil
}

// Delete implements SecretStore interface
func (v *VaultAPISecretStore) Delete(ctx context.Context, key string) error {
	path := v.sanitizePath(key)

	err := v.client.KVv2("secret").DeleteMetadata(ctx, path)
	if err != nil {
		v.logger.Error("Failed to delete secret from vault", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("vault delete failed: %w", err)
	}

	v.logger.Debug("Secret deleted from vault", zap.String("path", path))
	return nil
}

// List implements SecretStore interface
func (v *VaultAPISecretStore) List(ctx context.Context, prefix string) ([]*Secret, error) {
	path := v.sanitizePath(prefix)

	secretList, err := v.client.KVv2("secret").List(ctx, path)
	if err != nil {
		v.logger.Error("Failed to list secrets from vault", zap.String("path", path), zap.Error(err))
		return nil, fmt.Errorf("vault list failed: %w", err)
	}

	var secrets []*Secret
	if secretList != nil && secretList.Data != nil {
		if keys, ok := secretList.Data["keys"].([]interface{}); ok {
			for _, keyInterface := range keys {
				if keyStr, ok := keyInterface.(string); ok {
					fullKey := fmt.Sprintf("%s/%s", prefix, keyStr)
					// Get full secret data
					secret, err := v.Get(ctx, fullKey)
					if err != nil {
						v.logger.Warn("Failed to get secret during list", zap.String("key", fullKey), zap.Error(err))
						continue
					}
					secrets = append(secrets, secret)
				}
			}
		}
	}

	return secrets, nil
}

// sanitizePath converts domain key to vault path
func (v *VaultAPISecretStore) sanitizePath(key string) string {
	// Remove any dangerous characters and normalize path
	path := strings.ReplaceAll(key, "..", "")
	path = strings.ReplaceAll(path, "//", "/")
	path = strings.Trim(path, "/")
	return path
}

// FallbackSecretStore implements SecretStore using environment variables
// This is used when vault is not available
type FallbackSecretStore struct {
	logger *zap.Logger
}

// NewFallbackSecretStore creates a fallback secret store
func NewFallbackSecretStore(logger *zap.Logger) *FallbackSecretStore {
	return &FallbackSecretStore{
		logger: logger,
	}
}

// Get implements SecretStore interface using environment variables
func (f *FallbackSecretStore) Get(ctx context.Context, key string) (*Secret, error) {
	envVar := "EOS_SECRET_" + f.sanitizeKey(key)
	value := os.Getenv(envVar)

	if value == "" {
		f.logger.Warn("Secret not found in environment", zap.String("key", key), zap.String("env_var", envVar))
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	secret := &Secret{
		Key:   key,
		Value: value,
		Metadata: map[string]string{
			"source": "environment",
		},
		CreatedAt: time.Now(), // We don't know actual creation time
		UpdatedAt: time.Now(),
	}

	f.logger.Debug("Secret retrieved from environment", zap.String("key", key))
	return secret, nil
}

// Set implements SecretStore interface (not supported for environment)
func (f *FallbackSecretStore) Set(ctx context.Context, key string, secret *Secret) error {
	return fmt.Errorf("setting secrets not supported in fallback mode")
}

// Delete implements SecretStore interface (not supported for environment)
func (f *FallbackSecretStore) Delete(ctx context.Context, key string) error {
	return fmt.Errorf("deleting secrets not supported in fallback mode")
}

// List implements SecretStore interface (not supported for environment)
func (f *FallbackSecretStore) List(ctx context.Context, prefix string) ([]*Secret, error) {
	return nil, fmt.Errorf("listing secrets not supported in fallback mode")
}

// sanitizeKey converts key to environment variable format
func (f *FallbackSecretStore) sanitizeKey(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, "/", "_"))
}

// ==============================================================================
// DOMAIN ENTITIES (Clean, no external dependencies)
// ==============================================================================

// AuthenticationResult represents the result of an authentication attempt
type AuthenticationResult struct {
	UserID      string    `json:"user_id"`
	Method      string    `json:"method"`
	Success     bool      `json:"success"`
	Timestamp   time.Time `json:"timestamp"`
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
	ErrorReason string    `json:"error_reason,omitempty"`
}

// VaultInitConfig represents vault initialization parameters
type VaultInitConfig struct {
	RootToken       string   `json:"-"` // Never serialize
	UnsealKeys      []string `json:"-"` // Never serialize
	SecretShares    int      `json:"secret_shares"`
	SecretThreshold int      `json:"secret_threshold"`
	VaultVersion    string   `json:"vault_version,omitempty"`
}

// VaultInitResult represents the result of vault initialization
type VaultInitResult struct {
	Initialized     bool      `json:"initialized"`
	SecretShares    int       `json:"secret_shares"`
	SecretThreshold int       `json:"secret_threshold"`
	Timestamp       time.Time `json:"timestamp"`
}

// ==============================================================================
// USAGE EXAMPLE - How the refactored code would be used
// ==============================================================================

// RefactoredVaultExample shows how to use the clean architecture
func RefactoredVaultExample(ctx context.Context, vaultClient *api.Client, logger *zap.Logger) error {
	// 1. Create infrastructure implementations
	vaultStore := NewVaultAPISecretStore(vaultClient, logger)
	fallbackStore := NewFallbackSecretStore(logger)
	
	// 2. Create composite store that tries vault first, falls back to env
	compositeStore := &CompositeSecretStore{
		primary:   vaultStore,
		fallback:  fallbackStore,
		logger:    logger,
	}
	
	// 3. Create audit repository (implementation not shown)
	auditRepo := &FileAuditRepository{logger: logger}
	
	// 4. Create domain service
	vaultService := NewVaultDomainService(compositeStore, auditRepo, logger)
	
	// 5. Use domain service for business operations
	authResult, err := vaultService.AuthenticateUser(ctx, "admin", "userpass")
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	
	logger.Info("Authentication completed",
		zap.String("user", authResult.UserID),
		zap.Bool("success", authResult.Success),
	)
	
	return nil
}

// CompositeSecretStore tries vault first, falls back to environment
type CompositeSecretStore struct {
	primary  SecretStore
	fallback SecretStore
	logger   *zap.Logger
}

// Get tries primary store first, then fallback
func (c *CompositeSecretStore) Get(ctx context.Context, key string) (*Secret, error) {
	secret, err := c.primary.Get(ctx, key)
	if err != nil {
		c.logger.Warn("Primary secret store failed, trying fallback", zap.String("key", key), zap.Error(err))
		return c.fallback.Get(ctx, key)
	}
	return secret, nil
}

// Set only uses primary store
func (c *CompositeSecretStore) Set(ctx context.Context, key string, secret *Secret) error {
	return c.primary.Set(ctx, key, secret)
}

// Delete only uses primary store
func (c *CompositeSecretStore) Delete(ctx context.Context, key string) error {
	return c.primary.Delete(ctx, key)
}

// List only uses primary store
func (c *CompositeSecretStore) List(ctx context.Context, prefix string) ([]*Secret, error) {
	return c.primary.List(ctx, prefix)
}

// ==============================================================================
// BENEFITS OF THIS REFACTORING
// ==============================================================================

// 1. TESTABILITY
//    - VaultDomainService can be tested with mock stores
//    - No external dependencies in business logic
//    - Fast unit tests

// 2. MAINTAINABILITY
//    - Clear separation between business logic and infrastructure
//    - Easy to understand what each layer does
//    - Single responsibility principle

// 3. FLEXIBILITY
//    - Can swap vault implementation without changing business logic
//    - Can add new secret stores (AWS Secrets Manager, etc.)
//    - Can compose multiple stores

// 4. RELIABILITY
//    - Fallback mechanisms built-in
//    - Proper error handling at each layer
//    - Audit logging for security

// 5. PERFORMANCE
//    - Reduced dependencies = faster compilation
//    - Interface-based design allows for optimizations
//    - Clear data flow

// MIGRATION PATH:
// 1. Create these interfaces and implementations
// 2. Update one command at a time to use the new service
// 3. Gradually replace direct vault client usage
// 4. Remove old tightly-coupled code
// 5. Add comprehensive tests