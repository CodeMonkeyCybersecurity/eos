// Package vault provides infrastructure implementations for vault domain interfaces
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
)

// FileConfigRepository implements vault.ConfigRepository using file system storage
type FileConfigRepository struct {
	configDir string
	configMap map[string]string
	mutex     sync.RWMutex
	logger    *zap.Logger
}

// NewFileConfigRepository creates a new file-based configuration repository
func NewFileConfigRepository(configDir string, logger *zap.Logger) *FileConfigRepository {
	repo := &FileConfigRepository{
		configDir: configDir,
		configMap: make(map[string]string),
		logger:    logger.Named("vault.config"),
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0750); err != nil {
		logger.Error("Failed to create config directory", 
			zap.String("dir", configDir), 
			zap.Error(err))
	}

	// Load existing configuration
	if err := repo.loadFromFile(); err != nil {
		logger.Warn("Failed to load existing configuration", zap.Error(err))
	}

	return repo
}

// GetConfig retrieves configuration by key
func (r *FileConfigRepository) GetConfig(ctx context.Context, key string) (string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	value, exists := r.configMap[key]
	if !exists {
		return "", fmt.Errorf("configuration key not found: %s", key)
	}

	r.logger.Debug("Configuration retrieved", zap.String("key", key))
	return value, nil
}

// SetConfig stores configuration
func (r *FileConfigRepository) SetConfig(ctx context.Context, key, value string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.configMap[key] = value
	
	if err := r.saveToFile(); err != nil {
		r.logger.Error("Failed to save configuration", 
			zap.String("key", key),
			zap.Error(err))
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	r.logger.Info("Configuration stored", zap.String("key", key))
	return nil
}

// GetAllConfig returns all configuration
func (r *FileConfigRepository) GetAllConfig(ctx context.Context) (map[string]string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy to prevent external modifications
	result := make(map[string]string)
	for k, v := range r.configMap {
		result[k] = v
	}

	r.logger.Debug("All configuration retrieved", zap.Int("count", len(result)))
	return result, nil
}

// DeleteConfig removes configuration
func (r *FileConfigRepository) DeleteConfig(ctx context.Context, key string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.configMap[key]; !exists {
		return fmt.Errorf("configuration key not found: %s", key)
	}

	delete(r.configMap, key)
	
	if err := r.saveToFile(); err != nil {
		r.logger.Error("Failed to save configuration after deletion", 
			zap.String("key", key),
			zap.Error(err))
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	r.logger.Info("Configuration deleted", zap.String("key", key))
	return nil
}

// loadFromFile loads configuration from the file system
func (r *FileConfigRepository) loadFromFile() error {
	configFile := filepath.Join(r.configDir, "vault-config.json")
	
	// Check if file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		r.logger.Debug("No existing configuration file found")
		return nil
	}

	// Read file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config map[string]string
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	r.configMap = config
	r.logger.Info("Configuration loaded from file", 
		zap.String("file", configFile),
		zap.Int("count", len(config)))

	return nil
}

// saveToFile saves configuration to the file system
func (r *FileConfigRepository) saveToFile() error {
	configFile := filepath.Join(r.configDir, "vault-config.json")
	
	// Marshal to JSON
	data, err := json.MarshalIndent(r.configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to temporary file first
	tempFile := configFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0640); err != nil {
		return fmt.Errorf("failed to write temp config file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempFile, configFile); err != nil {
		// Cleanup temp file on failure
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename config file: %w", err)
	}

	r.logger.Debug("Configuration saved to file", 
		zap.String("file", configFile),
		zap.Int("count", len(r.configMap)))

	return nil
}

// VaultConfigRepository implements vault.ConfigRepository using Vault's KV store
type VaultConfigRepository struct {
	secretStore vault.SecretStore
	keyPrefix   string
	logger      *zap.Logger
}

// NewVaultConfigRepository creates a new vault-based configuration repository
func NewVaultConfigRepository(secretStore vault.SecretStore, keyPrefix string, logger *zap.Logger) *VaultConfigRepository {
	return &VaultConfigRepository{
		secretStore: secretStore,
		keyPrefix:   keyPrefix,
		logger:      logger.Named("vault.config.vault"),
	}
}

// GetConfig retrieves configuration by key from vault
func (r *VaultConfigRepository) GetConfig(ctx context.Context, key string) (string, error) {
	fullKey := r.keyPrefix + "/" + key
	
	secret, err := r.secretStore.Get(ctx, fullKey)
	if err != nil {
		r.logger.Error("Failed to get config from vault", 
			zap.String("key", key),
			zap.Error(err))
		return "", fmt.Errorf("failed to get config from vault: %w", err)
	}

	if secret == nil {
		return "", fmt.Errorf("configuration key not found: %s", key)
	}

	r.logger.Debug("Configuration retrieved from vault", zap.String("key", key))
	return secret.Value, nil
}

// SetConfig stores configuration in vault
func (r *VaultConfigRepository) SetConfig(ctx context.Context, key, value string) error {
	fullKey := r.keyPrefix + "/" + key
	
	secret := &vault.Secret{
		Key:   fullKey,
		Value: value,
		Metadata: map[string]string{
			"type":        "config",
			"config_key":  key,
		},
	}

	if err := r.secretStore.Set(ctx, fullKey, secret); err != nil {
		r.logger.Error("Failed to store config in vault", 
			zap.String("key", key),
			zap.Error(err))
		return fmt.Errorf("failed to store config in vault: %w", err)
	}

	r.logger.Info("Configuration stored in vault", zap.String("key", key))
	return nil
}

// GetAllConfig returns all configuration from vault
func (r *VaultConfigRepository) GetAllConfig(ctx context.Context) (map[string]string, error) {
	secrets, err := r.secretStore.List(ctx, r.keyPrefix+"/")
	if err != nil {
		r.logger.Error("Failed to list config from vault", zap.Error(err))
		return nil, fmt.Errorf("failed to list config from vault: %w", err)
	}

	result := make(map[string]string)
	for _, secret := range secrets {
		// Extract key name from full key path
		if len(secret.Key) > len(r.keyPrefix)+1 {
			key := secret.Key[len(r.keyPrefix)+1:]
			result[key] = secret.Value
		}
	}

	r.logger.Debug("All configuration retrieved from vault", zap.Int("count", len(result)))
	return result, nil
}

// DeleteConfig removes configuration from vault
func (r *VaultConfigRepository) DeleteConfig(ctx context.Context, key string) error {
	fullKey := r.keyPrefix + "/" + key
	
	if err := r.secretStore.Delete(ctx, fullKey); err != nil {
		r.logger.Error("Failed to delete config from vault", 
			zap.String("key", key),
			zap.Error(err))
		return fmt.Errorf("failed to delete config from vault: %w", err)
	}

	r.logger.Info("Configuration deleted from vault", zap.String("key", key))
	return nil
}