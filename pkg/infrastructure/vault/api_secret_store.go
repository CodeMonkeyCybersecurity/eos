// Package vault implements infrastructure layer for vault operations
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	domain "github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// APISecretStore implements domain.SecretStore using HashiCorp Vault API
type APISecretStore struct {
	client    *api.Client
	mountPath string
	logger    *zap.Logger
}

// NewAPISecretStore creates a new vault API secret store
func NewAPISecretStore(client *api.Client, mountPath string, logger *zap.Logger) *APISecretStore {
	if mountPath == "" {
		mountPath = "secret" // Default KV mount
	}
	return &APISecretStore{
		client:    client,
		mountPath: mountPath,
		logger:    logger,
	}
}

// Get implements domain.SecretStore interface
func (a *APISecretStore) Get(ctx context.Context, key string) (*domain.Secret, error) {
	path := a.sanitizePath(key)

	a.logger.Debug("Getting secret from vault",
		zap.String("key", key),
		zap.String("path", path))

	secret, err := a.client.KVv2(a.mountPath).Get(ctx, path)
	if err != nil {
		a.logger.Error("Failed to get secret from vault",
			zap.String("path", path),
			zap.Error(err))
		return nil, fmt.Errorf("vault get failed for key %s: %w", key, err)
	}

	if secret == nil || secret.Data == nil {
		a.logger.Debug("Secret not found in vault", zap.String("key", key))
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	// Convert vault secret to domain secret
	domainSecret, err := a.convertVaultSecretToDomain(key, secret)
	if err != nil {
		a.logger.Error("Failed to convert vault secret",
			zap.String("key", key),
			zap.Error(err))
		return nil, fmt.Errorf("failed to convert secret %s: %w", key, err)
	}

	a.logger.Debug("Secret retrieved successfully from vault", zap.String("key", key))
	return domainSecret, nil
}

// Set implements domain.SecretStore interface
func (a *APISecretStore) Set(ctx context.Context, key string, secret *domain.Secret) error {
	path := a.sanitizePath(key)

	a.logger.Debug("Setting secret in vault",
		zap.String("key", key),
		zap.String("path", path))

	// Convert domain secret to vault data format
	data, err := a.convertDomainSecretToVault(secret)
	if err != nil {
		a.logger.Error("Failed to convert domain secret",
			zap.String("key", key),
			zap.Error(err))
		return fmt.Errorf("failed to convert secret %s: %w", key, err)
	}

	_, err = a.client.KVv2(a.mountPath).Put(ctx, path, data)
	if err != nil {
		a.logger.Error("Failed to set secret in vault",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("vault set failed for key %s: %w", key, err)
	}

	a.logger.Debug("Secret stored successfully in vault", zap.String("key", key))
	return nil
}

// Delete implements domain.SecretStore interface
func (a *APISecretStore) Delete(ctx context.Context, key string) error {
	path := a.sanitizePath(key)

	a.logger.Debug("Deleting secret from vault",
		zap.String("key", key),
		zap.String("path", path))

	err := a.client.KVv2(a.mountPath).DeleteMetadata(ctx, path)
	if err != nil {
		a.logger.Error("Failed to delete secret from vault",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("vault delete failed for key %s: %w", key, err)
	}

	a.logger.Debug("Secret deleted successfully from vault", zap.String("key", key))
	return nil
}

// List implements domain.SecretStore interface
func (a *APISecretStore) List(ctx context.Context, prefix string) ([]*domain.Secret, error) {
	path := a.sanitizePath(prefix)

	a.logger.Debug("Listing secrets from vault",
		zap.String("prefix", prefix),
		zap.String("path", path))

	// Use the Logical client to list metadata
	metaPath := fmt.Sprintf("%s/metadata/%s", a.mountPath, path)
	secretList, err := a.client.Logical().List(metaPath)
	if err != nil {
		a.logger.Error("Failed to list secrets from vault",
			zap.String("path", path),
			zap.Error(err))
		return nil, fmt.Errorf("vault list failed for prefix %s: %w", prefix, err)
	}

	var secrets []*domain.Secret
	if secretList != nil && secretList.Data != nil {
		if keys, ok := secretList.Data["keys"].([]interface{}); ok {
			for _, keyInterface := range keys {
				if keyStr, ok := keyInterface.(string); ok {
					fullKey := a.buildFullKey(prefix, keyStr)

					// Get full secret data
					secret, err := a.Get(ctx, fullKey)
					if err != nil {
						a.logger.Warn("Failed to get secret during list",
							zap.String("key", fullKey),
							zap.Error(err))
						continue // Skip this secret but continue listing
					}
					secrets = append(secrets, secret)
				}
			}
		}
	}

	a.logger.Debug("Secrets listed successfully from vault",
		zap.String("prefix", prefix),
		zap.Int("count", len(secrets)))

	return secrets, nil
}

// Exists implements domain.SecretStore interface
func (a *APISecretStore) Exists(ctx context.Context, key string) (bool, error) {
	path := a.sanitizePath(key)

	a.logger.Debug("Checking if secret exists in vault",
		zap.String("key", key),
		zap.String("path", path))

	// Try to get metadata only (more efficient than full secret)
	metaPath := fmt.Sprintf("%s/metadata/%s", a.mountPath, path)
	secret, err := a.client.Logical().Read(metaPath)
	if err != nil {
		a.logger.Debug("Error checking secret existence",
			zap.String("key", key),
			zap.Error(err))
		return false, nil // Treat errors as "not found" for existence check
	}

	exists := secret != nil
	a.logger.Debug("Secret existence check completed",
		zap.String("key", key),
		zap.Bool("exists", exists))

	return exists, nil
}

// convertVaultSecretToDomain converts a vault KV secret to domain Secret
func (a *APISecretStore) convertVaultSecretToDomain(key string, vaultSecret *api.KVSecret) (*domain.Secret, error) {
	// Get the secret value
	value, ok := vaultSecret.Data["value"].(string)
	if !ok {
		// Try to get as JSON for complex values
		if jsonData, ok := vaultSecret.Data["json"].(string); ok {
			value = jsonData
		} else {
			return nil, fmt.Errorf("secret value not found or invalid format")
		}
	}

	// Convert metadata
	metadata := make(map[string]string)
	for k, v := range vaultSecret.Data {
		if k != "value" && k != "json" {
			if str, ok := v.(string); ok {
				metadata[k] = str
			}
		}
	}

	// Create domain secret
	domainSecret := &domain.Secret{
		Key:       key,
		Value:     value,
		Metadata:  metadata,
		Version:   vaultSecret.VersionMetadata.Version,
		CreatedAt: vaultSecret.VersionMetadata.CreatedTime,
		UpdatedAt: vaultSecret.VersionMetadata.CreatedTime, // Vault doesn't track separate update time
	}

	// Check for expiry in metadata
	if expiryStr, ok := metadata["expires_at"]; ok {
		if expiry, err := time.Parse(time.RFC3339, expiryStr); err == nil {
			domainSecret.ExpiresAt = &expiry
		}
	}

	return domainSecret, nil
}

// convertDomainSecretToVault converts a domain Secret to vault data format
func (a *APISecretStore) convertDomainSecretToVault(secret *domain.Secret) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"value": secret.Value,
	}

	// Add metadata
	for k, v := range secret.Metadata {
		data[k] = v
	}

	// Add expiry if present
	if secret.ExpiresAt != nil {
		data["expires_at"] = secret.ExpiresAt.Format(time.RFC3339)
	}

	// Add version if present
	if secret.Version > 0 {
		data["version"] = secret.Version
	}

	// Store complex values as JSON
	if strings.HasPrefix(secret.Value, "{") || strings.HasPrefix(secret.Value, "[") {
		// Try to parse as JSON to validate
		var jsonCheck interface{}
		if json.Unmarshal([]byte(secret.Value), &jsonCheck) == nil {
			data["json"] = secret.Value
			delete(data, "value") // Use json field instead of value for structured data
		}
	}

	return data, nil
}

// sanitizePath converts domain key to safe vault path
func (a *APISecretStore) sanitizePath(key string) string {
	// Remove dangerous path elements
	path := strings.ReplaceAll(key, "..", "")
	path = strings.ReplaceAll(path, "//", "/")
	path = strings.Trim(path, "/")

	// Ensure path doesn't start with slash (vault KV paths are relative)
	path = strings.TrimPrefix(path, "/")

	return path
}

// buildFullKey constructs full key from prefix and key
func (a *APISecretStore) buildFullKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	if strings.HasSuffix(prefix, "/") {
		return prefix + key
	}
	return prefix + "/" + key
}
