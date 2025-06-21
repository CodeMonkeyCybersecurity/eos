// Package vault implements a composite secret store with fallback capability
package vault

import (
	"context"
	"fmt"

	domain "github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	"go.uber.org/zap"
)

// CompositeSecretStore implements domain.SecretStore with primary/fallback strategy
type CompositeSecretStore struct {
	primary  domain.SecretStore
	fallback domain.SecretStore
	logger   *zap.Logger
}

// NewCompositeSecretStore creates a composite secret store
func NewCompositeSecretStore(
	primary domain.SecretStore,
	fallback domain.SecretStore,
	logger *zap.Logger,
) *CompositeSecretStore {
	return &CompositeSecretStore{
		primary:  primary,
		fallback: fallback,
		logger:   logger,
	}
}

// Get implements domain.SecretStore interface with fallback logic
func (c *CompositeSecretStore) Get(ctx context.Context, key string) (*domain.Secret, error) {
	c.logger.Debug("Getting secret from composite store", zap.String("key", key))

	// Try primary store first
	secret, err := c.primary.Get(ctx, key)
	if err == nil && secret != nil {
		c.logger.Debug("Secret retrieved from primary store", zap.String("key", key))
		return secret, nil
	}

	// Log primary failure and try fallback
	c.logger.Debug("Primary store failed, trying fallback",
		zap.String("key", key),
		zap.Error(err))

	secret, fallbackErr := c.fallback.Get(ctx, key)
	if fallbackErr == nil && secret != nil {
		c.logger.Info("Secret retrieved from fallback store", zap.String("key", key))
		// Add metadata indicating this came from fallback
		if secret.Metadata == nil {
			secret.Metadata = make(map[string]string)
		}
		secret.Metadata["retrieved_from"] = "fallback"
		return secret, nil
	}

	// Both stores failed
	c.logger.Warn("Secret not found in any store",
		zap.String("key", key),
		zap.NamedError("primary_error", err),
		zap.NamedError("fallback_error", fallbackErr))

	// Return the primary error as it's usually more meaningful
	return nil, fmt.Errorf("secret not found in primary or fallback store: %w", err)
}

// Set implements domain.SecretStore interface
func (c *CompositeSecretStore) Set(ctx context.Context, key string, secret *domain.Secret) error {
	c.logger.Debug("Setting secret in composite store", zap.String("key", key))

	// Try to set in primary store first
	err := c.primary.Set(ctx, key, secret)
	if err == nil {
		c.logger.Debug("Secret stored in primary store", zap.String("key", key))

		// Optionally sync to fallback for backup (best effort)
		if fallbackErr := c.fallback.Set(ctx, key, secret); fallbackErr != nil {
			c.logger.Warn("Failed to sync secret to fallback store",
				zap.String("key", key),
				zap.Error(fallbackErr))
		} else {
			c.logger.Debug("Secret synced to fallback store", zap.String("key", key))
		}

		return nil
	}

	// Primary failed, try fallback as last resort
	c.logger.Warn("Primary store failed for set, trying fallback",
		zap.String("key", key),
		zap.Error(err))

	fallbackErr := c.fallback.Set(ctx, key, secret)
	if fallbackErr == nil {
		c.logger.Info("Secret stored in fallback store", zap.String("key", key))
		return nil
	}

	// Both stores failed
	c.logger.Error("Failed to store secret in any store",
		zap.String("key", key),
		zap.NamedError("primary_error", err),
		zap.NamedError("fallback_error", fallbackErr))

	return fmt.Errorf("failed to store secret in primary or fallback store: %w", err)
}

// Delete implements domain.SecretStore interface
func (c *CompositeSecretStore) Delete(ctx context.Context, key string) error {
	c.logger.Debug("Deleting secret from composite store", zap.String("key", key))

	// Try to delete from both stores (best effort)
	primaryErr := c.primary.Delete(ctx, key)
	fallbackErr := c.fallback.Delete(ctx, key)

	// Log results
	if primaryErr != nil {
		c.logger.Debug("Failed to delete from primary store",
			zap.String("key", key),
			zap.Error(primaryErr))
	} else {
		c.logger.Debug("Secret deleted from primary store", zap.String("key", key))
	}

	if fallbackErr != nil {
		c.logger.Debug("Failed to delete from fallback store",
			zap.String("key", key),
			zap.Error(fallbackErr))
	} else {
		c.logger.Debug("Secret deleted from fallback store", zap.String("key", key))
	}

	// Success if at least one deletion succeeded
	if primaryErr == nil || fallbackErr == nil {
		c.logger.Debug("Secret deleted successfully from composite store", zap.String("key", key))
		return nil
	}

	// Both deletions failed
	c.logger.Warn("Failed to delete secret from any store",
		zap.String("key", key),
		zap.NamedError("primary_error", primaryErr),
		zap.NamedError("fallback_error", fallbackErr))

	return fmt.Errorf("failed to delete secret from primary or fallback store: %w", primaryErr)
}

// List implements domain.SecretStore interface
func (c *CompositeSecretStore) List(ctx context.Context, prefix string) ([]*domain.Secret, error) {
	c.logger.Debug("Listing secrets from composite store", zap.String("prefix", prefix))

	// Try primary store first
	secrets, err := c.primary.List(ctx, prefix)
	if err == nil {
		c.logger.Debug("Secrets listed from primary store",
			zap.String("prefix", prefix),
			zap.Int("count", len(secrets)))
		return secrets, nil
	}

	// Primary failed, try fallback
	c.logger.Debug("Primary store failed for list, trying fallback",
		zap.String("prefix", prefix),
		zap.Error(err))

	secrets, fallbackErr := c.fallback.List(ctx, prefix)
	if fallbackErr == nil {
		c.logger.Info("Secrets listed from fallback store",
			zap.String("prefix", prefix),
			zap.Int("count", len(secrets)))

		// Mark secrets as coming from fallback
		for _, secret := range secrets {
			if secret.Metadata == nil {
				secret.Metadata = make(map[string]string)
			}
			secret.Metadata["listed_from"] = "fallback"
		}

		return secrets, nil
	}

	// Both stores failed
	c.logger.Warn("Failed to list secrets from any store",
		zap.String("prefix", prefix),
		zap.NamedError("primary_error", err),
		zap.NamedError("fallback_error", fallbackErr))

	return nil, fmt.Errorf("failed to list secrets from primary or fallback store: %w", err)
}

// Exists implements domain.SecretStore interface
func (c *CompositeSecretStore) Exists(ctx context.Context, key string) (bool, error) {
	c.logger.Debug("Checking if secret exists in composite store", zap.String("key", key))

	// Check primary store first
	exists, err := c.primary.Exists(ctx, key)
	if err == nil && exists {
		c.logger.Debug("Secret exists in primary store", zap.String("key", key))
		return true, nil
	}

	// Check fallback store
	exists, fallbackErr := c.fallback.Exists(ctx, key)
	if fallbackErr == nil && exists {
		c.logger.Debug("Secret exists in fallback store", zap.String("key", key))
		return true, nil
	}

	// Neither store has the secret or both had errors
	if err != nil && fallbackErr != nil {
		c.logger.Debug("Error checking existence in both stores",
			zap.String("key", key),
			zap.NamedError("primary_error", err),
			zap.NamedError("fallback_error", fallbackErr))
		return false, fmt.Errorf("failed to check existence in any store: %w", err)
	}

	c.logger.Debug("Secret does not exist in any store", zap.String("key", key))
	return false, nil
}

// GetPrimaryStore returns the primary secret store (for testing/debugging)
func (c *CompositeSecretStore) GetPrimaryStore() domain.SecretStore {
	return c.primary
}

// GetFallbackStore returns the fallback secret store (for testing/debugging)
func (c *CompositeSecretStore) GetFallbackStore() domain.SecretStore {
	return c.fallback
}

// HealthCheck checks the health of both stores
func (c *CompositeSecretStore) HealthCheck(ctx context.Context) map[string]error {
	health := make(map[string]error)

	// Test primary store with a simple existence check
	_, primaryErr := c.primary.Exists(ctx, "__health_check__")
	health["primary"] = primaryErr

	// Test fallback store
	_, fallbackErr := c.fallback.Exists(ctx, "__health_check__")
	health["fallback"] = fallbackErr

	c.logger.Debug("Composite store health check completed",
		zap.Bool("primary_healthy", primaryErr == nil),
		zap.Bool("fallback_healthy", fallbackErr == nil))

	return health
}
