// Package purge handles deletion of service secrets and configuration from Vault and Consul
package purge

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PurgeServiceSecrets deletes all secrets for a service from Vault
// Follows AIE pattern: Assess → Intervene → Evaluate
func PurgeServiceSecrets(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Purging service secrets from Vault",
		zap.String("service", serviceName))

	// ASSESS - Get Vault client
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		logger.Warn("Failed to connect to Vault, skipping secret purge",
			zap.Error(err))
		// Non-fatal - Vault may not be available
		return nil
	}

	// ASSESS - List all secret paths for this service
	secretPaths, err := listServiceSecretPaths(rc, client, serviceName)
	if err != nil {
		logger.Warn("Failed to list service secrets",
			zap.Error(err),
			zap.String("service", serviceName))
		return nil // Non-fatal
	}

	if len(secretPaths) == 0 {
		logger.Info("No secrets found for service in Vault",
			zap.String("service", serviceName))
		return nil
	}

	logger.Info("Found secrets to purge",
		zap.String("service", serviceName),
		zap.Int("count", len(secretPaths)))

	// INTERVENE - Delete each secret path
	deletedCount := 0
	for _, path := range secretPaths {
		logger.Debug("Deleting secret", zap.String("path", path))

		// Use KV v2 Delete (soft delete - can be recovered if needed)
		err := client.KVv2("secret").Delete(context.Background(), path)
		if err != nil {
			logger.Warn("Failed to delete secret",
				zap.String("path", path),
				zap.Error(err))
			// Continue with other secrets
			continue
		}

		logger.Debug("Secret deleted successfully", zap.String("path", path))
		deletedCount++
	}

	// EVALUATE
	logger.Info("Secret purge complete",
		zap.String("service", serviceName),
		zap.Int("deleted", deletedCount),
		zap.Int("total", len(secretPaths)))

	return nil
}

// PurgeServiceConfigs deletes all configs for a service from Consul KV
// Follows AIE pattern: Assess → Intervene → Evaluate
func PurgeServiceConfigs(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Purging service configs from Consul KV",
		zap.String("service", serviceName))

	// ASSESS - Get Consul client
	consulConfig := api.DefaultConfig()
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		logger.Warn("Failed to connect to Consul, skipping config purge",
			zap.Error(err))
		// Non-fatal - Consul may not be available
		return nil
	}

	// ASSESS - List all KV keys for this service
	prefix := fmt.Sprintf("service/%s/", serviceName)
	keys, err := listConsulKeys(rc, consulClient, prefix)
	if err != nil {
		logger.Warn("Failed to list service configs",
			zap.Error(err),
			zap.String("service", serviceName))
		return nil // Non-fatal
	}

	if len(keys) == 0 {
		logger.Info("No configs found for service in Consul KV",
			zap.String("service", serviceName))
		return nil
	}

	logger.Info("Found configs to purge",
		zap.String("service", serviceName),
		zap.Int("count", len(keys)))

	// INTERVENE - Delete each key
	deletedCount := 0
	for _, key := range keys {
		logger.Debug("Deleting config key", zap.String("key", key))

		_, err := consulClient.KV().Delete(key, nil)
		if err != nil {
			logger.Warn("Failed to delete config key",
				zap.String("key", key),
				zap.Error(err))
			// Continue with other keys
			continue
		}

		logger.Debug("Config key deleted successfully", zap.String("key", key))
		deletedCount++
	}

	// EVALUATE
	logger.Info("Config purge complete",
		zap.String("service", serviceName),
		zap.Int("deleted", deletedCount),
		zap.Int("total", len(keys)))

	return nil
}

// PurgeService is a convenience function that purges both secrets and configs
func PurgeService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Purging service data from Vault and Consul",
		zap.String("service", serviceName))

	// Purge secrets from Vault
	if err := PurgeServiceSecrets(rc, serviceName); err != nil {
		logger.Error("Failed to purge service secrets",
			zap.Error(err),
			zap.String("service", serviceName))
		// Continue to purge configs even if secrets failed
	}

	// Purge configs from Consul
	if err := PurgeServiceConfigs(rc, serviceName); err != nil {
		logger.Error("Failed to purge service configs",
			zap.Error(err),
			zap.String("service", serviceName))
	}

	logger.Info("Service purge complete",
		zap.String("service", serviceName))

	return nil
}

// Helper: listServiceSecretPaths lists all secret paths for a service
func listServiceSecretPaths(rc *eos_io.RuntimeContext, client interface{}, serviceName string) ([]string, error) {
	// Always use direct listing (client parameter unused)
	_ = client
	return listServiceSecretPathsDirect(rc, serviceName)
}

// Helper: listServiceSecretPathsDirect lists secret paths using Vault API directly
func listServiceSecretPathsDirect(rc *eos_io.RuntimeContext, serviceName string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get Vault client
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to get Vault client: %w", err)
	}

	paths := []string{}

	// List all environments under services/
	envListPath := "secret/metadata/services"
	envList, err := vaultClient.Logical().ListWithContext(rc.Ctx, envListPath)
	if err != nil {
		logger.Debug("Failed to list environments (may not exist)", zap.Error(err))
		return paths, nil
	}

	if envList == nil || envList.Data == nil {
		return paths, nil
	}

	// Extract environment keys
	envKeys, ok := envList.Data["keys"].([]interface{})
	if !ok {
		return paths, nil
	}

	// Check each environment for this service
	for _, envInterface := range envKeys {
		env := strings.TrimSuffix(envInterface.(string), "/")

		// Check if this service exists in this environment
		servicePath := fmt.Sprintf("services/%s/%s", env, serviceName)
		metadataPath := fmt.Sprintf("secret/metadata/%s", servicePath)

		// Check if secret exists
		secret, err := vaultClient.Logical().ReadWithContext(rc.Ctx, metadataPath)
		if err != nil || secret == nil {
			continue
		}

		paths = append(paths, servicePath)
	}

	logger.Debug("Found secret paths",
		zap.String("service", serviceName),
		zap.Int("count", len(paths)))

	return paths, nil
}

// Helper: listConsulKeys lists all Consul KV keys under a prefix
func listConsulKeys(rc *eos_io.RuntimeContext, client *api.Client, prefix string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// List all keys under prefix
	pairs, _, err := client.KV().List(prefix, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list Consul KV keys at %s: %w", prefix, err)
	}

	keys := []string{}
	for _, pair := range pairs {
		keys = append(keys, pair.Key)
	}

	logger.Debug("Found Consul KV keys",
		zap.String("prefix", prefix),
		zap.Int("count", len(keys)))

	return keys, nil
}
