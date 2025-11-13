// pkg/consul/kv/manager.go
//
// Consul KV Store Manager
//
// This module provides a high-level API for managing configuration in Consul's
// Key-Value store. Part of Phase 2 implementation (Vault + Consul integration).
//
// Design Principles:
// - Non-sensitive configuration only (secrets belong in Vault)
// - Structured path conventions (config/[service]/[category]/[key])
// - Type-safe operations with validation
// - Watch support for real-time config updates
//
// Usage Pattern:
//   1. Store non-sensitive config in Consul KV
//   2. Services watch for config changes
//   3. Config updates trigger automatic service reloads
//   4. Secrets always come from Vault (never from Consul KV)

package kv

import (
	"context"
	"fmt"
	"strings"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Manager provides high-level Consul KV operations
type Manager struct {
	client *consulapi.Client
	ctx    context.Context
	logger otelzap.LoggerWithCtx
}

// NewManager creates a new Consul KV manager
func NewManager(ctx context.Context, client *consulapi.Client) *Manager {
	return &Manager{
		client: client,
		ctx:    ctx,
		logger: otelzap.Ctx(ctx),
	}
}

// Get retrieves a value from Consul KV
//
// Parameters:
//   - key: KV path (e.g., "config/eos/log-level")
//
// Returns:
//   - value: The stored value as string
//   - exists: Whether the key exists
//   - error: Any error encountered
//
// Example:
//
//	value, exists, err := manager.Get("config/eos/log-level")
//	if !exists {
//	    // Use default value
//	    value = "info"
//	}
func (m *Manager) Get(key string) (string, bool, error) {
	m.logger.Debug("Reading Consul KV",
		zap.String("key", key))

	pair, _, err := m.client.KV().Get(key, nil)
	if err != nil {
		return "", false, fmt.Errorf("failed to read Consul KV: %w", err)
	}

	if pair == nil {
		m.logger.Debug("Key not found in Consul KV",
			zap.String("key", key))
		return "", false, nil
	}

	value := string(pair.Value)
	m.logger.Debug("Successfully read Consul KV",
		zap.String("key", key),
		zap.Int("value_length", len(value)))

	return value, true, nil
}

// GetOrDefault retrieves a value or returns a default if not found
//
// Example:
//
//	logLevel := manager.GetOrDefault("config/eos/log-level", "info")
func (m *Manager) GetOrDefault(key string, defaultValue string) (string, error) {
	value, exists, err := m.Get(key)
	if err != nil {
		return "", err
	}

	if !exists {
		m.logger.Debug("Using default value for missing key",
			zap.String("key", key),
			zap.String("default", defaultValue))
		return defaultValue, nil
	}

	return value, nil
}

// Put stores a value in Consul KV
//
// Parameters:
//   - key: KV path (e.g., "config/bionicgpt/log_level")
//   - value: The value to store
//
// Returns:
//   - error: Any error encountered
//
// Example:
//
//	if err := manager.Put("config/bionicgpt/log_level", "debug"); err != nil {
//	    return fmt.Errorf("failed to update config: %w", err)
//	}
func (m *Manager) Put(key string, value string) error {
	m.logger.Info("Writing to Consul KV",
		zap.String("key", key),
		zap.Int("value_length", len(value)))

	// Validate key doesn't look like a secret path
	if err := ValidateKeyNotSecret(key); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Validate value doesn't contain secret-like data
	if err := ValidateValueNotSecret(key, value); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	pair := &consulapi.KVPair{
		Key:   key,
		Value: []byte(value),
	}

	_, err := m.client.KV().Put(pair, nil)
	if err != nil {
		return fmt.Errorf("failed to write Consul KV: %w", err)
	}

	m.logger.Info("Successfully wrote to Consul KV",
		zap.String("key", key))

	return nil
}

// PutIfNotExists stores a value only if the key doesn't exist (CAS operation)
//
// Returns:
//   - created: true if value was created, false if key already exists
//   - error: Any error encountered
//
// Example:
//
//	created, err := manager.PutIfNotExists("config/eos/log-level", "info")
//	if created {
//	    logger.Info("Created default config")
//	} else {
//	    logger.Info("Config already exists, not overwriting")
//	}
func (m *Manager) PutIfNotExists(key string, value string) (bool, error) {
	m.logger.Debug("Attempting conditional write to Consul KV",
		zap.String("key", key))

	// Validate before attempting write
	if err := ValidateKeyNotSecret(key); err != nil {
		return false, err
	}
	if err := ValidateValueNotSecret(key, value); err != nil {
		return false, err
	}

	pair := &consulapi.KVPair{
		Key:   key,
		Value: []byte(value),
		Flags: 0,
	}

	// CAS with index 0 = only create if not exists
	success, _, err := m.client.KV().CAS(pair, nil)
	if err != nil {
		return false, fmt.Errorf("failed conditional write: %w", err)
	}

	if success {
		m.logger.Info("Created new config entry",
			zap.String("key", key))
	} else {
		m.logger.Debug("Config entry already exists",
			zap.String("key", key))
	}

	return success, nil
}

// Delete removes a key from Consul KV
//
// Example:
//
//	if err := manager.Delete("config/old-service/deprecated"); err != nil {
//	    logger.Warn("Failed to delete old config", zap.Error(err))
//	}
func (m *Manager) Delete(key string) error {
	m.logger.Info("Deleting from Consul KV",
		zap.String("key", key))

	_, err := m.client.KV().Delete(key, nil)
	if err != nil {
		return fmt.Errorf("failed to delete Consul KV key: %w", err)
	}

	m.logger.Info("Successfully deleted from Consul KV",
		zap.String("key", key))

	return nil
}

// DeleteTree recursively deletes all keys under a prefix
//
// WARNING: This is a destructive operation!
//
// Example:
//
//	// Delete all config for a service
//	if err := manager.DeleteTree("config/old-service/"); err != nil {
//	    return fmt.Errorf("failed to cleanup old config: %w", err)
//	}
func (m *Manager) DeleteTree(prefix string) error {
	m.logger.Warn("Recursively deleting Consul KV tree",
		zap.String("prefix", prefix))

	_, err := m.client.KV().DeleteTree(prefix, nil)
	if err != nil {
		return fmt.Errorf("failed to delete Consul KV tree: %w", err)
	}

	m.logger.Info("Successfully deleted Consul KV tree",
		zap.String("prefix", prefix))

	return nil
}

// List retrieves all keys under a prefix
//
// Parameters:
//   - prefix: KV path prefix (e.g., "config/bionicgpt/")
//
// Returns:
//   - keys: List of key paths
//   - error: Any error encountered
//
// Example:
//
//	keys, err := manager.List("config/bionicgpt/")
//	for _, key := range keys {
//	    logger.Info("Found config", zap.String("key", key))
//	}
func (m *Manager) List(prefix string) ([]string, error) {
	m.logger.Debug("Listing Consul KV keys",
		zap.String("prefix", prefix))

	keys, _, err := m.client.KV().Keys(prefix, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list Consul KV keys: %w", err)
	}

	m.logger.Debug("Successfully listed Consul KV keys",
		zap.String("prefix", prefix),
		zap.Int("count", len(keys)))

	return keys, nil
}

// ListValues retrieves all key-value pairs under a prefix
//
// Returns:
//   - pairs: Map of key → value
//   - error: Any error encountered
//
// Example:
//
//	config, err := manager.ListValues("config/bionicgpt/")
//	for key, value := range config {
//	    logger.Info("Config item", zap.String("key", key), zap.String("value", value))
//	}
func (m *Manager) ListValues(prefix string) (map[string]string, error) {
	m.logger.Debug("Listing Consul KV values",
		zap.String("prefix", prefix))

	pairs, _, err := m.client.KV().List(prefix, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list Consul KV values: %w", err)
	}

	result := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		result[pair.Key] = string(pair.Value)
	}

	m.logger.Debug("Successfully listed Consul KV values",
		zap.String("prefix", prefix),
		zap.Int("count", len(result)))

	return result, nil
}

// Exists checks if a key exists in Consul KV
//
// Example:
//
//	if exists, err := manager.Exists("config/eos/initialized"); err == nil && exists {
//	    logger.Info("System already initialized")
//	}
func (m *Manager) Exists(key string) (bool, error) {
	_, exists, err := m.Get(key)
	return exists, err
}

// Transaction performs multiple operations atomically
//
// Example:
//
//	ops := []*consulapi.KVTxnOp{
//	    {
//	        Verb: consulapi.KVSet,
//	        Key:  "config/service/a",
//	        Value: []byte("value1"),
//	    },
//	    {
//	        Verb: consulapi.KVSet,
//	        Key:  "config/service/b",
//	        Value: []byte("value2"),
//	    },
//	}
//	if err := manager.Transaction(ops); err != nil {
//	    // All operations rolled back
//	}
func (m *Manager) Transaction(ops consulapi.KVTxnOps) error {
	m.logger.Info("Executing Consul KV transaction",
		zap.Int("operation_count", len(ops)))

	// Validate all keys and values before transaction
	for _, op := range ops {
		if err := ValidateKeyNotSecret(op.Key); err != nil {
			return fmt.Errorf("transaction validation failed: %w", err)
		}
		if op.Verb == consulapi.KVSet || op.Verb == consulapi.KVCAS {
			if err := ValidateValueNotSecret(op.Key, string(op.Value)); err != nil {
				return fmt.Errorf("transaction validation failed: %w", err)
			}
		}
	}

	success, response, _, err := m.client.KV().Txn(ops, nil)
	if err != nil {
		return fmt.Errorf("transaction failed: %w", err)
	}

	if !success {
		// Transaction failed, collect error messages
		var errors []string
		for _, result := range response.Errors {
			errors = append(errors, result.What)
		}
		return fmt.Errorf("transaction failed: %s", strings.Join(errors, "; "))
	}

	m.logger.Info("Successfully executed Consul KV transaction",
		zap.Int("operation_count", len(ops)))

	return nil
}

// GetMetadata retrieves full metadata for a key (including modify index)
//
// Returns:
//   - pair: Full KVPair with metadata
//   - error: Any error encountered
//
// Example:
//
//	pair, err := manager.GetMetadata("config/eos/version")
//	logger.Info("Config metadata",
//	    zap.Uint64("modify_index", pair.ModifyIndex),
//	    zap.Uint64("create_index", pair.CreateIndex))
func (m *Manager) GetMetadata(key string) (*consulapi.KVPair, error) {
	m.logger.Debug("Reading Consul KV metadata",
		zap.String("key", key))

	pair, _, err := m.client.KV().Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read Consul KV metadata: %w", err)
	}

	if pair == nil {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	return pair, nil
}
