// pkg/hecate/config_storage.go

package hecate

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigStorage manages persistent storage of Hecate configuration in Consul KV
type ConfigStorage struct {
	client *consulapi.Client
}

// NewConfigStorage creates a new ConfigStorage instance
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check Consul availability
// - Intervene: Create Consul client
// - Evaluate: Return configured storage
func NewConfigStorage(rc *eos_io.RuntimeContext) (*ConfigStorage, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating Consul config storage client")

	// Create Consul client with default config (uses CONSUL_HTTP_ADDR env var)
	consulConfig := consulapi.DefaultConfig()
	client, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Test connectivity
	_, err = client.Agent().Self()
	if err != nil {
		logger.Warn("Consul not available, config will not be persisted",
			zap.Error(err),
			zap.String("consul_addr", consulConfig.Address))
		return nil, fmt.Errorf("consul not available: %w", err)
	}

	logger.Debug("Consul config storage initialized",
		zap.String("consul_addr", consulConfig.Address))

	return &ConfigStorage{
		client: client,
	}, nil
}

// StoreConfig stores Hecate configuration in Consul KV
//
// Storage path convention: service/hecate/config/apps/{app_name}/{field}
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Validate configuration structure
// - Intervene: Write each app config to Consul KV
// - Evaluate: Verify storage success
func (cs *ConfigStorage) StoreConfig(rc *eos_io.RuntimeContext, config RawYAMLConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Storing Hecate configuration in Consul KV",
		zap.Int("app_count", len(config.Apps)))

	kv := cs.client.KV()

	// Store each app's configuration
	for appName, app := range config.Apps {
		logger.Debug("Storing app config",
			zap.String("app", appName))

		// Marshal app config to JSON for storage
		appJSON, err := json.Marshal(app)
		if err != nil {
			return fmt.Errorf("failed to marshal app '%s' config: %w", appName, err)
		}

		// Store complete app config as JSON
		kvPair := &consulapi.KVPair{
			Key:   fmt.Sprintf("service/hecate/config/apps/%s", appName),
			Value: appJSON,
		}

		_, err = kv.Put(kvPair, nil)
		if err != nil {
			return fmt.Errorf("failed to store app '%s' config in Consul: %w", appName, err)
		}

		logger.Debug("App config stored successfully",
			zap.String("app", appName),
			zap.String("key", kvPair.Key))
	}

	// Store metadata about the configuration
	metadata := map[string]interface{}{
		"version":      "1.0",
		"app_count":    len(config.Apps),
		"generated_by": "eos create config --hecate",
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = kv.Put(&consulapi.KVPair{
		Key:   "service/hecate/config/metadata",
		Value: metadataJSON,
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	logger.Info("Hecate configuration stored successfully in Consul KV",
		zap.Int("apps_stored", len(config.Apps)))

	return nil
}

// LoadConfig loads Hecate configuration from Consul KV
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Query Consul KV for stored config
// - Intervene: Parse and reconstruct configuration
// - Evaluate: Return validated configuration
func (cs *ConfigStorage) LoadConfig(rc *eos_io.RuntimeContext) (*RawYAMLConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Loading Hecate configuration from Consul KV")

	kv := cs.client.KV()

	// List all apps
	appKeys, _, err := kv.Keys("service/hecate/config/apps/", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list apps from Consul: %w", err)
	}

	if len(appKeys) == 0 {
		logger.Debug("No previous configuration found in Consul KV")
		return nil, nil // No previous config
	}

	config := &RawYAMLConfig{
		Apps: make(map[string]RawAppConfig),
	}

	// Load each app's config
	for _, key := range appKeys {
		kvPair, _, err := kv.Get(key, nil)
		if err != nil {
			logger.Warn("Failed to get app config from Consul",
				zap.String("key", key),
				zap.Error(err))
			continue
		}

		if kvPair == nil || kvPair.Value == nil {
			continue
		}

		var app RawAppConfig
		if err := json.Unmarshal(kvPair.Value, &app); err != nil {
			logger.Warn("Failed to unmarshal app config",
				zap.String("key", key),
				zap.Error(err))
			continue
		}

		// Extract app name from key: service/hecate/config/apps/{app_name}
		appName := key[len("service/hecate/config/apps/"):]
		config.Apps[appName] = app

		logger.Debug("Loaded app config from Consul",
			zap.String("app", appName),
			zap.String("domain", app.Domain))
	}

	logger.Info("Hecate configuration loaded from Consul KV",
		zap.Int("apps_loaded", len(config.Apps)))

	return config, nil
}

// GetAppDefaults retrieves default values for a specific app from Consul KV
func (cs *ConfigStorage) GetAppDefaults(rc *eos_io.RuntimeContext, appName string) (*RawAppConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Loading app defaults from Consul KV",
		zap.String("app", appName))

	kv := cs.client.KV()
	kvPair, _, err := kv.Get(fmt.Sprintf("service/hecate/config/apps/%s", appName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get app config: %w", err)
	}

	if kvPair == nil || kvPair.Value == nil {
		logger.Debug("No defaults found for app",
			zap.String("app", appName))
		return nil, nil
	}

	var app RawAppConfig
	if err := json.Unmarshal(kvPair.Value, &app); err != nil {
		return nil, fmt.Errorf("failed to unmarshal app config: %w", err)
	}

	logger.Debug("Loaded app defaults",
		zap.String("app", appName),
		zap.String("domain", app.Domain))

	return &app, nil
}

// ClearConfig removes all Hecate configuration from Consul KV
func (cs *ConfigStorage) ClearConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Clearing Hecate configuration from Consul KV")

	kv := cs.client.KV()

	// Delete all config keys
	_, err := kv.DeleteTree("service/hecate/config/", nil)
	if err != nil {
		return fmt.Errorf("failed to clear config: %w", err)
	}

	logger.Info("Hecate configuration cleared from Consul KV")

	return nil
}
