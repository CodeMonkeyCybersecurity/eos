// Package cmd_helpers provides configuration management helpers for commands
package cmd_helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	configinfra "github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/config"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ConfigServiceContainer provides configuration operations for commands
type ConfigServiceContainer struct {
	Service config.Service
	ctx     context.Context
	logger  *zap.Logger
}

// NewConfigServiceContainer creates a new configuration service container
func NewConfigServiceContainer(rc *eos_io.RuntimeContext) (*ConfigServiceContainer, error) {
	logger := rc.Log.Named("config")

	// Create infrastructure implementations
	repository := configinfra.NewFileRepository(logger)
	parser := configinfra.NewMultiFormatParser(logger)
	validator := configinfra.NewSchemaValidator(logger)
	encryptor := configinfra.NewAESEncryptor(getEncryptionKey(), logger)
	cache := configinfra.NewMemoryCache(logger)

	// Create domain service
	service := config.NewService(
		repository,
		parser,
		validator,
		encryptor,
		cache,
		logger,
	)

	return &ConfigServiceContainer{
		Service: service,
		ctx:     rc.Ctx,
		logger:  logger,
	}, nil
}

// LoadJSON loads a JSON configuration file (backward compatibility)
func (c *ConfigServiceContainer) LoadJSON(path string, v interface{}) error {
	// Use the domain service
	return c.Service.LoadFile(c.ctx, path, v)
}

// SaveJSON saves a JSON configuration file (backward compatibility)
func (c *ConfigServiceContainer) SaveJSON(path string, v interface{}) error {
	opts := config.SaveOptions{
		Format:     config.FormatJSON,
		Permission: 0644,
		Backup:     true,
		Pretty:     true,
	}
	return c.Service.SaveFile(c.ctx, path, v, opts)
}

// LoadYAML loads a YAML configuration file (backward compatibility)
func (c *ConfigServiceContainer) LoadYAML(path string, v interface{}) error {
	return c.Service.LoadFile(c.ctx, path, v)
}

// SaveYAML saves a YAML configuration file (backward compatibility)
func (c *ConfigServiceContainer) SaveYAML(path string, v interface{}) error {
	opts := config.SaveOptions{
		Format:     config.FormatYAML,
		Permission: 0644,
		Backup:     true,
		Pretty:     true,
	}
	return c.Service.SaveFile(c.ctx, path, v, opts)
}

// LoadWithDefaults loads config with default values
func (c *ConfigServiceContainer) LoadWithDefaults(path string, v interface{}, defaults map[string]interface{}) error {
	return c.Service.LoadWithDefaults(c.ctx, path, v, defaults)
}

// LoadSecure loads configuration with decryption
func (c *ConfigServiceContainer) LoadSecure(path string, v interface{}) error {
	// The service automatically handles decryption
	return c.Service.LoadFile(c.ctx, path, v)
}

// SaveSecure saves configuration with encryption
func (c *ConfigServiceContainer) SaveSecure(path string, v interface{}) error {
	opts := config.SaveOptions{
		Format:     config.FormatJSON,
		Permission: 0600, // Secure permissions
		Backup:     true,
		Encrypt:    true,
		Pretty:     false, // No pretty print for encrypted files
	}
	return c.Service.SaveFile(c.ctx, path, v, opts)
}

// Watch watches a configuration file for changes
func (c *ConfigServiceContainer) Watch(path string, callback func() error) (func(), error) {
	watchCallback := func(event config.WatchEvent) error {
		c.logger.Info("Configuration changed",
			zap.String("path", event.Path),
			zap.String("type", string(event.Type)))
		return callback()
	}

	return c.Service.Watch(c.ctx, path, watchCallback)
}

// Validate validates configuration against a schema
func (c *ConfigServiceContainer) Validate(v interface{}, required []string) error {
	schema := config.Schema{
		Required: required,
	}
	return c.Service.Validate(c.ctx, v, schema)
}

// Get retrieves a single value from configuration
func (c *ConfigServiceContainer) Get(path, key string) (interface{}, error) {
	return c.Service.Get(c.ctx, path, key)
}

// Set sets a single value in configuration
func (c *ConfigServiceContainer) Set(path, key string, value interface{}) error {
	return c.Service.Set(c.ctx, path, key, value)
}

// Legacy compatibility functions for direct migration

// LoadABTestConfig loads A/B test configuration (replaces the one in ab_config.go)
func (c *ConfigServiceContainer) LoadABTestConfig(path string) (map[string]interface{}, error) {
	var config map[string]interface{}
	err := c.LoadJSON(path, &config)
	return config, err
}

// SaveABTestConfig saves A/B test configuration
func (c *ConfigServiceContainer) SaveABTestConfig(path string, config map[string]interface{}) error {
	return c.SaveJSON(path, config)
}

// LoadServicesConfig loads services configuration (replaces loadServicesFromFile)
func (c *ConfigServiceContainer) LoadServicesConfig(path string) (interface{}, error) {
	var config interface{}
	err := c.Service.LoadFile(c.ctx, path, &config)
	return config, err
}

// Direct replacement functions that maintain exact compatibility

// ReadConfigFile reads any config file and unmarshals it
func ReadConfigFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	// Detect format from extension
	ext := filepath.Ext(path)
	switch ext {
	case ".json":
		return json.Unmarshal(data, v)
	case ".yaml", ".yml":
		return yaml.Unmarshal(data, v)
	default:
		// Try JSON first, then YAML
		if err := json.Unmarshal(data, v); err == nil {
			return nil
		}
		return yaml.Unmarshal(data, v)
	}
}

// WriteConfigFile writes config to file with proper formatting
func WriteConfigFile(path string, v interface{}) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	// Marshal based on extension
	var data []byte
	var err error

	ext := filepath.Ext(path)
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(v, "", "  ")
	case ".yaml", ".yml":
		data, err = yaml.Marshal(v)
	default:
		data, err = json.MarshalIndent(v, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// getEncryptionKey retrieves the encryption key for secure configs
func getEncryptionKey() []byte {
	// In production, this should come from a secure source
	// like environment variable or key management service
	key := os.Getenv("Eos_CONFIG_KEY")
	if key == "" {
		// Use a default key for development (NOT FOR PRODUCTION)
		return []byte("eos-config-encryption-key-32char")
	}
	return []byte(key)
}
