// pkg/gitea/config.go
// Configuration storage and retrieval for Gitea instances
// Uses file-based storage with optional Consul KV sync

package gitea

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// GetConfigDir returns the configuration directory path
// Creates the directory if it doesn't exist
func GetConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".eos", ConfigDirName)
	if err := os.MkdirAll(configDir, ConfigDirPerm); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}

	return configDir, nil
}

// GetConfigPath returns the full path to the config file
func GetConfigPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, ConfigFileName), nil
}

// LoadConfig loads the persisted configuration from disk
// Returns empty config (not error) if file doesn't exist
func LoadConfig(rc *eos_io.RuntimeContext) (*PersistedConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	configPath, err := GetConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config path: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Debug("No existing config file, returning empty config",
			zap.String("path", configPath))
		return &PersistedConfig{
			Instances: []InstanceConfig{},
		}, nil
	}

	// Read and parse config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config PersistedConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	logger.Debug("Loaded gitea config",
		zap.String("path", configPath),
		zap.Int("instances", len(config.Instances)))

	return &config, nil
}

// SaveConfig saves the configuration to disk
func SaveConfig(rc *eos_io.RuntimeContext, config *PersistedConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	configPath, err := GetConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if err := os.WriteFile(configPath, data, ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("Saved gitea config",
		zap.String("path", configPath),
		zap.Int("instances", len(config.Instances)))

	return nil
}

// AddInstance adds or updates an instance in the configuration
// If an instance with the same name exists, it is updated
func AddInstance(rc *eos_io.RuntimeContext, instance *InstanceConfig, setDefault bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check if instance with same name exists
	found := false
	for i, existing := range config.Instances {
		if existing.Name == instance.Name {
			config.Instances[i] = *instance
			found = true
			logger.Info("Updated existing gitea instance",
				zap.String("name", instance.Name))
			break
		}
	}

	if !found {
		config.Instances = append(config.Instances, *instance)
		logger.Info("Added new gitea instance",
			zap.String("name", instance.Name))
	}

	// Set as default if requested or if first instance
	if setDefault || config.DefaultInstance == "" {
		config.DefaultInstance = instance.Name
		logger.Info("Set default gitea instance",
			zap.String("name", instance.Name))
	}

	return SaveConfig(rc, config)
}

// GetInstance retrieves an instance by name
// If name is empty, returns the default instance
func GetInstance(rc *eos_io.RuntimeContext, name string) (*InstanceConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := LoadConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// If no name provided, use default
	if name == "" {
		name = config.DefaultInstance
		if name == "" {
			return nil, fmt.Errorf("no gitea instance configured; run 'eos create gitea' first")
		}
	}

	// Find the instance
	for _, instance := range config.Instances {
		if instance.Name == name {
			logger.Debug("Found gitea instance",
				zap.String("name", instance.Name),
				zap.String("hostname", instance.Hostname))
			return &instance, nil
		}
	}

	return nil, fmt.Errorf("gitea instance '%s' not found", name)
}

// ListInstances returns all configured instances
func ListInstances(rc *eos_io.RuntimeContext) ([]InstanceConfig, string, error) {
	config, err := LoadConfig(rc)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load config: %w", err)
	}

	return config.Instances, config.DefaultInstance, nil
}

// RemoveInstance removes an instance by name
func RemoveInstance(rc *eos_io.RuntimeContext, name string) error {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Find and remove the instance
	found := false
	newInstances := []InstanceConfig{}
	for _, instance := range config.Instances {
		if instance.Name == name {
			found = true
			continue
		}
		newInstances = append(newInstances, instance)
	}

	if !found {
		return fmt.Errorf("gitea instance '%s' not found", name)
	}

	config.Instances = newInstances

	// Update default if we removed it
	if config.DefaultInstance == name {
		if len(config.Instances) > 0 {
			config.DefaultInstance = config.Instances[0].Name
			logger.Info("Updated default gitea instance",
				zap.String("name", config.DefaultInstance))
		} else {
			config.DefaultInstance = ""
		}
	}

	logger.Info("Removed gitea instance", zap.String("name", name))
	return SaveConfig(rc, config)
}
