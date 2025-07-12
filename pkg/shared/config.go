package shared

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// Configuration management utilities to standardize config file operations

// ConfigFormat represents supported configuration file formats
type ConfigFormat string

const (
	FormatJSON ConfigFormat = "json"
	FormatYAML ConfigFormat = "yaml"
	FormatTOML ConfigFormat = "toml"
	FormatINI  ConfigFormat = "ini"
	FormatENV  ConfigFormat = "env"
)

// ConfigManager provides standardized configuration file management
type ConfigManager struct {
	logger Logger
}

// ConfigOptions holds options for configuration operations
type ConfigOptions struct {
	Path         string      `json:"path"`
	Format       ConfigFormat `json:"format"`
	CreateBackup bool        `json:"create_backup"`
	Validate     bool        `json:"validate"`
	Permissions  uint32      `json:"permissions"`
}

// NewConfigManager creates a new configuration manager with dependency injection
func NewConfigManager(logger Logger) *ConfigManager {
	return &ConfigManager{
		logger: logger,
	}
}

// LoadConfig loads configuration from file into a struct
func (cm *ConfigManager) LoadConfig(opts *ConfigOptions, target interface{}) error {
	cm.logger.Info("Loading configuration",
		zap.String("path", opts.Path),
		zap.String("format", string(opts.Format)))

	// ASSESS - Check if file exists and determine format
	if !FileExists(opts.Path) {
		return fmt.Errorf("configuration file does not exist: %s", opts.Path)
	}

	if opts.Format == "" {
		opts.Format = cm.detectFormat(opts.Path)
	}

	// INTERVENE - Read and parse configuration
	content, err := ReadFileContents(opts.Path)
	if err != nil {
		return WrapConfigError("read", opts.Path, err)
	}

	if err := cm.parseConfig(content, opts.Format, target); err != nil {
		return WrapConfigError("parse", opts.Path, err)
	}

	// EVALUATE - Validate if requested
	if opts.Validate {
		if err := cm.validateConfig(target); err != nil {
			return WrapConfigError("validate", opts.Path, err)
		}
	}

	cm.logger.Info("Configuration loaded successfully",
		zap.String("path", opts.Path))

	return nil
}

// SaveConfig saves configuration from struct to file
func (cm *ConfigManager) SaveConfig(opts *ConfigOptions, source interface{}) error {
	cm.logger.Info("Saving configuration",
		zap.String("path", opts.Path),
		zap.String("format", string(opts.Format)))

	// ASSESS - Determine format and validate
	if opts.Format == "" {
		opts.Format = cm.detectFormat(opts.Path)
	}

	if opts.Validate {
		if err := cm.validateConfig(source); err != nil {
			return WrapConfigError("validate", opts.Path, err)
		}
	}

	// Create backup if requested
	if opts.CreateBackup && FileExists(opts.Path) {
		if backupPath, err := BackupFile(opts.Path); err != nil {
			cm.logger.Warn("Failed to create backup",
				zap.String("path", opts.Path),
				zap.Error(err))
		} else {
			cm.logger.Info("Configuration backup created",
				zap.String("backup_path", backupPath))
		}
	}

	// INTERVENE - Serialize and write configuration
	content, err := cm.serializeConfig(source, opts.Format)
	if err != nil {
		return WrapConfigError("serialize", opts.Path, err)
	}

	permissions := opts.Permissions
	if permissions == 0 {
		permissions = 0644
	}

	if err := SafeWriteFile(opts.Path, content, os.FileMode(permissions)); err != nil {
		return WrapConfigError("write", opts.Path, err)
	}

	// EVALUATE - Verify file was written correctly
	if !FileExists(opts.Path) {
		return fmt.Errorf("configuration file was not created: %s", opts.Path)
	}

	cm.logger.Info("Configuration saved successfully",
		zap.String("path", opts.Path))

	return nil
}

// UpdateConfig updates specific fields in a configuration file
func (cm *ConfigManager) UpdateConfig(opts *ConfigOptions, updates map[string]interface{}) error {
	cm.logger.Info("Updating configuration",
		zap.String("path", opts.Path),
		zap.Int("fields", len(updates)))

	// Load existing configuration
	var existing map[string]interface{}
	if err := cm.LoadConfig(opts, &existing); err != nil {
		return err
	}

	// Apply updates
	for key, value := range updates {
		cm.setNestedValue(existing, key, value)
	}

	// Save updated configuration
	return cm.SaveConfig(opts, existing)
}

// MergeConfigs merges multiple configuration files
func (cm *ConfigManager) MergeConfigs(basePath string, overlayPaths []string, outputPath string) error {
	cm.logger.Info("Merging configurations",
		zap.String("base", basePath),
		zap.Strings("overlays", overlayPaths),
		zap.String("output", outputPath))

	// Load base configuration
	baseOpts := &ConfigOptions{Path: basePath}
	var merged map[string]interface{}
	if err := cm.LoadConfig(baseOpts, &merged); err != nil {
		return err
	}

	// Merge overlays
	for _, overlayPath := range overlayPaths {
		if !FileExists(overlayPath) {
			cm.logger.Warn("Overlay file does not exist, skipping",
				zap.String("path", overlayPath))
			continue
		}

		overlayOpts := &ConfigOptions{Path: overlayPath}
		var overlay map[string]interface{}
		if err := cm.LoadConfig(overlayOpts, &overlay); err != nil {
			return err
		}

		cm.mergeMap(merged, overlay)
	}

	// Save merged configuration
	outputOpts := &ConfigOptions{
		Path:         outputPath,
		Format:       cm.detectFormat(outputPath),
		CreateBackup: true,
	}
	return cm.SaveConfig(outputOpts, merged)
}

// ValidateConfigFile validates a configuration file
func (cm *ConfigManager) ValidateConfigFile(path string, schema interface{}) error {
	opts := &ConfigOptions{
		Path:     path,
		Validate: true,
	}

	return cm.LoadConfig(opts, schema)
}

// GetConfigValue retrieves a specific value from a configuration file
func (cm *ConfigManager) GetConfigValue(path, key string) (interface{}, error) {
	opts := &ConfigOptions{Path: path}
	var config map[string]interface{}
	
	if err := cm.LoadConfig(opts, &config); err != nil {
		return nil, err
	}

	return cm.getNestedValue(config, key), nil
}

// SetConfigValue sets a specific value in a configuration file
func (cm *ConfigManager) SetConfigValue(path, key string, value interface{}) error {
	opts := &ConfigOptions{
		Path:         path,
		CreateBackup: true,
	}

	updates := map[string]interface{}{key: value}
	return cm.UpdateConfig(opts, updates)
}

// Helper methods

func (cm *ConfigManager) detectFormat(path string) ConfigFormat {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return FormatJSON
	case ".yaml", ".yml":
		return FormatYAML
	case ".toml":
		return FormatTOML
	case ".ini":
		return FormatINI
	case ".env":
		return FormatENV
	default:
		// Default to JSON
		return FormatJSON
	}
}

func (cm *ConfigManager) parseConfig(content []byte, format ConfigFormat, target interface{}) error {
	switch format {
	case FormatJSON:
		return json.Unmarshal(content, target)
	case FormatYAML:
		return fmt.Errorf("YAML format not yet implemented")
	case FormatTOML:
		// Would need TOML library
		return fmt.Errorf("TOML format not yet implemented")
	case FormatINI:
		// Would need INI library
		return fmt.Errorf("INI format not yet implemented")
	case FormatENV:
		return cm.parseEnvFormat(content, target)
	default:
		return fmt.Errorf("unsupported configuration format: %s", format)
	}
}

func (cm *ConfigManager) serializeConfig(source interface{}, format ConfigFormat) ([]byte, error) {
	switch format {
	case FormatJSON:
		return json.MarshalIndent(source, "", "  ")
	case FormatYAML:
		return nil, fmt.Errorf("YAML format not yet implemented")
	case FormatTOML:
		return nil, fmt.Errorf("TOML format not yet implemented")
	case FormatINI:
		return nil, fmt.Errorf("INI format not yet implemented")
	case FormatENV:
		return cm.serializeEnvFormat(source)
	default:
		return nil, fmt.Errorf("unsupported configuration format: %s", format)
	}
}

func (cm *ConfigManager) parseEnvFormat(content []byte, target interface{}) error {
	// Simple ENV format parser
	// Each line: KEY=VALUE
	lines := strings.Split(string(content), "\n")
	envMap := make(map[string]string)
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	
	// Convert to JSON for standard unmarshaling
	jsonData, err := json.Marshal(envMap)
	if err != nil {
		return err
	}
	
	return json.Unmarshal(jsonData, target)
}

func (cm *ConfigManager) serializeEnvFormat(source interface{}) ([]byte, error) {
	// Convert to map first
	jsonData, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	
	var envMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &envMap); err != nil {
		return nil, err
	}
	
	var lines []string
	for key, value := range envMap {
		lines = append(lines, fmt.Sprintf("%s=%v", key, value))
	}
	
	return []byte(strings.Join(lines, "\n")), nil
}

func (cm *ConfigManager) validateConfig(config interface{}) error {
	// Check if config implements a Validator interface
	if validator, ok := config.(interface{ Validate() error }); ok {
		return validator.Validate()
	}
	
	// Basic validation - check for nil
	if config == nil {
		return fmt.Errorf("configuration is nil")
	}
	
	return nil
}

func (cm *ConfigManager) setNestedValue(config map[string]interface{}, key string, value interface{}) {
	keys := strings.Split(key, ".")
	current := config
	
	for _, k := range keys[:len(keys)-1] {
		if _, exists := current[k]; !exists {
			current[k] = make(map[string]interface{})
		}
		if next, ok := current[k].(map[string]interface{}); ok {
			current = next
		} else {
			// Create new nested map
			newMap := make(map[string]interface{})
			current[k] = newMap
			current = newMap
		}
	}
	
	current[keys[len(keys)-1]] = value
}

func (cm *ConfigManager) getNestedValue(config map[string]interface{}, key string) interface{} {
	keys := strings.Split(key, ".")
	current := config
	
	for _, k := range keys[:len(keys)-1] {
		if next, ok := current[k].(map[string]interface{}); ok {
			current = next
		} else {
			return nil
		}
	}
	
	return current[keys[len(keys)-1]]
}

func (cm *ConfigManager) mergeMap(base, overlay map[string]interface{}) {
	for key, value := range overlay {
		if baseValue, exists := base[key]; exists {
			if baseMap, ok := baseValue.(map[string]interface{}); ok {
				if overlayMap, ok := value.(map[string]interface{}); ok {
					cm.mergeMap(baseMap, overlayMap)
					continue
				}
			}
		}
		base[key] = value
	}
}

// WrapConfigError creates a standardized configuration error
func WrapConfigError(operation, path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("failed to %s configuration '%s': %w", operation, path, err)
}

// Convenience functions for common operations

// LoadJSONConfig loads a JSON configuration file
func (cm *ConfigManager) LoadJSONConfig(path string, target interface{}) error {
	opts := &ConfigOptions{
		Path:   path,
		Format: FormatJSON,
	}
	return cm.LoadConfig(opts, target)
}

// SaveJSONConfig saves a JSON configuration file
func (cm *ConfigManager) SaveJSONConfig(path string, source interface{}) error {
	opts := &ConfigOptions{
		Path:         path,
		Format:       FormatJSON,
		CreateBackup: true,
		Permissions:  0644,
	}
	return cm.SaveConfig(opts, source)
}

// LoadYAMLConfig loads a YAML configuration file
func (cm *ConfigManager) LoadYAMLConfig(path string, target interface{}) error {
	opts := &ConfigOptions{
		Path:   path,
		Format: FormatYAML,
	}
	return cm.LoadConfig(opts, target)
}

// SaveYAMLConfig saves a YAML configuration file  
func (cm *ConfigManager) SaveYAMLConfig(path string, source interface{}) error {
	opts := &ConfigOptions{
		Path:         path,
		Format:       FormatYAML,
		CreateBackup: true,
		Permissions:  0644,
	}
	return cm.SaveConfig(opts, source)
}