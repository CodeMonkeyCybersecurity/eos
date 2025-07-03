// Package config provides domain interfaces and services for configuration management
package config

import (
	"context"
	"os"
)

// Service defines high-level configuration operations
type Service interface {
	// LoadFile loads configuration from a file into the target struct
	LoadFile(ctx context.Context, path string, target interface{}) error

	// SaveFile saves configuration from source struct to a file
	SaveFile(ctx context.Context, path string, source interface{}, opts SaveOptions) error

	// LoadWithDefaults loads config and applies defaults for missing values
	LoadWithDefaults(ctx context.Context, path string, target interface{}, defaults map[string]interface{}) error

	// Validate validates configuration against a schema
	Validate(ctx context.Context, data interface{}, schema Schema) error

	// Watch watches a configuration file for changes
	Watch(ctx context.Context, path string, callback WatchCallback) (CancelFunc, error)

	// Get retrieves a single configuration value by key path (e.g., "database.host")
	Get(ctx context.Context, path string, key string) (interface{}, error)

	// Set sets a single configuration value by key path
	Set(ctx context.Context, path string, key string, value interface{}) error
}

// Repository defines storage operations for configurations
type Repository interface {
	// Read reads raw configuration data from storage
	Read(ctx context.Context, path string) ([]byte, error)

	// Write writes raw configuration data to storage
	Write(ctx context.Context, path string, data []byte, perm FilePermission) error

	// Exists checks if a configuration file exists
	Exists(ctx context.Context, path string) (bool, error)

	// Delete removes a configuration file
	Delete(ctx context.Context, path string) error

	// Stat returns file information
	Stat(ctx context.Context, path string) (FileInfo, error)

	// List lists configuration files in a directory
	List(ctx context.Context, dir string) ([]FileInfo, error)
}

// Parser defines parsing operations for different configuration formats
type Parser interface {
	// Parse parses raw bytes into a generic structure
	Parse(ctx context.Context, data []byte, format Format) (map[string]interface{}, error)

	// Marshal converts a structure into formatted bytes
	Marshal(ctx context.Context, v interface{}, format Format) ([]byte, error)

	// DetectFormat attempts to detect the format of configuration data
	DetectFormat(ctx context.Context, data []byte, hint string) (Format, error)

	// Unmarshal parses bytes directly into a target structure
	Unmarshal(ctx context.Context, data []byte, format Format, target interface{}) error
}

// Validator defines validation operations for configurations
type Validator interface {
	// ValidateSchema validates data against a JSON schema
	ValidateSchema(ctx context.Context, data interface{}, schema Schema) error

	// ValidateRequired ensures all required fields are present
	ValidateRequired(ctx context.Context, data interface{}, required []string) error

	// ValidateTypes validates field types match expectations
	ValidateTypes(ctx context.Context, data interface{}, types TypeMap) error

	// ValidateConstraints validates business rule constraints
	ValidateConstraints(ctx context.Context, data interface{}, constraints []Constraint) error
}

// Encryptor defines encryption operations for sensitive configurations
type Encryptor interface {
	// Encrypt encrypts configuration data
	Encrypt(ctx context.Context, data []byte) ([]byte, error)

	// Decrypt decrypts configuration data
	Decrypt(ctx context.Context, data []byte) ([]byte, error)

	// IsEncrypted checks if data is encrypted
	IsEncrypted(ctx context.Context, data []byte) bool

	// EncryptField encrypts a specific field in the configuration
	EncryptField(ctx context.Context, data map[string]interface{}, fieldPath string) error

	// DecryptField decrypts a specific field in the configuration
	DecryptField(ctx context.Context, data map[string]interface{}, fieldPath string) error
}

// Watcher defines file watching operations
type Watcher interface {
	// Start starts watching for changes
	Start(ctx context.Context) error

	// Stop stops watching
	Stop() error

	// Events returns the event channel
	Events() <-chan WatchEvent
}

// Cache defines caching operations for configurations
type Cache interface {
	// Get retrieves a cached configuration
	Get(key string) (CachedConfig, bool)

	// Set stores a configuration in cache
	Set(key string, config CachedConfig) error

	// Delete removes a configuration from cache
	Delete(key string) error

	// Clear clears all cached configurations
	Clear() error

	// Stats returns cache statistics
	Stats() CacheStats
}

// Callbacks and function types

// WatchCallback is called when a configuration file changes
type WatchCallback func(event WatchEvent) error

// CancelFunc cancels a watch operation
type CancelFunc func()

// MigrationFunc migrates configuration from one version to another
type MigrationFunc func(ctx context.Context, oldData map[string]interface{}) (map[string]interface{}, error)

// TransformFunc transforms configuration data
type TransformFunc func(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error)

// Type definitions

// Format represents a configuration file format
type Format string

// FilePermission represents file permissions
type FilePermission os.FileMode

// TypeMap maps field paths to expected types
type TypeMap map[string]DataType

// DataType represents a data type for validation
type DataType string
