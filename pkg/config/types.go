package config

import (
	"time"
)

// Format represents the configuration file format
type Format string

// DataType represents the data type for configuration values
type DataType string

// FilePermission represents file permissions
type FilePermission int

// TransformFunc is a function that transforms configuration data
type TransformFunc func(map[string]interface{}) (map[string]interface{}, error)

// TypeMap represents a mapping of field names to their expected data types
type TypeMap map[string]DataType

// Format constants
const (
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
	FormatTOML Format = "toml"
	FormatINI  Format = "ini"
	FormatENV  Format = "env"
	FormatHCL  Format = "hcl"
	FormatAuto Format = "auto" // Auto-detect format
)

// DataType constants for validation
const (
	TypeString   DataType = "string"
	TypeInt      DataType = "int"
	TypeFloat    DataType = "float"
	TypeBool     DataType = "bool"
	TypeArray    DataType = "array"
	TypeObject   DataType = "object"
	TypeDate     DataType = "date"
	TypeDuration DataType = "duration"
)

// FilePermission constants
const (
	PermissionDefault    FilePermission = 0644
	PermissionSecure     FilePermission = 0600
	PermissionExecutable FilePermission = 0755
	PermissionReadOnly   FilePermission = 0444
)

// SaveOptions configures how configuration is saved
type SaveOptions struct {
	// Format specifies the output format
	Format Format

	// Permission sets file permissions
	Permission FilePermission

	// Backup creates a backup before overwriting
	Backup bool

	// Encrypt encrypts the configuration
	Encrypt bool

	// EncryptFields encrypts only specific fields
	EncryptFields []string

	// Pretty enables pretty printing (indentation)
	Pretty bool

	// Schema validates before saving
	Schema *Schema

	// Header adds a header comment (for formats that support it)
	Header string
}

// Schema defines configuration validation schema
type Schema struct {
	// Required fields that must be present
	Required []string

	// Properties defines schema for each property
	Properties map[string]PropertySchema

	// AdditionalProperties allows properties not in schema
	AdditionalProperties bool

	// Definitions for reusable schema components
	Definitions map[string]interface{}

	// Version of the schema
	Version string
}

// PropertySchema defines validation for a single property
type PropertySchema struct {
	Type        DataType
	Description string
	Default     interface{}
	Required    bool
	MinLength   *int
	MaxLength   *int
	MinValue    *float64
	MaxValue    *float64
	Pattern     string
	Enum        []interface{}
	Properties  map[string]PropertySchema // For nested objects
	Items       *PropertySchema           // For arrays
}

// Constraint defines a business rule constraint
type Constraint struct {
	Field     string
	Operator  ConstraintOperator
	Value     interface{}
	Message   string
	DependsOn []string
}

// ConstraintOperator defines constraint operators
type ConstraintOperator string

const (
	OpEquals      ConstraintOperator = "equals"
	OpNotEquals   ConstraintOperator = "not_equals"
	OpGreaterThan ConstraintOperator = "greater_than"
	OpLessThan    ConstraintOperator = "less_than"
	OpIn          ConstraintOperator = "in"
	OpNotIn       ConstraintOperator = "not_in"
	OpMatches     ConstraintOperator = "matches"
	OpCustom      ConstraintOperator = "custom"
)

// WatchEvent represents a configuration file change event
type WatchEvent struct {
	Path      string
	Type      WatchEventType
	Timestamp time.Time
	OldData   interface{}
	NewData   interface{}
	Error     error
}

// WatchEventType defines types of watch events
type WatchEventType string

const (
	EventCreate WatchEventType = "create"
	EventUpdate WatchEventType = "update"
	EventDelete WatchEventType = "delete"
	EventError  WatchEventType = "error"
)

// FileInfo contains information about a configuration file
type FileInfo struct {
	Path        string
	Size        int64
	ModTime     time.Time
	Format      Format
	Permissions FilePermission
	IsEncrypted bool
	Checksum    string
}

// CachedConfig represents a cached configuration
type CachedConfig struct {
	Data        interface{}
	LoadedAt    time.Time
	ModTime     time.Time
	Checksum    string
	Format      Format
	IsEncrypted bool
}

// CacheStats provides cache statistics
type CacheStats struct {
	Entries   int
	Hits      int64
	Misses    int64
	Evictions int64
	SizeBytes int64
}

// LoadOptions configures how configuration is loaded
type LoadOptions struct {
	// Format forces a specific format (otherwise auto-detected)
	Format Format

	// Decrypt automatically decrypts if encrypted
	Decrypt bool

	// DecryptFields decrypts only specific fields
	DecryptFields []string

	// Defaults to apply for missing values
	Defaults map[string]interface{}

	// Schema to validate against
	Schema *Schema

	// Required fields that must be present
	Required []string

	// Transform applies transformations after loading
	Transform TransformFunc

	// Cache enables caching
	Cache bool

	// CacheTTL sets cache expiration
	CacheTTL time.Duration
}

// ConfigError represents a configuration-related error
type ConfigError struct {
	Type    ErrorType
	Path    string
	Field   string
	Message string
	Cause   error
}

// ErrorType defines types of configuration errors
type ErrorType string

const (
	ErrorLoad       ErrorType = "load"
	ErrorParse      ErrorType = "parse"
	ErrorValidation ErrorType = "validation"
	ErrorSave       ErrorType = "save"
	ErrorEncryption ErrorType = "encryption"
	ErrorWatch      ErrorType = "watch"
	ErrorNotFound   ErrorType = "not_found"
	ErrorPermission ErrorType = "permission"
)

// Error implements the error interface
func (e *ConfigError) Error() string {
	if e.Field != "" {
		return string(e.Type) + " error at " + e.Field + ": " + e.Message
	}
	return string(e.Type) + " error: " + e.Message
}

// Unwrap returns the underlying error
func (e *ConfigError) Unwrap() error {
	return e.Cause
}

// ValidationResult contains validation results
type ValidationResult struct {
	Valid    bool
	Errors   []ValidationError
	Warnings []ValidationWarning
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Rule    string
	Message string
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field   string
	Value   interface{}
	Message string
}

// MergeOptions defines how configurations are merged
type MergeOptions struct {
	// OverwriteArrays replaces arrays instead of appending
	OverwriteArrays bool

	// OverwriteEmptyStrings allows empty strings to overwrite
	OverwriteEmptyStrings bool

	// DeepMerge enables deep merging of nested objects
	DeepMerge bool

	// ConflictResolver handles merge conflicts
	ConflictResolver func(key string, a, b interface{}) interface{}
}

// ConfigMetadata contains metadata about a configuration
type ConfigMetadata struct {
	Version      string
	LoadedFrom   string
	LoadedAt     time.Time
	LastModified time.Time
	Checksum     string
	Format       Format
	IsPartial    bool
	Sources      []string
}

// DefaultSaveOptions returns default save options
func DefaultSaveOptions() SaveOptions {
	return SaveOptions{
		Format:     FormatJSON,
		Permission: PermissionDefault,
		Backup:     true,
		Encrypt:    false,
		Pretty:     true,
	}
}

// DefaultLoadOptions returns default load options
func DefaultLoadOptions() LoadOptions {
	return LoadOptions{
		Format:   FormatAuto,
		Decrypt:  true,
		Cache:    true,
		CacheTTL: 5 * time.Minute,
	}
}

// IsSecure returns true if the error is security-related
func (e *ConfigError) IsSecure() bool {
	return e.Type == ErrorPermission || e.Type == ErrorEncryption
}

// IsNotFound returns true if the error indicates a missing config
func (e *ConfigError) IsNotFound() bool {
	return e.Type == ErrorNotFound
}
