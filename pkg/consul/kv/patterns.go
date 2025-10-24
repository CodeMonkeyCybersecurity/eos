// pkg/consul/kv/patterns.go
//
// Consul KV Path Patterns and Conventions
//
// This module defines standard path structures for storing configuration
// in Consul KV. Consistent path patterns enable:
// - Predictable config discovery
// - Automated tooling (backup, migration, validation)
// - Clear ownership and lifecycle management
//
// Path Structure:
//   config/                     Root for all configuration
//     ├─ eos/                   Global EOS configuration
//     │  ├─ log-level           System-wide settings
//     │  ├─ telemetry-enabled
//     │  └─ update-channel
//     │
//     ├─ [service]/             Service-specific configuration
//     │  ├─ log_level           Service settings
//     │  ├─ timeouts/           Grouped settings
//     │  │  ├─ request
//     │  │  └─ connection
//     │  ├─ feature_flags/      Feature toggles
//     │  │  ├─ enable_rag
//     │  │  └─ enable_audit
//     │  └─ endpoints/          External service URLs
//     │     ├─ wazuh
//     │     └─ azure_openai
//     │
//     └─ environments/          Environment-specific overrides
//        ├─ production/
//        └─ staging/

package kv

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

const (
	// PathPrefixConfig is the root prefix for all configuration
	PathPrefixConfig = "config/"

	// PathPrefixEOS is the prefix for global EOS configuration
	PathPrefixEOS = "config/eos/"

	// PathPrefixEnvironments is the prefix for environment-specific config
	PathPrefixEnvironments = "config/environments/"
)

// ConfigPath builds a configuration path following standard conventions
//
// Parameters:
//   - service: Service name (e.g., "eos", "bionicgpt", "authentik")
//   - category: Config category (e.g., "feature_flags", "timeouts", "endpoints")
//   - key: Config key name (e.g., "enable_rag", "request_timeout")
//
// Returns:
//   - Full Consul KV path (e.g., "config/bionicgpt/feature_flags/enable_rag")
//
// Example:
//
//	path := kv.ConfigPath("bionicgpt", "feature_flags", "enable_rag")
//	// Returns: "config/bionicgpt/feature_flags/enable_rag"
//
//	if err := manager.Put(path, "true"); err != nil {
//	    return err
//	}
func ConfigPath(service string, category string, key string) string {
	parts := []string{PathPrefixConfig + service}

	if category != "" {
		parts = append(parts, category)
	}

	if key != "" {
		parts = append(parts, key)
	}

	return strings.Join(parts, "/")
}

// ServicePath builds a path prefix for all config of a service
//
// Example:
//
//	prefix := kv.ServicePath("bionicgpt")
//	// Returns: "config/bionicgpt/"
//
//	allConfig, err := manager.ListValues(prefix)
func ServicePath(service string) string {
	return PathPrefixConfig + service + "/"
}

// EOSConfigPath builds a path for global EOS configuration
//
// Example:
//
//	path := kv.EOSConfigPath("log-level")
//	// Returns: "config/eos/log-level"
func EOSConfigPath(key string) string {
	return PathPrefixEOS + key
}

// EnvironmentPath builds a path for environment-specific config
//
// Example:
//
//	path := kv.EnvironmentPath("production", "bionicgpt", "replicas")
//	// Returns: "config/environments/production/bionicgpt/replicas"
func EnvironmentPath(environment string, service string, key string) string {
	return fmt.Sprintf("%s%s/%s/%s", PathPrefixEnvironments, environment, service, key)
}

// StandardCategories defines well-known config categories
var StandardCategories = []string{
	"feature_flags",  // Boolean feature toggles
	"timeouts",       // Duration values (request, connection, etc.)
	"endpoints",      // External service URLs
	"limits",         // Rate limits, quotas, thresholds
	"policies",       // Configuration for policies (retry, backoff, etc.)
	"observability",  // Logging, metrics, tracing config
	"security",       // Non-sensitive security settings
}

// PathType represents the type of config path
type PathType int

const (
	PathTypeUnknown PathType = iota
	PathTypeEOSGlobal
	PathTypeService
	PathTypeEnvironment
)

// ParsePath parses a Consul KV path and extracts components
//
// Returns:
//   - pathType: Type of path (EOS global, service, environment)
//   - service: Service name (if applicable)
//   - category: Config category (if present)
//   - key: Config key name
//
// Example:
//
//	pathType, service, category, key := kv.ParsePath("config/bionicgpt/feature_flags/enable_rag")
//	// pathType: PathTypeService
//	// service: "bionicgpt"
//	// category: "feature_flags"
//	// key: "enable_rag"
func ParsePath(path string) (PathType, string, string, string) {
	if !strings.HasPrefix(path, PathPrefixConfig) {
		return PathTypeUnknown, "", "", ""
	}

	// Remove config/ prefix
	remainder := strings.TrimPrefix(path, PathPrefixConfig)
	parts := strings.Split(remainder, "/")

	if len(parts) == 0 {
		return PathTypeUnknown, "", "", ""
	}

	// Check for EOS global config
	if parts[0] == "eos" {
		if len(parts) == 1 {
			return PathTypeEOSGlobal, "eos", "", ""
		}
		if len(parts) == 2 {
			return PathTypeEOSGlobal, "eos", "", parts[1]
		}
		if len(parts) >= 3 {
			return PathTypeEOSGlobal, "eos", parts[1], strings.Join(parts[2:], "/")
		}
	}

	// Check for environment-specific config
	if parts[0] == "environments" {
		if len(parts) >= 4 {
			environment := parts[1]
			service := parts[2]
			key := strings.Join(parts[3:], "/")
			return PathTypeEnvironment, service, environment, key
		}
		return PathTypeEnvironment, "", "", ""
	}

	// Service config
	service := parts[0]
	if len(parts) == 1 {
		return PathTypeService, service, "", ""
	}
	if len(parts) == 2 {
		return PathTypeService, service, "", parts[1]
	}
	// parts[1] is category, parts[2+] is key
	category := parts[1]
	key := strings.Join(parts[2:], "/")
	return PathTypeService, service, category, key
}

// ValidatePathStructure checks if a path follows standard conventions
//
// Returns:
//   - error: Validation error if path is non-standard (warning, not fatal)
//
// Example:
//
//	if err := kv.ValidatePathStructure("config/bionicgpt/feature_flags/enable_rag"); err != nil {
//	    logger.Warn("Non-standard path", zap.Error(err))
//	}
func ValidatePathStructure(path string) error {
	pathType, service, category, key := ParsePath(path)

	switch pathType {
	case PathTypeUnknown:
		return fmt.Errorf("path does not follow standard convention: %s (should start with 'config/')", path)

	case PathTypeEOSGlobal:
		// EOS paths are always valid
		return nil

	case PathTypeEnvironment:
		if service == "" || key == "" {
			return fmt.Errorf("environment path incomplete: %s (needs environment/service/key)", path)
		}
		return nil

	case PathTypeService:
		if service == "" {
			return fmt.Errorf("service name missing in path: %s", path)
		}

		// Warn if category is non-standard (but don't fail)
		if category != "" {
			isStandard := false
			for _, std := range StandardCategories {
				if category == std {
					isStandard = true
					break
				}
			}
			if !isStandard {
				return fmt.Errorf("non-standard category '%s' in path: %s (standard categories: %v)",
					category, path, StandardCategories)
			}
		}

		return nil
	}

	return nil
}

// ConfigTemplate represents a reusable configuration template
type ConfigTemplate struct {
	Service     string
	Category    string
	Key         string
	Description string
	DefaultValue string
	Type         string // "string", "int", "bool", "duration"
}

// StandardTemplates defines common configuration patterns
var StandardTemplates = []ConfigTemplate{
	// Logging
	{
		Service:      "", // Applies to any service
		Category:     "",
		Key:          "log_level",
		Description:  "Logging verbosity level",
		DefaultValue: "info",
		Type:         "string",
	},
	{
		Service:      "",
		Category:     "",
		Key:          "log_format",
		Description:  "Log output format",
		DefaultValue: "json",
		Type:         "string",
	},

	// Timeouts
	{
		Service:      "",
		Category:     "timeouts",
		Key:          "request",
		Description:  "Request timeout duration",
		DefaultValue: "30s",
		Type:         "duration",
	},
	{
		Service:      "",
		Category:     "timeouts",
		Key:          "connection",
		Description:  "Connection timeout duration",
		DefaultValue: "5s",
		Type:         "duration",
	},

	// Feature flags (examples)
	{
		Service:      "",
		Category:     "feature_flags",
		Key:          "enable_telemetry",
		Description:  "Enable telemetry collection",
		DefaultValue: "true",
		Type:         "bool",
	},

	// Limits
	{
		Service:      "",
		Category:     "limits",
		Key:          "max_connections",
		Description:  "Maximum concurrent connections",
		DefaultValue: "100",
		Type:         "int",
	},
	{
		Service:      "",
		Category:     "limits",
		Key:          "request_rate",
		Description:  "Requests per second limit",
		DefaultValue: "1000",
		Type:         "int",
	},
}

// GetTemplate retrieves a standard template for a config key
//
// Example:
//
//	template, found := kv.GetTemplate("log_level")
//	if found {
//	    logger.Info("Using standard template",
//	        zap.String("default", template.DefaultValue),
//	        zap.String("type", template.Type))
//	}
func GetTemplate(key string) (*ConfigTemplate, bool) {
	for i, tmpl := range StandardTemplates {
		if tmpl.Key == key {
			return &StandardTemplates[i], true
		}
	}
	return nil, false
}

// InitializeServiceDefaults creates default config entries for a service
//
// Parameters:
//   - manager: KV manager instance
//   - service: Service name
//   - overrides: Map of key → value to override defaults
//
// Example:
//
//	defaults := map[string]string{
//	    "log_level": "debug", // Override default "info"
//	}
//	if err := kv.InitializeServiceDefaults(manager, "bionicgpt", defaults); err != nil {
//	    return err
//	}
func InitializeServiceDefaults(manager *Manager, service string, overrides map[string]string) error {
	for _, tmpl := range StandardTemplates {
		key := ConfigPath(service, tmpl.Category, tmpl.Key)

		// Check if already exists
		exists, err := manager.Exists(key)
		if err != nil {
			return fmt.Errorf("failed to check if %s exists: %w", key, err)
		}

		if exists {
			continue // Don't overwrite existing config
		}

		// Use override if provided, otherwise default
		value := tmpl.DefaultValue
		if override, ok := overrides[tmpl.Key]; ok {
			value = override
		}

		// Create with PutIfNotExists (atomic check-and-set)
		created, err := manager.PutIfNotExists(key, value)
		if err != nil {
			return fmt.Errorf("failed to initialize %s: %w", key, err)
		}

		if created {
			manager.logger.Info("Initialized default config",
				zap.String("service", service),
				zap.String("key", key),
				zap.String("value", value))
		}
	}

	return nil
}
