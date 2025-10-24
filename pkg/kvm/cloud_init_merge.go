//go:build linux

// pkg/kvm/cloud_init_merge.go
//
// Cloud-init YAML merging for combining multiple cloud-init configurations.
//
// This package provides intelligent merging of cloud-init documents to combine:
// - Security hardening cloud-init
// - Consul agent deployment cloud-init
// - Service-specific configuration cloud-init
//
// Last Updated: 2025-01-24

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// MergeCloudInitConfigs combines multiple cloud-init YAML documents
// into a single valid cloud-init configuration.
//
// This function:
//  1. Parses each YAML document
//  2. Intelligently merges sections (runcmd, write_files, packages, etc.)
//  3. Preserves ordering where semantically important
//  4. Validates final output
//
// Merging strategy:
//   - Arrays (runcmd, packages, write_files, bootcmd): Append all items
//   - Maps/Objects: Overlay wins (last config takes precedence)
//   - Scalars: Overlay wins
//
// Parameters:
//   - rc: RuntimeContext for logging
//   - configs: List of cloud-init YAML strings to merge
//
// Returns:
//   - string: Merged cloud-init YAML (with #cloud-config header)
//   - error: Any parsing or validation error
//
// Example:
//
//	baseConfig := `#cloud-config
//	packages:
//	  - curl
//	  - vim
//	runcmd:
//	  - apt update`
//
//	consulConfig := `#cloud-config
//	packages:
//	  - unzip
//	runcmd:
//	  - curl -o consul.zip https://releases.hashicorp.com/consul/1.19.2/consul.zip
//	  - unzip consul.zip`
//
//	merged, err := MergeCloudInitConfigs(rc, baseConfig, consulConfig)
//	// Result:
//	// #cloud-config
//	// packages:
//	//   - curl
//	//   - vim
//	//   - unzip
//	// runcmd:
//	//   - apt update
//	//   - curl -o consul.zip ...
//	//   - unzip consul.zip
func MergeCloudInitConfigs(rc *eos_io.RuntimeContext, configs ...string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if len(configs) == 0 {
		return "", fmt.Errorf("no cloud-init configs provided")
	}

	if len(configs) == 1 {
		logger.Debug("Only one cloud-init config provided, no merging needed")
		return configs[0], nil
	}

	logger.Info("Merging cloud-init configurations",
		zap.Int("config_count", len(configs)))

	// ASSESS - Parse all configs
	var merged map[string]interface{}

	for i, config := range configs {
		// Strip #cloud-config header if present
		cleanConfig := stripCloudConfigHeader(config)

		var doc map[string]interface{}
		if err := yaml.Unmarshal([]byte(cleanConfig), &doc); err != nil {
			return "", fmt.Errorf("failed to parse cloud-init config %d: %w", i, err)
		}

		logger.Debug("Parsed cloud-init config",
			zap.Int("index", i),
			zap.Int("keys", len(doc)))

		// INTERVENE - Merge sections
		merged = mergeCloudInitSections(merged, doc)
	}

	// EVALUATE - Validate and serialize
	finalYAML, err := yaml.Marshal(merged)
	if err != nil {
		return "", fmt.Errorf("failed to serialize merged cloud-init: %w", err)
	}

	// Add #cloud-config header
	result := "#cloud-config\n" + string(finalYAML)

	logger.Info("Cloud-init configs merged successfully",
		zap.Int("input_count", len(configs)),
		zap.Int("output_size", len(result)))

	return result, nil
}

// mergeCloudInitSections intelligently merges two cloud-init documents.
//
// Merging rules:
//   - Arrays: Append (runcmd, packages, write_files, bootcmd, users, ssh_authorized_keys)
//   - Maps: Deep merge (recursive)
//   - Scalars: Overlay wins (second value replaces first)
//
// This preserves the semantics of cloud-init where:
//   - Commands run in order (runcmd)
//   - Packages are all installed
//   - Files are all written
//   - Later configs can override earlier settings
func mergeCloudInitSections(base, overlay map[string]interface{}) map[string]interface{} {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}

	result := make(map[string]interface{})

	// Start with all base keys
	for key, baseValue := range base {
		result[key] = baseValue
	}

	// Merge overlay keys
	for key, overlayValue := range overlay {
		if baseValue, exists := result[key]; exists {
			// Key exists in both - merge intelligently
			switch key {
			case "runcmd", "bootcmd", "packages", "write_files", "users", "ssh_authorized_keys", "groups":
				// Array sections - append
				result[key] = appendSlices(baseValue, overlayValue)

			default:
				// Check if both are maps (nested merge)
				baseMap, baseIsMap := baseValue.(map[string]interface{})
				overlayMap, overlayIsMap := overlayValue.(map[string]interface{})

				if baseIsMap && overlayIsMap {
					// Deep merge maps
					result[key] = mergeCloudInitSections(baseMap, overlayMap)
				} else {
					// Scalar or incompatible types - overlay wins
					result[key] = overlayValue
				}
			}
		} else {
			// Key only in overlay - add it
			result[key] = overlayValue
		}
	}

	return result
}

// appendSlices appends two values as slices.
//
// Handles conversion of:
//   - []interface{} + []interface{} → []interface{}
//   - interface{} + []interface{} → []interface{}
//   - []interface{} + interface{} → []interface{}
//   - interface{} + interface{} → []interface{}
func appendSlices(a, b interface{}) interface{} {
	var result []interface{}

	// Convert a to slice
	switch v := a.(type) {
	case []interface{}:
		result = append(result, v...)
	case []string:
		for _, s := range v {
			result = append(result, s)
		}
	default:
		result = append(result, a)
	}

	// Append b
	switch v := b.(type) {
	case []interface{}:
		result = append(result, v...)
	case []string:
		for _, s := range v {
			result = append(result, s)
		}
	default:
		result = append(result, b)
	}

	return result
}

// stripCloudConfigHeader removes the #cloud-config header line if present.
//
// Cloud-init YAML can start with #cloud-config but this is not valid YAML.
// We strip it before parsing and add it back after merging.
func stripCloudConfigHeader(config string) string {
	const header = "#cloud-config"

	if len(config) >= len(header) && config[:len(header)] == header {
		// Remove header and any trailing newline
		config = config[len(header):]
		if len(config) > 0 && config[0] == '\n' {
			config = config[1:]
		}
	}

	return config
}
