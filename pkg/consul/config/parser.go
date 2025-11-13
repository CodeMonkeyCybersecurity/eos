// pkg/consul/config/parser.go
//
// Consul HCL/JSON configuration file parser for data directory discovery.
//
// This package provides filesystem-based configuration parsing without requiring
// Consul API authentication. Used primarily for ACL bootstrap token recovery when
// API access is unavailable due to lost tokens.
//
// Last Updated: 2025-10-25

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulConfigMinimal represents the minimal Consul configuration needed for parsing.
// We only extract the data_dir field, ignoring all other configuration.
// The struct uses hcl:"attr" tags to match Consul's HCL attribute syntax.
type ConsulConfigMinimal struct {
	// Required for HCL parsing - mark all fields as optional
	Datacenter string `hcl:"datacenter,optional" json:"datacenter"`
	NodeName   string `hcl:"node_name,optional" json:"node_name"`
	DataDir    string `hcl:"data_dir,optional" json:"data_dir"`
	LogLevel   string `hcl:"log_level,optional" json:"log_level"`
	Server     *bool  `hcl:"server,optional" json:"server"`

	// Nested blocks - define structs to accept their attributes
	UIConfig *UIConfigBlock `hcl:"ui_config,block" json:"ui_config,omitempty"`
	ACL      *ACLBlock      `hcl:"acl,block" json:"acl,omitempty"`
}

// UIConfigBlock represents the ui_config block
type UIConfigBlock struct {
	Enabled *bool `hcl:"enabled,optional" json:"enabled,omitempty"`
}

// ACLBlock represents the acl block
type ACLBlock struct {
	Enabled       *bool   `hcl:"enabled,optional" json:"enabled,omitempty"`
	DefaultPolicy *string `hcl:"default_policy,optional" json:"default_policy,omitempty"`
}

// DefaultConfigLocations returns the standard Consul config file locations to check.
// Locations are tried in order until a valid config is found.
//
// Priority order:
//  1. /etc/consul.d/consul.hcl (Eos standard)
//  2. /etc/consul.d/consul.json (JSON format)
//  3. /etc/consul.d/config.hcl (Alternative name)
//  4. $CONSUL_CONFIG_DIR/consul.hcl (Environment variable)
//  5. /opt/consul/config/consul.hcl (Alternative location)
func DefaultConfigLocations() []string {
	locations := []string{
		"/etc/consul.d/consul.hcl",
		"/etc/consul.d/consul.json",
		"/etc/consul.d/config.hcl",
	}

	// Check CONSUL_CONFIG_DIR environment variable
	if consulConfigDir := os.Getenv("CONSUL_CONFIG_DIR"); consulConfigDir != "" {
		envPath := filepath.Join(consulConfigDir, "consul.hcl")
		locations = append(locations, envPath)
	}

	// Add alternative location
	locations = append(locations, "/opt/consul/config/consul.hcl")

	return locations
}

// ParseDataDirFromConfigFile attempts to extract the data_dir from Consul config files.
//
// This function tries multiple config file locations and formats (HCL and JSON) to find
// the data directory. It does NOT require Consul API access or authentication.
//
// Algorithm:
//  1. Try each config location in order
//  2. For each file that exists:
//     - Try parsing as HCL first
//     - Fall back to JSON if HCL fails
//  3. Return first valid data_dir found
//  4. Return error if no valid config found
//
// Parameters:
//   - rc: Runtime context for logging
//   - locations: Config file paths to try (use DefaultConfigLocations() if nil)
//
// Returns:
//   - string: Data directory path from config
//   - error: If no config file found or data_dir not set
//
// Example:
//
//	dataDir, err := config.ParseDataDirFromConfigFile(rc, nil)
//	if err != nil {
//	    logger.Warn("Failed to parse data dir from config", zap.Error(err))
//	    // Fall back to other detection methods
//	}
func ParseDataDirFromConfigFile(rc *eos_io.RuntimeContext, locations []string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Use default locations if none provided
	if locations == nil || len(locations) == 0 {
		locations = DefaultConfigLocations()
	}

	logger.Debug("Attempting to parse data_dir from Consul config files",
		zap.Int("location_count", len(locations)))

	var lastErr error

	for _, configPath := range locations {
		logger.Debug("Checking config file", zap.String("path", configPath))

		// Check if file exists
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			logger.Debug("Config file does not exist", zap.String("path", configPath))
			lastErr = fmt.Errorf("file not found: %s", configPath)
			continue
		}

		// Try parsing the file
		dataDir, err := parseConfigFile(rc, configPath)
		if err != nil {
			logger.Debug("Failed to parse config file",
				zap.String("path", configPath),
				zap.Error(err))
			lastErr = err
			continue
		}

		// Success!
		logger.Info("Data directory extracted from config file",
			zap.String("config_path", configPath),
			zap.String("data_dir", dataDir))

		return dataDir, nil
	}

	// All locations exhausted
	return "", fmt.Errorf("failed to parse data_dir from any config file: %w", lastErr)
}

// parseConfigFile parses a single config file (HCL or JSON) and extracts data_dir.
//
// Tries HCL parsing first, falls back to JSON if HCL fails.
func parseConfigFile(rc *eos_io.RuntimeContext, configPath string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var config ConsulConfigMinimal

	// Try HCL parsing first
	logger.Debug("Attempting HCL parse", zap.String("path", configPath))
	hclErr := hclsimple.DecodeFile(configPath, nil, &config)
	if hclErr == nil {
		// HCL parsing succeeded
		if config.DataDir == "" {
			return "", fmt.Errorf("data_dir not set in HCL config: %s", configPath)
		}
		logger.Debug("HCL parsing successful",
			zap.String("data_dir", config.DataDir))
		return config.DataDir, nil
	}

	// HCL failed, try JSON
	logger.Debug("HCL parsing failed, trying JSON",
		zap.String("path", configPath),
		zap.Error(hclErr))

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", configPath, err)
	}

	var jsonConfig ConsulConfigMinimal
	jsonErr := json.Unmarshal(data, &jsonConfig)
	if jsonErr != nil {
		// Both HCL and JSON failed
		return "", fmt.Errorf("failed to parse as HCL or JSON: HCL error: %v, JSON error: %v",
			hclErr, jsonErr)
	}

	// JSON parsing succeeded
	if jsonConfig.DataDir == "" {
		return "", fmt.Errorf("data_dir not set in JSON config: %s", configPath)
	}

	logger.Debug("JSON parsing successful",
		zap.String("data_dir", jsonConfig.DataDir))

	return jsonConfig.DataDir, nil
}
