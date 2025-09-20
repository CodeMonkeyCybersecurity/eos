// Package environment provides automatic environment discovery and configuration management
package environment

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnvironmentConfig represents the discovered environment configuration
type EnvironmentConfig struct {
	// Environment identification
	Environment string `json:"environment"` // production, staging, development
	Datacenter  string `json:"datacenter"`  // dc1, us-east-1, eu-west-1
	Region      string `json:"region"`      // geographic region

	// Node configuration
	NodeRole     string   `json:"node_role"`     // server, client, standalone
	NodeID       string   `json:"node_id"`       // unique node identifier
	ClusterNodes []string `json:"cluster_nodes"` // other nodes in cluster

	// Service configuration
	Services ServiceDefaults `json:"services"`

	// Secret management
	VaultAddr string `json:"vault_addr"` // vault server address
}

// ServiceDefaults contains default configurations for services
type ServiceDefaults struct {
	// Network defaults
	DefaultPorts map[string]int `json:"default_ports"`

	// Resource defaults by environment
	Resources map[string]ResourceConfig `json:"resources"`

	// Storage defaults
	DataPath   string `json:"data_path"`
	BackupPath string `json:"backup_path"`
}

// ResourceConfig defines resource allocation by environment
type ResourceConfig struct {
	CPU         int `json:"cpu"`
	Memory      int `json:"memory"`
	Replicas    int `json:"replicas"`
	MaxReplicas int `json:"max_replicas"`
}

// DiscoverEnvironment automatically discovers the current environment configuration
// This is the main entry point that uses enhanced discovery when available
func DiscoverEnvironment(rc *eos_io.RuntimeContext) (*EnvironmentConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Discovering environment configuration with enhanced topology detection")

	// Try enhanced discovery first (includes cluster topology and node roles)
	if enhancedConfig, err := DiscoverEnhancedEnvironment(rc); err == nil {
		// Convert enhanced config to basic config for backward compatibility
		config := convertEnhancedToBasic(enhancedConfig)

		logger.Info("Enhanced environment discovery completed",
			zap.String("profile", string(enhancedConfig.Profile)),
			zap.Int("cluster_size", enhancedConfig.ClusterSize),
			zap.String("environment", config.Environment),
			zap.String("datacenter", config.Datacenter),
			zap.String("namespace_primary", enhancedConfig.Namespaces.Primary))

		// Save both enhanced and basic configs
		if err := saveEnhancedConfig(enhancedConfig); err != nil {
			logger.Warn("Failed to save enhanced configuration", zap.Error(err))
		}
		if err := saveConfig(config); err != nil {
			logger.Warn("Failed to save basic configuration", zap.Error(err))
		}

		return config, nil
	}

	// Fallback to basic discovery
	logger.Info("Enhanced discovery failed, using basic discovery")
	config := &EnvironmentConfig{}

	// 1. Check for existing environment configuration
	if err := loadExistingConfig(config); err == nil {
		logger.Info("Loaded existing environment configuration",
			zap.String("environment", config.Environment),
			zap.String("datacenter", config.Datacenter))
		return config, nil
	}

	// 2. Discover from HashiCorp bootstrap state
	if err := discoverFromHashiCorpBootstrap(config); err != nil {
		logger.Warn("Failed to discover from HashiCorp bootstrap", zap.Error(err))
	}

	// 4. Discover from cloud metadata
	if err := discoverFromCloud(config); err != nil {
		logger.Warn("Failed to discover from cloud", zap.Error(err))
	}

	// 5. Apply intelligent defaults
	applyDefaults(config)

	// 6. Save discovered configuration
	if err := saveConfig(config); err != nil {
		logger.Warn("Failed to save configuration", zap.Error(err))
	}

	logger.Debug("Enhanced environment config loaded",
		zap.String("environment", config.Environment),
		zap.String("datacenter", config.Datacenter),
		zap.String("region", config.Region),
		zap.String("vault_addr", config.VaultAddr))

	return config, nil
}

// convertEnhancedToBasic converts enhanced config to basic config for backward compatibility
func convertEnhancedToBasic(enhanced *EnhancedEnvironmentConfig) *EnvironmentConfig {
	return &EnvironmentConfig{
		Environment:  enhanced.Environment,
		Datacenter:   enhanced.Datacenter,
		Region:       enhanced.Region,
		NodeRole:     determineNodeRole(enhanced),
		NodeID:       "localhost", // Could be enhanced to use actual node ID
		ClusterNodes: extractClusterNodes(enhanced),
		Services:     enhanced.Services,
		VaultAddr:    enhanced.VaultAddr,
	}
}

// determineNodeRole determines the primary role for this node
func determineNodeRole(enhanced *EnhancedEnvironmentConfig) string {
	// Find localhost or current node in the cluster
	hostname, _ := os.Hostname()

	// Try to find current node in cluster
	for nodeId, roles := range enhanced.NodeRoles {
		if nodeId == hostname || nodeId == "localhost" {
			if len(roles) > 0 {
				return roles[0] // Return primary role
			}
		}
	}

	// Default based on profile
	switch enhanced.Profile {
	case ProfileDevelopment, ProfileSingleNode, ProfileHomelab:
		return "server"
	case ProfileSmallCluster, ProfileEnterprise, ProfileCloud:
		return "client"
	default:
		return "server"
	}
}

// extractClusterNodes extracts cluster node list from enhanced config
func extractClusterNodes(enhanced *EnhancedEnvironmentConfig) []string {
	nodes := make([]string, 0, len(enhanced.NodeRoles))
	for nodeId := range enhanced.NodeRoles {
		nodes = append(nodes, nodeId)
	}
	return nodes
}

// saveEnhancedConfig saves the enhanced configuration
func saveEnhancedConfig(config *EnhancedEnvironmentConfig) error {
	configDir := "/opt/eos/config"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "enhanced_environment.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal enhanced config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write enhanced config file: %w", err)
	}

	return nil
}

// loadExistingConfig loads previously discovered configuration
func loadExistingConfig(config *EnvironmentConfig) error {
	configPath := "/opt/eos/config/environment.json"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("no existing configuration found")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	return nil
}



// discoverFrom discovers configuration from  s
func discoverFrom(config *EnvironmentConfig) error {
	// Try to get  s
	output, err := executeCommand("-call", "--local", "s.items", "--output=json")
	if err != nil {
		return fmt.Errorf("failed to get  s: %w", err)
	}

	var s map[string]interface{}
	if err := json.Unmarshal([]byte(output), &s); err != nil {
		return fmt.Errorf("failed to parse  s: %w", err)
	}

	// Extract environment information from s
	if local, ok := s["local"].(map[string]interface{}); ok {
		if env, ok := local["environment"].(string); ok {
			config.Environment = env
		}
		if dc, ok := local["datacenter"].(string); ok {
			config.Datacenter = dc
		}
		if role, ok := local["node_role"].(string); ok {
			config.NodeRole = role
		}
	}

	return nil
}

// discoverFromCloud discovers configuration from cloud metadata
func discoverFromCloud(config *EnvironmentConfig) error {
	// Try different cloud providers
	if err := discoverFromHetzner(config); err == nil {
		return nil
	}

	if err := discoverFromAWS(config); err == nil {
		return nil
	}

	return fmt.Errorf("no cloud metadata found")
}

// discoverFromHetzner discovers configuration from Hetzner Cloud metadata
func discoverFromHetzner(config *EnvironmentConfig) error {
	// Hetzner metadata endpoint
	metadata, err := executeCommand("curl", "-s", "http://169.254.169.254/hetzner/v1/metadata")
	if err != nil {
		return fmt.Errorf("failed to get Hetzner metadata: %w", err)
	}

	var hetznerMeta map[string]interface{}
	if err := json.Unmarshal([]byte(metadata), &hetznerMeta); err != nil {
		return err
	}

	// Extract region/datacenter from Hetzner metadata
	if region, ok := hetznerMeta["region"].(string); ok {
		config.Region = region
		config.Datacenter = region
	}

	return nil
}

// discoverFromAWS discovers configuration from AWS metadata
func discoverFromAWS(config *EnvironmentConfig) error {
	// AWS metadata endpoint
	region, err := executeCommand("curl", "-s", "http://169.254.169.254/latest/meta-data/placement/region")
	if err != nil {
		return fmt.Errorf("failed to get AWS region: %w", err)
	}

	config.Region = strings.TrimSpace(region)
	config.Datacenter = strings.TrimSpace(region)

	return nil
}

// applyDefaults applies intelligent defaults based on discovered information
func applyDefaults(config *EnvironmentConfig) {
	// Environment defaults
	if config.Environment == "" {
		config.Environment = determineEnvironmentFromContext(config)
	}

	if config.Datacenter == "" {
		config.Datacenter = "dc1" // Default datacenter
	}

	if config.NodeRole == "" {
		config.NodeRole = "standalone" // Default for single-node
	}

	// Vault address detection (HashiCorp migration)
	config.VaultAddr = determineVaultAddress()

	// Service defaults
	config.Services = ServiceDefaults{
		DefaultPorts: map[string]int{
			"grafana":    3000,
			"jenkins":    8080,
			"consul":     8500,
			"nomad":      4646,
			"vault":      8200,
			"mattermost": 8065,
			"umami":      3001,
		},
		Resources: map[string]ResourceConfig{
			"development": {
				CPU:         100,
				Memory:      256,
				Replicas:    1,
				MaxReplicas: 1,
			},
			"staging": {
				CPU:         200,
				Memory:      512,
				Replicas:    1,
				MaxReplicas: 2,
			},
			"production": {
				CPU:         500,
				Memory:      1024,
				Replicas:    2,
				MaxReplicas: 5,
			},
		},
		DataPath:   "/opt/services/data",
		BackupPath: "/opt/services/backup",
	}

	// Vault/Consul addresses
	if config.VaultAddr == "" {
		config.VaultAddr = "http://127.0.0.1:8200"
	}
}

// determineEnvironmentFromContext intelligently determines environment
func determineEnvironmentFromContext(config *EnvironmentConfig) string {
	// Check hostname patterns
	hostname, _ := os.Hostname()
	hostname = strings.ToLower(hostname)

	if strings.Contains(hostname, "prod") || strings.Contains(hostname, "production") {
		return "production"
	}
	if strings.Contains(hostname, "stag") || strings.Contains(hostname, "staging") {
		return "staging"
	}
	if strings.Contains(hostname, "dev") || strings.Contains(hostname, "development") {
		return "development"
	}

	// Check for cloud instance patterns
	if config.Region != "" {
		return "production" // Cloud instances default to production
	}

	// Default to development for local/unknown
	return "development"
}

// determineVaultAddress determines the Vault server address (HashiCorp migration)
func determineVaultAddress() string {
	// Check if Vault is available locally
	if _, err := executeCommand("vault", "status"); err == nil {
		return "http://localhost:8200" // Default local Vault address
	}

	// Check environment variable
	if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
		return vaultAddr
	}

	// Default Vault address
	return "http://localhost:8200"
}

// saveConfig saves the discovered configuration
func saveConfig(config *EnvironmentConfig) error {
	configDir := "/opt/eos/config"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "environment.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Helper functions
func parseBootstrapConfig(path string, config *EnvironmentConfig) error {
	// Implementation depends on bootstrap file format
	return fmt.Errorf("bootstrap config parsing not implemented")
}

func executeCommand(name string, args ...string) (string, error) {
	// Simple command execution - would use proper exec package in real implementation
	return "", fmt.Errorf("command execution not implemented")
}

// discoverFromHashiCorpBootstrap discovers configuration from HashiCorp bootstrap state
func discoverFromHashiCorpBootstrap(config *EnvironmentConfig) error {
	// Check for HashiCorp bootstrap state files
	bootstrapPaths := []string{
		"/opt/eos/bootstrap/environment.json",
		"/etc/eos/bootstrap.conf",
		"/var/lib/consul/bootstrap.json",
	}

	for _, path := range bootstrapPaths {
		if _, err := os.Stat(path); err == nil {
			return parseBootstrapConfig(path, config)
		}
	}

	return fmt.Errorf("no HashiCorp bootstrap configuration found")
}
