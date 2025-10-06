// Package environment provides enhanced environment discovery with flexible deployment models
package environment

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeploymentProfile represents different deployment patterns
type DeploymentProfile string

const (
	// Single-node deployments
	ProfileDevelopment DeploymentProfile = "development" // 1 node, all services
	ProfileSingleNode  DeploymentProfile = "single-node" // 1 node, production workload
	ProfileHomelab     DeploymentProfile = "homelab"     // 1-2 nodes, personal/learning

	// Multi-node deployments
	ProfileSmallCluster DeploymentProfile = "small-cluster" // 3-5 nodes, small business
	ProfileEnterprise   DeploymentProfile = "enterprise"    // 6+ nodes, full separation
	ProfileCloud        DeploymentProfile = "cloud"         // Auto-scaling, cloud-native
)

// EnvironmentNamespace represents workload separation
type EnvironmentNamespace struct {
	Primary   string   `json:"primary"`   // dev, staging, production, or single
	Secondary []string `json:"secondary"` // frontend, backend, database, monitoring
	Admin     bool     `json:"admin"`     // separate admin/management namespace
}

// EnhancedEnvironmentConfig extends the basic environment config
type EnhancedEnvironmentConfig struct {
	// Basic identification (existing)
	Environment string `json:"environment"`
	Datacenter  string `json:"datacenter"`
	Region      string `json:"region"`

	// Enhanced deployment characteristics
	Profile     DeploymentProfile    `json:"profile"`
	ClusterSize int                  `json:"cluster_size"`
	NodeRoles   map[string][]string  `json:"node_roles"` // node_id -> [roles]
	Namespaces  EnvironmentNamespace `json:"namespaces"`

	// Resource allocation strategy
	ResourceStrategy string `json:"resource_strategy"` // shared, dedicated, hybrid

	// Service placement
	ServicePlacement map[string]string `json:"service_placement"` // service -> preferred_node_role

	// Existing fields
	SecretBackend string          `json:"secret_backend"`
	VaultAddr     string          `json:"vault_addr"`
	Master        string          `json:"_master"`
	Services      ServiceDefaults `json:"services"`
}

// DiscoverEnhancedEnvironment performs intelligent environment discovery
func DiscoverEnhancedEnvironment(rc *eos_io.RuntimeContext) (*EnhancedEnvironmentConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Discovering enhanced environment configuration")

	config := &EnhancedEnvironmentConfig{}

	// 0. Check for existing bootstrap configuration first
	if bootstrapConfig, err := loadBootstrapEnvironmentConfig(); err == nil {
		logger.Info("Found existing bootstrap environment configuration")
		return bootstrapConfig, nil
	}

	// 1. Detect cluster topology
	if err := detectClusterTopology(config); err != nil {
		logger.Warn("Failed to detect cluster topology", zap.Error(err))
	}

	// 2. Determine deployment profile based on cluster size and context
	determineDeploymentProfile(config)

	// 3. Configure namespaces based on profile
	configureNamespaces(config)

	// 4. Set resource allocation strategy
	determineResourceStrategy(config)

	// 5. Configure service placement preferences
	configureServicePlacement(config)

	// 6. Apply service defaults based on profile
	applyEnhancedServiceDefaults(config)

	// 7. Apply secret management defaults
	if config.SecretBackend == "" {
		config.SecretBackend = determineEnhancedSecretBackend()
	}
	if config.VaultAddr == "" {
		config.VaultAddr = fmt.Sprintf("http://127.0.0.1:%d", shared.PortVault)
	}
	if config.Master == "" {
		config.Master = "127.0.0.1"
	}

	logger.Info("Enhanced environment discovery completed",
		zap.String("profile", string(config.Profile)),
		zap.Int("cluster_size", config.ClusterSize),
		zap.String("namespace_primary", config.Namespaces.Primary),
		zap.String("resource_strategy", config.ResourceStrategy))

	return config, nil
}

// detectClusterTopology discovers the actual cluster size and node roles
func detectClusterTopology(config *EnhancedEnvironmentConfig) error {
	// Try to detect from
	if nodes, err := getNodes(); err == nil {
		config.ClusterSize = len(nodes)
		config.NodeRoles = nodes
		return nil
	}

	// Try to detect from Consul
	if nodes, err := getConsulNodes(); err == nil {
		config.ClusterSize = len(nodes)
		config.NodeRoles = nodes
		return nil
	}

	// Try to detect from Nomad
	if nodes, err := getNomadNodes(); err == nil {
		config.ClusterSize = len(nodes)
		config.NodeRoles = nodes
		return nil
	}

	// Default to single node
	config.ClusterSize = 1
	config.NodeRoles = map[string][]string{
		"localhost": {"server", "client", "database", "monitoring"},
	}

	return nil
}

// determineDeploymentProfile intelligently determines the deployment profile
func determineDeploymentProfile(config *EnhancedEnvironmentConfig) {
	switch {
	case config.ClusterSize == 1:
		// Single node - determine use case
		if isDevelopmentContext() {
			config.Profile = ProfileDevelopment
			config.Environment = "development"
		} else if isHomelab() {
			config.Profile = ProfileHomelab
			config.Environment = "homelab"
		} else {
			config.Profile = ProfileSingleNode
			config.Environment = "production"
		}

	case config.ClusterSize >= 2 && config.ClusterSize <= 5:
		config.Profile = ProfileSmallCluster
		config.Environment = "production"

	case config.ClusterSize >= 6:
		if isCloudEnvironment() {
			config.Profile = ProfileCloud
			config.Environment = "production"
		} else {
			config.Profile = ProfileEnterprise
			config.Environment = "production"
		}

	default:
		config.Profile = ProfileDevelopment
		config.Environment = "development"
	}

	// Override with explicit environment detection
	if env := detectExplicitEnvironment(); env != "" {
		config.Environment = env
	}
}

// configureNamespaces sets up appropriate namespaces for the deployment profile
func configureNamespaces(config *EnhancedEnvironmentConfig) {
	switch config.Profile {
	case ProfileDevelopment:
		config.Namespaces = EnvironmentNamespace{
			Primary:   "dev",
			Secondary: []string{"all"}, // Everything in one namespace
			Admin:     false,
		}

	case ProfileSingleNode, ProfileHomelab:
		config.Namespaces = EnvironmentNamespace{
			Primary:   "single",
			Secondary: []string{"frontend", "backend", "database"},
			Admin:     false, // Admin mixed with other services
		}

	case ProfileSmallCluster:
		config.Namespaces = EnvironmentNamespace{
			Primary:   "production",
			Secondary: []string{"frontend", "backend", "database", "monitoring"},
			Admin:     true, // Separate admin namespace
		}

	case ProfileEnterprise, ProfileCloud:
		config.Namespaces = EnvironmentNamespace{
			Primary:   "production",
			Secondary: []string{"frontend", "backend", "database", "monitoring", "security"},
			Admin:     true,
		}
	}
}

// determineResourceStrategy sets the resource allocation approach
func determineResourceStrategy(config *EnhancedEnvironmentConfig) {
	switch config.Profile {
	case ProfileDevelopment, ProfileSingleNode, ProfileHomelab:
		config.ResourceStrategy = "shared" // All services share resources

	case ProfileSmallCluster:
		config.ResourceStrategy = "hybrid" // Some dedicated, some shared

	case ProfileEnterprise, ProfileCloud:
		config.ResourceStrategy = "dedicated" // Services get dedicated resources
	}
}

// configureServicePlacement sets preferred node roles for different services
func configureServicePlacement(config *EnhancedEnvironmentConfig) {
	config.ServicePlacement = make(map[string]string)

	switch config.Profile {
	case ProfileDevelopment, ProfileSingleNode, ProfileHomelab:
		// Everything goes on available nodes
		config.ServicePlacement = map[string]string{
			"grafana":    "server",
			"jenkins":    "server",
			"mattermost": "server",
			"vault":      "server",
			"consul":     "server",
			"nomad":      "server",
		}

	case ProfileSmallCluster:
		// Some separation but flexible
		config.ServicePlacement = map[string]string{
			"grafana":    "monitoring",
			"jenkins":    "backend",
			"mattermost": "frontend",
			"vault":      "server",
			"consul":     "server",
			"nomad":      "server",
		}

	case ProfileEnterprise, ProfileCloud:
		// Full separation
		config.ServicePlacement = map[string]string{
			"grafana":    "monitoring",
			"jenkins":    "cicd",
			"mattermost": "collaboration",
			"vault":      "security",
			"consul":     "infrastructure",
			"nomad":      "infrastructure",
		}
	}
}

// applyEnhancedServiceDefaults sets resource allocations based on deployment profile
func applyEnhancedServiceDefaults(config *EnhancedEnvironmentConfig) {
	// Base resource configs by profile
	var resourceConfigs map[string]ResourceConfig

	switch config.Profile {
	case ProfileDevelopment:
		resourceConfigs = map[string]ResourceConfig{
			"development": {CPU: 50, Memory: 128, Replicas: 1, MaxReplicas: 1},
		}

	case ProfileSingleNode, ProfileHomelab:
		resourceConfigs = map[string]ResourceConfig{
			"single": {CPU: 200, Memory: 512, Replicas: 1, MaxReplicas: 1},
		}

	case ProfileSmallCluster:
		resourceConfigs = map[string]ResourceConfig{
			"production": {CPU: 500, Memory: 1024, Replicas: 2, MaxReplicas: 3},
			"staging":    {CPU: 200, Memory: 512, Replicas: 1, MaxReplicas: 2},
		}

	case ProfileEnterprise, ProfileCloud:
		resourceConfigs = map[string]ResourceConfig{
			"production":  {CPU: 1000, Memory: 2048, Replicas: 3, MaxReplicas: 10},
			"staging":     {CPU: 500, Memory: 1024, Replicas: 2, MaxReplicas: 5},
			"development": {CPU: 200, Memory: 512, Replicas: 1, MaxReplicas: 2},
		}
	}

	// Default ports (same as before)
	defaultPorts := map[string]int{
		"grafana":    3000,
		"jenkins":    8080,
		"mattermost": 8065,
		"consul":     8500,
		"nomad":      4646,
		"vault":      8200,
	}

	config.Services = ServiceDefaults{
		DefaultPorts: defaultPorts,
		Resources:    resourceConfigs,
		DataPath:     "/opt/services/data",
		BackupPath:   "/opt/services/backup",
	}
}

// Helper functions for environment detection
func isDevelopmentContext() bool {
	// Check for development indicators
	hostname, _ := os.Hostname()
	hostname = strings.ToLower(hostname)

	// Development hostname patterns
	developmentPatterns := []string{"dev", "development", "local", "test", "laptop", "desktop"}
	for _, pattern := range developmentPatterns {
		if strings.Contains(hostname, pattern) {
			return true
		}
	}

	// Check for development environment variables
	if env := os.Getenv("NODE_ENV"); env == "development" || env == "dev" {
		return true
	}
	if env := os.Getenv("ENVIRONMENT"); env == "development" || env == "dev" {
		return true
	}

	// Check if running in common development locations
	if wd, err := os.Getwd(); err == nil {
		if strings.Contains(wd, "/home/") && strings.Contains(wd, "/dev") {
			return true
		}
	}

	return false
}

func isHomelab() bool {
	// Check for homelab/personal indicators
	hostname, _ := os.Hostname()
	hostname = strings.ToLower(hostname)

	// Homelab hostname patterns
	homelabPatterns := []string{"homelab", "home", "lab", "personal", "pi", "mini", "nuc"}
	for _, pattern := range homelabPatterns {
		if strings.Contains(hostname, pattern) {
			return true
		}
	}

	// Check for private IP ranges (common in homelabs)
	if isPrivateNetwork() {
		// Additional homelab indicators on private networks
		if checkHomelabServices() {
			return true
		}
	}

	return false
}

// isPrivateNetwork checks if we're on a private network
func isPrivateNetwork() bool {
	// This is a simplified check - could be expanded
	cmd := exec.Command("hostname", "-I")
	if output, err := cmd.Output(); err == nil {
		ip := strings.TrimSpace(string(output))
		// Check for common private IP ranges
		if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
			return true
		}
	}
	return false
}

// checkHomelabServices looks for common homelab services
func checkHomelabServices() bool {
	// Check for common homelab applications
	homelabServices := []string{"plex", "jellyfin", "pihole", "homeassistant", "nextcloud"}

	for _, service := range homelabServices {
		// Check if service is running
		cmd := exec.Command("systemctl", "is-active", service)
		if err := cmd.Run(); err == nil {
			return true
		}

		// Check if docker container exists
		cmd = exec.Command("docker", "ps", "-q", "-f", fmt.Sprintf("name=%s", service))
		if output, err := cmd.Output(); err == nil && len(strings.TrimSpace(string(output))) > 0 {
			return true
		}
	}

	return false
}

func isCloudEnvironment() bool {
	// Check for cloud provider metadata endpoints
	cloudChecks := []func() bool{
		checkAWS,
		checkGCP,
		checkAzure,
		checkHetzner,
		checkDigitalOcean,
	}

	for _, check := range cloudChecks {
		if check() {
			return true
		}
	}

	return false
}

// Cloud provider detection functions
func checkAWS() bool {
	cmd := exec.Command("curl", "-s", "--max-time", "2", "http://169.254.169.254/latest/meta-data/instance-id")
	return cmd.Run() == nil
}

func checkGCP() bool {
	cmd := exec.Command("curl", "-s", "--max-time", "2", "-H", "Metadata-Flavor: Google", "http://metadata.google.internal/computeMetadata/v1/instance/id")
	return cmd.Run() == nil
}

func checkAzure() bool {
	cmd := exec.Command("curl", "-s", "--max-time", "2", "-H", "Metadata:true", "http://169.254.169.254/metadata/instance/compute/vmId")
	return cmd.Run() == nil
}

func checkHetzner() bool {
	cmd := exec.Command("curl", "-s", "--max-time", "2", "http://169.254.169.254/hetzner/v1/metadata")
	return cmd.Run() == nil
}

func checkDigitalOcean() bool {
	cmd := exec.Command("curl", "-s", "--max-time", "2", "http://169.254.169.254/metadata/v1/id")
	return cmd.Run() == nil
}

func detectExplicitEnvironment() string {
	// Check environment variables
	if env := os.Getenv("EOS_ENVIRONMENT"); env != "" {
		return env
	}
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}
	if env := os.Getenv("NODE_ENV"); env != "" {
		return env
	}

	// Check for explicit environment files
	envFiles := []string{
		"/opt/eos/config/environment",
		"/etc/eos/environment",
		"/opt/eos/bootstrap/environment",
		".env",
	}

	for _, file := range envFiles {
		if content, err := os.ReadFile(file); err == nil {
			env := strings.TrimSpace(string(content))
			if env != "" {
				return env
			}
		}
	}

	// Check  s for explicit environment
	cmd := exec.Command("-call", "--local", "s.get", "environment", "--output=json")
	if output, err := cmd.Output(); err == nil {
		var result map[string]interface{}
		if json.Unmarshal(output, &result) == nil {
			if local, exists := result["local"]; exists {
				if env, ok := local.(string); ok && env != "" {
					return env
				}
			}
		}
	}

	return ""
}

// determineEnhancedSecretBackend determines the best available secret backend
func determineEnhancedSecretBackend() string {
	// Check if Vault is available
	if _, err := exec.Command("vault", "status").Output(); err == nil {
		return "vault"
	}

	// Check if  is available
	if _, err := exec.Command("-call", "--version").Output(); err == nil {
		return ""
	}

	// Fallback to file-based secrets
	return "file"
}

// loadBootstrapEnvironmentConfig loads the environment config created during bootstrap
func loadBootstrapEnvironmentConfig() (*EnhancedEnvironmentConfig, error) {
	bootstrapConfigFile := "/opt/eos/bootstrap/environment.json"

	// Check if the bootstrap config file exists
	if _, err := os.Stat(bootstrapConfigFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("bootstrap config file not found: %s", bootstrapConfigFile)
	}

	// Read the bootstrap config file
	data, err := os.ReadFile(bootstrapConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap config: %w", err)
	}

	// Parse the config
	var config EnhancedEnvironmentConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap config: %w", err)
	}

	return &config, nil
}

func getNodes() (map[string][]string, error) {
	// Query  for node inventory via -run manage.status
	cmd := exec.Command("-run", "manage.status", "--output=json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query  node status: %w", err)
	}

	var statusResult map[string]interface{}
	if err := json.Unmarshal(output, &statusResult); err != nil {
		return nil, fmt.Errorf("failed to parse  status output: %w", err)
	}

	nodes := make(map[string][]string)

	// Get up nodes
	if upNodes, exists := statusResult["up"]; exists {
		if upList, ok := upNodes.([]interface{}); ok {
			for _, nodeInterface := range upList {
				if nodeId, ok := nodeInterface.(string); ok {
					// Query each node for its roles via s
					roles, err := getNodeRoles(nodeId)
					if err != nil {
						// Default roles if we can't query
						roles = []string{"server", "client"}
					}
					nodes[nodeId] = roles
				}
			}
		}
	}

	// If no nodes found, add localhost as default
	if len(nodes) == 0 {
		nodes["localhost"] = []string{"server", "client", "database", "monitoring"}
	}

	return nodes, nil
}

// getNodeRoles queries a specific node for its configured roles
func getNodeRoles(nodeId string) ([]string, error) {
	// Query node s for role information
	cmd := exec.Command("", nodeId, "s.get", "roles", "--output=json")
	output, err := cmd.Output()
	if err != nil {
		// Try alternative  keys
		if roles := tryAlternativeRoles(nodeId); len(roles) > 0 {
			return roles, nil
		}
		return []string{"server", "client"}, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return []string{"server", "client"}, nil
	}

	// Extract roles from result
	if nodeResult, exists := result[nodeId]; exists {
		if rolesList, ok := nodeResult.([]interface{}); ok {
			roles := make([]string, 0, len(rolesList))
			for _, roleInterface := range rolesList {
				if role, ok := roleInterface.(string); ok {
					roles = append(roles, role)
				}
			}
			return roles, nil
		}
	}

	return []string{"server", "client"}, nil
}

// tryAlternativeRoles tries different  keys for role information
func tryAlternativeRoles(nodeId string) []string {
	alternativeKeys := []string{"node_roles", "service_roles", "cluster_roles", "environment"}

	for _, key := range alternativeKeys {
		cmd := exec.Command("", nodeId, "s.get", key, "--output=json")
		if output, err := cmd.Output(); err == nil {
			var result map[string]interface{}
			if json.Unmarshal(output, &result) == nil {
				if nodeResult, exists := result[nodeId]; exists {
					// Try to extract roles from various formats
					if roles := extractRolesFrom(nodeResult); len(roles) > 0 {
						return roles
					}
				}
			}
		}
	}

	return nil
}

// extractRolesFrom extracts role information from various data formats
func extractRolesFrom(data interface{}) []string {
	switch v := data.(type) {
	case []interface{}:
		// Array of roles
		roles := make([]string, 0, len(v))
		for _, roleInterface := range v {
			if role, ok := roleInterface.(string); ok {
				roles = append(roles, role)
			}
		}
		return roles

	case string:
		// Single role or comma-separated
		if strings.Contains(v, ",") {
			return strings.Split(v, ",")
		}
		return []string{v}

	case map[string]interface{}:
		// Role object with enabled/disabled
		roles := make([]string, 0)
		for role, enabled := range v {
			if enabledBool, ok := enabled.(bool); ok && enabledBool {
				roles = append(roles, role)
			}
		}
		return roles
	}

	return nil
}

func getConsulNodes() (map[string][]string, error) {
	// Query Consul for node inventory
	cmd := exec.Command("consul", "members", "-format=json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query consul members: %w", err)
	}

	var members []map[string]interface{}
	if err := json.Unmarshal(output, &members); err != nil {
		return nil, fmt.Errorf("failed to parse consul members output: %w", err)
	}

	nodes := make(map[string][]string)
	for _, member := range members {
		if name, exists := member["Name"]; exists {
			if nameStr, ok := name.(string); ok {
				roles := []string{"client"}

				// Check if it's a server
				if tags, exists := member["Tags"]; exists {
					if tagsMap, ok := tags.(map[string]interface{}); ok {
						if role, exists := tagsMap["role"]; exists {
							if roleStr, ok := role.(string); ok && roleStr == "consul" {
								roles = append(roles, "server", "consul")
							}
						}
					}
				}

				nodes[nameStr] = roles
			}
		}
	}

	return nodes, nil
}

func getNomadNodes() (map[string][]string, error) {
	// Query Nomad for node inventory
	cmd := exec.Command("nomad", "node", "status", "-json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query nomad nodes: %w", err)
	}

	var nodeList []map[string]interface{}
	if err := json.Unmarshal(output, &nodeList); err != nil {
		return nil, fmt.Errorf("failed to parse nomad nodes output: %w", err)
	}

	nodes := make(map[string][]string)
	for _, node := range nodeList {
		if name, exists := node["Name"]; exists {
			if nameStr, ok := name.(string); ok {
				roles := []string{"client"}

				// Check node class for additional roles
				if nodeClass, exists := node["NodeClass"]; exists {
					if classStr, ok := nodeClass.(string); ok && classStr != "" {
						roles = append(roles, classStr)
					}
				}

				// Check if it's eligible (active)
				if status, exists := node["Status"]; exists {
					if statusStr, ok := status.(string); ok && statusStr == "ready" {
						roles = append(roles, "ready")
					}
				}

				nodes[nameStr] = roles
			}
		}
	}

	return nodes, nil
}
