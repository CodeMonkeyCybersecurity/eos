// pkg/bootstrap/detector.go

package bootstrap

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ClusterInfo contains information about the cluster state
type ClusterInfo struct {
	IsSingleNode bool
	IsMaster     bool
	MasterAddr   string
	NodeCount    int
	MyRole       environment.Role
	ClusterID    string
	ExistingNodes []NodeInfo
}

// NodeInfo contains information about a node in the cluster
type NodeInfo struct {
	Hostname      string
	IP            string
	Role          environment.Role
	JoinedAt      time.Time
	PreferredRole string           // Preferred role specified during join
	Resources     *ResourceInfo    // Node resource information
}

// ResourceInfo contains node resource information (defined in registration.go)

// Options for cluster detection
type Options struct {
	JoinCluster   string // Explicit master address
	SingleNode    bool   // Force single-node mode
	PreferredRole string // Preferred role when joining
	AutoDiscover  bool   // Enable auto-discovery
}

// ClusterConfig represents the cluster configuration file
type ClusterConfig struct {
	Cluster struct {
		ID     string `yaml:"id"`
		Master string `yaml:"master"`
		Discovery struct {
			Method string `yaml:"method"`
			Port   int    `yaml:"port"`
		} `yaml:"discovery"`
		Roles struct {
			Assignment      string `yaml:"assignment"`
			RebalanceOnJoin bool   `yaml:"rebalance_on_join"`
		} `yaml:"roles"`
	} `yaml:"cluster"`
}

// DetectClusterState determines if this is a single node or joining existing cluster
func DetectClusterState(rc *eos_io.RuntimeContext, opts Options) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Detecting cluster state",
		zap.String("join_cluster", opts.JoinCluster),
		zap.Bool("single_node", opts.SingleNode),
		zap.Bool("auto_discover", opts.AutoDiscover))

	// 1. Check explicit single-node flag
	if opts.SingleNode {
		logger.Info("Explicit single-node mode requested")
		return &ClusterInfo{
			IsSingleNode: true,
			IsMaster:     true,
			NodeCount:    1,
			MyRole:       environment.RoleMonolith,
		}, nil
	}

	// 2. Check explicit join-cluster flag
	if opts.JoinCluster != "" {
		logger.Info("Explicit cluster join requested",
			zap.String("master", opts.JoinCluster))
		return detectFromMaster(rc, opts.JoinCluster, opts.PreferredRole)
	}

	// 3. Check local configuration file
	if info, err := detectFromConfigFile(rc); err == nil && info != nil {
		logger.Info("Cluster information found in config file",
			zap.String("master", info.MasterAddr))
		return info, nil
	}

	// 4. Try auto-discovery if enabled
	if opts.AutoDiscover {
		if info, err := autoDiscoverCluster(rc); err == nil && info != nil {
			logger.Info("Cluster discovered via auto-discovery",
				zap.String("master", info.MasterAddr))
			return info, nil
		}
	}

	// 5. Check if Salt master is already running locally
	if isSaltMasterRunning(rc) {
		logger.Info("Salt master already running locally, assuming single-node")
		return &ClusterInfo{
			IsSingleNode: true,
			IsMaster:     true,
			NodeCount:    1,
			MyRole:       environment.RoleMonolith,
		}, nil
	}

	// 6. Default to single-node
	logger.Info("No existing cluster detected, defaulting to single-node mode")
	return &ClusterInfo{
		IsSingleNode: true,
		IsMaster:     true,
		NodeCount:    1,
		MyRole:       environment.RoleMonolith,
	}, nil
}

// detectFromMaster queries the Salt master for cluster information
func detectFromMaster(rc *eos_io.RuntimeContext, masterAddr string, preferredRole string) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test connectivity to Salt master
	conn, err := net.DialTimeout("tcp", masterAddr+":4506", 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to Salt master at %s: %w", masterAddr, err)
	}
	conn.Close()

	logger.Info("Connected to Salt master, querying cluster state")

	// Use basic cluster detection (HashiCorp migration - Consul integration TODO)
	logger.Info("Using basic cluster detection - Consul integration pending")
	
	// Fallback to direct Salt commands for now
	return queryClusterViaSalt(rc, masterAddr, preferredRole)
}

// queryClusterViaAPI function removed - replaced with Consul-based discovery (HashiCorp migration)
func queryClusterViaAPI(rc *eos_io.RuntimeContext, _ interface{}, masterAddr string, preferredRole string) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("API-based cluster query not implemented - using fallback to Salt commands")
	
	// Fallback to Salt-based detection
	return queryClusterViaSalt(rc, masterAddr, preferredRole)
}

// queryClusterViaSalt queries cluster information using direct Salt commands
func queryClusterViaSalt(rc *eos_io.RuntimeContext, masterAddr string, preferredRole string) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Querying cluster state via Salt commands")
	
	// Query accepted minion keys to determine cluster size
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-key",
		Args:    []string{"-L", "--no-color"},
		Capture: true,
		Timeout: 15 * time.Second,
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to query Salt keys: %w", err)
	}
	
	// Parse the salt-key output to count nodes
	nodes := parseSaltKeyOutput(output)
	
	// Try to get grains information for more details
	if len(nodes) > 0 {
		enrichNodesWithGrains(rc, &nodes)
	}
	
	// Determine role
	assignedRole := determineNodeRole(preferredRole, len(nodes))
	
	// Generate cluster ID if not available
	clusterID := fmt.Sprintf("salt-cluster-%s", masterAddr)
	
	logger.Info("Successfully queried cluster state via Salt commands",
		zap.String("cluster_id", clusterID),
		zap.Int("node_count", len(nodes)),
		zap.String("assigned_role", string(assignedRole)))
	
	return &ClusterInfo{
		IsSingleNode:  len(nodes) <= 1,
		IsMaster:      false,
		MasterAddr:    masterAddr,
		NodeCount:     len(nodes) + 1,
		MyRole:        assignedRole,
		ClusterID:     clusterID,
		ExistingNodes: nodes,
	}, nil
}

// queryClusterNodes queries the existing nodes in the cluster
func queryClusterNodes(rc *eos_io.RuntimeContext, _ interface{}) ([]NodeInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// This would make an API call to get minion information
	// For now, we'll implement a basic version
	logger.Debug("Querying cluster nodes via API (basic implementation)")
	
	// In a full implementation, this would call something like:
	// resp, err := apiClient.makeRequest("GET", "/minions", nil)
	// For now, return empty list - nodes will be discovered during bootstrap
	
	return []NodeInfo{}, nil
}

// parseSaltKeyOutput parses the output of salt-key -L to extract node information
func parseSaltKeyOutput(output string) []NodeInfo {
	var nodes []NodeInfo
	
	lines := strings.Split(output, "\n")
	inAcceptedSection := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "Accepted Keys:") {
			inAcceptedSection = true
			continue
		}
		
		if strings.Contains(line, "Denied Keys:") || 
		   strings.Contains(line, "Unaccepted Keys:") ||
		   strings.Contains(line, "Rejected Keys:") {
			inAcceptedSection = false
			continue
		}
		
		if inAcceptedSection && line != "" && !strings.Contains(line, "Keys:") {
			// Extract hostname from the key name
			hostname := line
			nodes = append(nodes, NodeInfo{
				Hostname:      hostname,
				IP:            "", // Will be populated by grains if available
				Role:          environment.RoleApp, // Default role
				JoinedAt:      time.Now(), // Approximate
				PreferredRole: "auto",
			})
		}
	}
	
	return nodes
}

// enrichNodesWithGrains adds additional information to nodes using Salt grains
func enrichNodesWithGrains(rc *eos_io.RuntimeContext, nodes *[]NodeInfo) {
	logger := otelzap.Ctx(rc.Ctx)
	
	for i := range *nodes {
		node := &(*nodes)[i]
		
		// Try to get IP address from grains
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "salt",
			Args:    []string{node.Hostname, "grains.get", "ipv4", "--no-color"},
			Capture: true,
			Timeout: 10 * time.Second,
		})
		
		if err == nil && output != "" {
			// Parse the IP address from grains output
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, ".") && !strings.Contains(line, ":") {
					// Looks like an IPv4 address
					if net.ParseIP(strings.Trim(line, " -")) != nil {
						node.IP = strings.Trim(line, " -")
						break
					}
				}
			}
		}
		
		logger.Debug("Enriched node information",
			zap.String("hostname", node.Hostname),
			zap.String("ip", node.IP))
	}
}

// determineNodeRole determines the appropriate role for this node
func determineNodeRole(preferredRole string, existingNodeCount int) environment.Role {
	// If user specified a role preference, try to honor it
	switch strings.ToLower(preferredRole) {
	case "data", "storage":
		return environment.RoleData
	case "compute", "app":
		return environment.RoleApp
	case "message", "messaging":
		return environment.RoleMessage
	case "observe", "monitoring":
		return environment.RoleObserve
	case "core":
		return environment.RoleCore
	case "edge":
		return environment.RoleEdge
	case "auto", "":
		// Auto-assign based on cluster size and needs
		if existingNodeCount == 0 {
			return environment.RoleApp // First node gets app role
		}
		// For subsequent nodes, default to app role
		// In a more sophisticated implementation, this would check
		// what roles are already filled and assign accordingly
		return environment.RoleApp
	default:
		// Unknown role, default to app
		return environment.RoleApp
	}
}

// detectFromConfigFile reads cluster info from local config
func detectFromConfigFile(rc *eos_io.RuntimeContext) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	configPath := "/etc/eos/cluster.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Debug("Cluster config file not found", zap.String("path", configPath))
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cluster config: %w", err)
	}

	var config ClusterConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse cluster config: %w", err)
	}

	if config.Cluster.Master == "" {
		return nil, fmt.Errorf("no master address in cluster config")
	}

	logger.Info("Found cluster configuration",
		zap.String("cluster_id", config.Cluster.ID),
		zap.String("master", config.Cluster.Master))

	return detectFromMaster(rc, config.Cluster.Master, "")
}

// autoDiscoverCluster attempts to discover Salt master via multicast/broadcast
func autoDiscoverCluster(rc *eos_io.RuntimeContext) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Attempting cluster auto-discovery")

	// Create UDP socket for multicast
	addr, err := net.ResolveUDPAddr("udp", "224.0.0.1:4505")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve multicast address: %w", err)
	}

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for multicast: %w", err)
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Send discovery request
	discoveryMsg := []byte("EOS_CLUSTER_DISCOVERY_v1")
	if _, err := conn.Write(discoveryMsg); err != nil {
		return nil, fmt.Errorf("failed to send discovery message: %w", err)
	}

	// Wait for response
	buffer := make([]byte, 1024)
	n, senderAddr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		logger.Debug("No discovery response received", zap.Error(err))
		return nil, err
	}

	// Parse response
	var response struct {
		ClusterID  string `json:"cluster_id"`
		MasterAddr string `json:"master_addr"`
		NodeCount  int    `json:"node_count"`
	}
	
	if err := json.Unmarshal(buffer[:n], &response); err != nil {
		return nil, fmt.Errorf("failed to parse discovery response: %w", err)
	}

	logger.Info("Discovered cluster via multicast",
		zap.String("cluster_id", response.ClusterID),
		zap.String("master", response.MasterAddr),
		zap.String("sender", senderAddr.String()))

	return detectFromMaster(rc, response.MasterAddr, "")
}

// isSaltMasterRunning checks if Salt master is already running
func isSaltMasterRunning(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking if Salt master is running...")
	
	// Check if salt-master service is running
	logger.Debug("Checking systemctl is-active salt-master")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "salt-master"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil && strings.TrimSpace(output) == "active" {
		logger.Debug("Salt master service is active")
		return true
	}
	logger.Debug("Salt master service check result", 
		zap.String("output", output),
		zap.Error(err))

	// Check if salt-master process is running
	logger.Debug("Checking pgrep for salt-master process")
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "salt-master"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		logger.Debug("Salt master process found")
		return true
	}
	logger.Debug("Salt master process not found")

	return false
}

// SaveClusterConfig saves cluster configuration for future use
func SaveClusterConfig(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	config := ClusterConfig{}
	config.Cluster.ID = info.ClusterID
	config.Cluster.Master = info.MasterAddr
	config.Cluster.Discovery.Method = "multicast"
	config.Cluster.Discovery.Port = 4505
	config.Cluster.Roles.Assignment = "automatic"
	config.Cluster.Roles.RebalanceOnJoin = true

	data, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster config: %w", err)
	}

	configDir := "/etc/eos"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "cluster.yaml")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cluster config: %w", err)
	}

	logger.Info("Saved cluster configuration",
		zap.String("path", configPath),
		zap.String("cluster_id", info.ClusterID))

	return nil
}