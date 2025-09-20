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

	NodeCount     int
	MyRole        environment.Role
	ClusterID     string
	ExistingNodes []NodeInfo
}

// NodeInfo contains information about a node in the cluster
type NodeInfo struct {
	Hostname      string
	IP            string
	Role          environment.Role
	JoinedAt      time.Time
	PreferredRole string        // Preferred role specified during join
	Resources     *ResourceInfo // Node resource information
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
		ID        string `yaml:"id"`
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
			NodeCount:    1,
			MyRole:       environment.RoleMonolith,
		}, nil
	}

	// 2. Check explicit join-cluster flag
	if opts.JoinCluster != "" {
		logger.Info("Explicit cluster join requested")
		// TODO: Implement HashiCorp cluster join logic
		return &ClusterInfo{
			IsSingleNode: false,
			NodeCount:    2,                        // Assume joining existing cluster
			MyRole:       environment.RoleMonolith, // TODO: Add proper worker role
		}, nil
	}

	// 3. Check local configuration file
	if info, err := detectFromConfigFile(rc); err == nil && info != nil {
		logger.Info("Cluster information found in config file")
		return info, nil
	}

	// 4. Try auto-discovery if enabled
	if opts.AutoDiscover {
		if info, err := autoDiscoverCluster(rc); err == nil && info != nil {
			logger.Info("Cluster discovered via auto-discovery")
			return info, nil
		}
	}

	// 6. Default to single-node
	logger.Info("No existing cluster detected, defaulting to single-node mode")
	return &ClusterInfo{
		IsSingleNode: true,
		NodeCount:    1,
		MyRole:       environment.RoleMonolith,
	}, nil
}


// queryClusterViaConsul queries cluster information using HashiCorp Consul
func queryClusterViaConsul(rc *eos_io.RuntimeContext, consulAddr string, preferredRole string) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Querying cluster via HashiCorp Consul",
		zap.String("consul_addr", consulAddr),
		zap.String("preferred_role", preferredRole))

	// Use Consul API to discover cluster members
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"members", "-format=json"},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	var nodeCount int = 1
	var existingNodes []NodeInfo
	var clusterID string = "eos-cluster-1"

	if err != nil {
		logger.Warn("Failed to query Consul members, defaulting to single-node",
			zap.Error(err))
	} else {
		// Parse Consul members output to get actual cluster info
		logger.Debug("Consul members query successful", zap.String("output", output))
		// For now, parse basic info - in production this would parse JSON
		if strings.Contains(output, "alive") {
			nodeCount = strings.Count(output, "alive")
			clusterID = "eos-consul-cluster"
		}
	}

	// Determine role based on cluster size and preference
	var myRole environment.Role
	switch {
	case nodeCount == 1:
		myRole = environment.RoleMonolith
	case preferredRole == "core":
		myRole = environment.RoleCore
	case preferredRole == "edge":
		myRole = environment.RoleEdge
	case preferredRole == "data":
		myRole = environment.RoleData
	default:
		myRole = environment.RoleApp // Default to app for multi-node
	}

	clusterInfo := &ClusterInfo{
		ClusterID:     clusterID,
		NodeCount:     nodeCount,
		MyRole:        myRole,
		IsSingleNode:  nodeCount <= 1,
		ExistingNodes: existingNodes,
	}

	logger.Info("Cluster information retrieved via Consul",
		zap.String("cluster_id", clusterInfo.ClusterID),
		zap.Int("node_count", clusterInfo.NodeCount),
		zap.String("role", string(clusterInfo.MyRole)))

	return clusterInfo, nil
}


// detectFromConsul detects cluster information using HashiCorp Consul
func detectFromConsul(rc *eos_io.RuntimeContext, port int) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	consulAddr := fmt.Sprintf("localhost:%d", port)
	logger.Info("Detecting cluster via HashiCorp Consul",
		zap.String("consul_addr", consulAddr))

	// TODO: Implement actual Consul API calls to discover cluster members
	// This would use the Consul API to:
	// 1. Query cluster members: GET /v1/agent/members
	// 2. Get cluster leader: GET /v1/status/leader
	// 3. Determine node roles and health status

	// For now, return single-node configuration
	// In a real implementation, this would make HTTP calls to Consul API
	logger.Info("HashiCorp Consul cluster detection - implementing administrator escalation pattern")

	return &ClusterInfo{
		IsSingleNode:  true,
		NodeCount:     1,
		MyRole:        environment.RoleMonolith,
		ClusterID:     "consul-cluster-local",
		ExistingNodes: []NodeInfo{},
	}, nil
}

// parseKeyOutput parses the output of -key -L to extract node information
func parseKeyOutput(output string) []NodeInfo {
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
				IP:            "",                  // Will be populated by s if available
				Role:          environment.RoleApp, // Default role
				JoinedAt:      time.Now(),          // Approximate
				PreferredRole: "auto",
			})
		}
	}

	return nodes
}

// enrichNodesWiths adds additional information to nodes using  s
func enrichNodesWiths(rc *eos_io.RuntimeContext, nodes *[]NodeInfo) {
	logger := otelzap.Ctx(rc.Ctx)

	for i := range *nodes {
		node := &(*nodes)[i]

		// Try to get IP address from s
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "",
			Args:    []string{node.Hostname, "s.get", "ipv4", "--no-color"},
			Capture: true,
			Timeout: 10 * time.Second,
		})

		if err == nil && output != "" {
			// Parse the IP address from s output
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

	// Check if Consul cluster is configured for HashiCorp-based discovery
	if config.Cluster.Discovery.Method == "consul" {
		logger.Info("Consul discovery configured, attempting HashiCorp cluster detection",
			zap.String("method", config.Cluster.Discovery.Method),
			zap.Int("port", config.Cluster.Discovery.Port))

		if info, err := detectFromConsul(rc, config.Cluster.Discovery.Port); err == nil && info != nil {
			return info, nil
		}
	}

	// Fallback to single-node if no HashiCorp discovery configured
	logger.Info("No HashiCorp discovery configured, defaulting to single-node",
		zap.String("cluster_id", config.Cluster.ID))

	return &ClusterInfo{
		IsSingleNode:  true,
		NodeCount:     1,
		MyRole:        environment.RoleMonolith,
		ClusterID:     config.Cluster.ID,
		ExistingNodes: []NodeInfo{},
	}, nil
}

// autoDiscoverCluster attempts to discover  master via multicast/broadcast
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
		ClusterID string `json:"cluster_id"`
		NodeCount int    `json:"node_count"`
	}

	if err := json.Unmarshal(buffer[:n], &response); err != nil {
		return nil, fmt.Errorf("failed to parse discovery response: %w", err)
	}

	logger.Info("HashiCorp cluster auto-discovery - using Consul service discovery",
		zap.String("cluster_id", response.ClusterID),
		zap.String("sender", senderAddr.String()))

	// Use HashiCorp Consul for cluster discovery instead of SaltStack master
	return detectFromConsul(rc, 8500) // Default Consul port
}

// SaveClusterConfig saves cluster configuration for future use
func SaveClusterConfig(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	config := ClusterConfig{}
	config.Cluster.ID = info.ClusterID
	config.Cluster.Discovery.Method = "consul"
	config.Cluster.Discovery.Port = 8500
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
