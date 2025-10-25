// pkg/consul/health_check.go
//
// Business logic for Consul cluster health checks using Consul SDK.
// Migrated from shell commands to SDK calls for improved reliability.
//
// Last Updated: 2025-01-25

package consul

import (
	"fmt"
	"strings"
	"time"

	consulsdk "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/sdk"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HealthCheckResult contains the comprehensive health status of Consul
type HealthCheckResult struct {
	Timestamp       time.Time
	Overall         HealthStatus
	Agent           AgentHealth
	Cluster         ClusterHealth
	Services        ServicesHealth
	KV              KVHealth
	Recommendations []string
}

// HealthStatus represents the overall health status
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// AgentHealth represents the local agent's health
type AgentHealth struct {
	Status      HealthStatus
	Running     bool
	Reachable   bool
	Mode        string // server, client, dev
	Version     string
	Datacenter  string
	NodeName    string
	BindAddress string
	Uptime      string
	Issues      []string
}

// ClusterHealth represents the cluster's health
type ClusterHealth struct {
	Status        HealthStatus
	MemberCount   int
	Members       []ClusterMemberHealth
	LeaderPresent bool
	Leader        string
	RaftHealth    string
	QuorumSize    int
	ConsensusOK   bool
	Issues        []string
}

// ClusterMemberHealth represents a single cluster member's health
type ClusterMemberHealth struct {
	Name           string
	Address        string
	Status         string // alive, left, failed
	Role           string // server, client
	ProtocolStatus string
	Tags           map[string]string
}

// ServicesHealth represents the health of registered services
type ServicesHealth struct {
	Status          HealthStatus
	TotalServices   int
	HealthyServices int
	Services        []ServiceHealth
	Issues          []string
}

// ServiceHealth represents a single service's health
type ServiceHealth struct {
	Name     string
	Healthy  bool
	Checks   int
	Passing  int
	Warning  int
	Critical int
}

// KVHealth represents the KV store health
type KVHealth struct {
	Status     HealthStatus
	Accessible bool
	Writeable  bool
	Issues     []string
}

// CheckHealth performs a comprehensive health check of the Consul cluster
func CheckHealth(rc *eos_io.RuntimeContext) (*HealthCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Starting comprehensive Consul health check")

	result := &HealthCheckResult{
		Timestamp:       time.Now(),
		Overall:         HealthStatusUnknown,
		Recommendations: make([]string, 0),
	}

	// ASSESS - Phase 1: Check agent health
	logger.Debug("Phase 1: Checking local agent health")
	agentHealth, err := checkAgentHealth(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to check agent health: %w", err)
	}
	result.Agent = *agentHealth

	// ASSESS - Phase 2: Check cluster health (if agent is healthy)
	if agentHealth.Running {
		logger.Debug("Phase 2: Checking cluster health")
		clusterHealth, err := checkClusterHealth(rc)
		if err != nil {
			logger.Warn("Failed to check cluster health", zap.Error(err))
			clusterHealth = &ClusterHealth{
				Status: HealthStatusUnknown,
				Issues: []string{fmt.Sprintf("Failed to query cluster: %v", err)},
			}
		}
		result.Cluster = *clusterHealth

		// ASSESS - Phase 3: Check services health
		logger.Debug("Phase 3: Checking services health")
		servicesHealth, err := checkServicesHealth(rc)
		if err != nil {
			logger.Warn("Failed to check services health", zap.Error(err))
			servicesHealth = &ServicesHealth{
				Status: HealthStatusUnknown,
				Issues: []string{fmt.Sprintf("Failed to query services: %v", err)},
			}
		}
		result.Services = *servicesHealth

		// ASSESS - Phase 4: Check KV store health
		logger.Debug("Phase 4: Checking KV store health")
		kvHealth, err := checkKVHealth(rc)
		if err != nil {
			logger.Warn("Failed to check KV health", zap.Error(err))
			kvHealth = &KVHealth{
				Status: HealthStatusUnknown,
				Issues: []string{fmt.Sprintf("Failed to query KV store: %v", err)},
			}
		}
		result.KV = *kvHealth
	}

	// EVALUATE - Calculate overall health
	result.Overall = calculateOverallHealth(result)

	// EVALUATE - Generate recommendations
	result.Recommendations = generateRecommendations(result)

	logger.Debug("Health check completed",
		zap.String("overall_status", string(result.Overall)))

	return result, nil
}

// checkAgentHealth checks the local Consul agent's health using SDK
func checkAgentHealth(rc *eos_io.RuntimeContext) (*AgentHealth, error) {
	logger := otelzap.Ctx(rc.Ctx)
	health := &AgentHealth{
		Status: HealthStatusUnknown,
		Issues: make([]string, 0),
	}

	// Check if systemd service is running
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true,
	})

	if err != nil {
		health.Running = false
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, "Consul service is not running")
		logger.Debug("Consul service not running")
		return health, nil
	}

	health.Running = strings.TrimSpace(output) == "active"

	// Create SDK client
	client, err := consulsdk.NewClient()
	if err != nil {
		health.Reachable = false
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, fmt.Sprintf("Failed to create Consul client: %v", err))
		return health, nil
	}

	// Try to get agent info using SDK
	info, err := consulsdk.AgentSelf(rc.Ctx, client)
	if err != nil {
		health.Reachable = false
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, "Consul agent not responding to queries")
		return health, nil
	}

	health.Reachable = true

	// Parse agent info from SDK response
	if configSection, ok := info["Config"]; ok {
		if datacenter, ok := configSection["Datacenter"].(string); ok {
			health.Datacenter = datacenter
		}
		if nodeName, ok := configSection["NodeName"].(string); ok {
			health.NodeName = nodeName
		}
		if server, ok := configSection["Server"].(bool); ok {
			if server {
				health.Mode = "server"
			} else {
				health.Mode = "client"
			}
		}
	}

	if statsSection, ok := info["Stats"]; ok {
		if raft, ok := statsSection["raft"].(map[string]interface{}); ok {
			if state, ok := raft["state"].(string); ok {
				if state != "Leader" && state != "Follower" && state != "" {
					health.Issues = append(health.Issues, fmt.Sprintf("Raft state unusual: %s", state))
				}
			}
		}
	}

	// Get version from agent member info
	members, err := consulsdk.AgentMembers(rc.Ctx, client, false)
	if err == nil && len(members) > 0 {
		// Find ourselves in the member list
		for _, member := range members {
			if member.Name == health.NodeName {
				if version, ok := member.Tags["build"]; ok {
					health.Version = version
				}
				break
			}
		}
	}

	// Overall agent health
	if health.Running && health.Reachable && len(health.Issues) == 0 {
		health.Status = HealthStatusHealthy
	} else if health.Running && health.Reachable {
		health.Status = HealthStatusDegraded
	} else {
		health.Status = HealthStatusUnhealthy
	}

	return health, nil
}

// checkClusterHealth checks the health of the Consul cluster using SDK
func checkClusterHealth(rc *eos_io.RuntimeContext) (*ClusterHealth, error) {
	health := &ClusterHealth{
		Status:  HealthStatusUnknown,
		Members: make([]ClusterMemberHealth, 0),
		Issues:  make([]string, 0),
	}

	// Create SDK client
	client, err := consulsdk.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Get cluster members using SDK
	members, err := consulsdk.AgentMembers(rc.Ctx, client, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster members: %w", err)
	}

	// Convert SDK members to our health structure
	aliveCount := 0
	for _, member := range members {
		memberHealth := ClusterMemberHealth{
			Name:    member.Name,
			Address: member.Addr,
			Status:  fmt.Sprintf("%d", member.Status), // Status is int in SDK
			Tags:    member.Tags,
		}

		// Determine status string from SDK status code
		// SDK uses: 1=alive, 2=left, 3=failed
		switch member.Status {
		case 1:
			memberHealth.Status = "alive"
			aliveCount++
		case 2:
			memberHealth.Status = "left"
		case 3:
			memberHealth.Status = "failed"
		default:
			memberHealth.Status = "unknown"
		}

		// Get role from tags
		if role, ok := member.Tags["role"]; ok {
			memberHealth.Role = role
		}

		health.Members = append(health.Members, memberHealth)
	}

	health.MemberCount = len(health.Members)

	// Check for leader using SDK
	raftConfig, err := consulsdk.OperatorRaftGetConfiguration(rc.Ctx, client)
	if err == nil {
		// Find the leader in the raft configuration
		for _, server := range raftConfig.Servers {
			if server.Leader {
				health.LeaderPresent = true
				health.Leader = server.Address
				break
			}
		}
	}

	// Evaluate cluster health
	if health.MemberCount == 0 {
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, "No cluster members found")
	} else if aliveCount < health.MemberCount {
		health.Status = HealthStatusDegraded
		health.Issues = append(health.Issues,
			fmt.Sprintf("%d of %d members not alive", health.MemberCount-aliveCount, health.MemberCount))
	} else if !health.LeaderPresent {
		health.Status = HealthStatusDegraded
		health.Issues = append(health.Issues, "No cluster leader elected")
	} else {
		health.Status = HealthStatusHealthy
	}

	return health, nil
}

// checkServicesHealth checks the health of registered services using SDK
func checkServicesHealth(rc *eos_io.RuntimeContext) (*ServicesHealth, error) {
	health := &ServicesHealth{
		Status:   HealthStatusUnknown,
		Services: make([]ServiceHealth, 0),
		Issues:   make([]string, 0),
	}

	// Create SDK client
	client, err := consulsdk.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Get list of services using SDK
	services, err := consulsdk.CatalogServices(rc.Ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	health.TotalServices = len(services)

	// Check health of each service
	for serviceName := range services {
		if serviceName == "" || serviceName == "consul" {
			continue // Skip empty and consul service itself
		}

		serviceHealth := checkServiceHealth(rc, client, serviceName)
		health.Services = append(health.Services, serviceHealth)

		if serviceHealth.Healthy {
			health.HealthyServices++
		}
	}

	// Evaluate services health
	if health.TotalServices == 0 {
		health.Status = HealthStatusHealthy // No services is OK
	} else if health.HealthyServices == health.TotalServices {
		health.Status = HealthStatusHealthy
	} else if health.HealthyServices > 0 {
		health.Status = HealthStatusDegraded
		health.Issues = append(health.Issues,
			fmt.Sprintf("%d of %d services unhealthy", health.TotalServices-health.HealthyServices, health.TotalServices))
	} else {
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, "All services unhealthy")
	}

	return health, nil
}

// checkServiceHealth checks the health of a single service using SDK
func checkServiceHealth(rc *eos_io.RuntimeContext, client *consulapi.Client, serviceName string) ServiceHealth {
	health := ServiceHealth{
		Name:    serviceName,
		Healthy: false,
	}

	// Get service health checks using SDK
	entries, err := consulsdk.HealthService(rc.Ctx, client, serviceName, "", false)
	if err != nil {
		return health
	}

	// Count health check statuses
	for _, entry := range entries {
		if entry.Checks != nil {
			for _, check := range entry.Checks {
				health.Checks++
				switch check.Status {
				case "passing":
					health.Passing++
				case "warning":
					health.Warning++
				case "critical":
					health.Critical++
				}
			}
		}
	}

	health.Healthy = health.Critical == 0 && health.Checks > 0

	return health
}

// checkKVHealth checks the health of the KV store using SDK
func checkKVHealth(rc *eos_io.RuntimeContext) (*KVHealth, error) {
	health := &KVHealth{
		Status: HealthStatusUnknown,
		Issues: make([]string, 0),
	}

	// Create SDK client
	client, err := consulsdk.NewClient()
	if err != nil {
		health.Accessible = false
		health.Writeable = false
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, fmt.Sprintf("Failed to create Consul client: %v", err))
		return health, nil
	}

	testKey := "eos/health/check/" + fmt.Sprintf("%d", time.Now().Unix())
	testValue := []byte("health-check-test")

	// Try to write using SDK
	err = consulsdk.KVPut(rc.Ctx, client, testKey, testValue)
	if err != nil {
		health.Accessible = false
		health.Writeable = false
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, "KV store not writeable")
		return health, nil
	}

	health.Writeable = true

	// Try to read using SDK
	readValue, err := consulsdk.KVGet(rc.Ctx, client, testKey)
	if err != nil || string(readValue) != string(testValue) {
		health.Accessible = false
		health.Status = HealthStatusDegraded
		health.Issues = append(health.Issues, "KV store read failed")
	} else {
		health.Accessible = true
		health.Status = HealthStatusHealthy
	}

	// Clean up test key using SDK
	_ = consulsdk.KVDelete(rc.Ctx, client, testKey)

	return health, nil
}

// Helper functions
// NOTE: parseConsulInfo, parseClusterMember, and parseLeaderInfo have been removed
// as they are no longer needed after migration to Consul SDK.

func calculateOverallHealth(result *HealthCheckResult) HealthStatus {
	// If agent is down, overall is unhealthy
	if result.Agent.Status == HealthStatusUnhealthy {
		return HealthStatusUnhealthy
	}

	// Count health statuses
	unhealthyCount := 0
	degradedCount := 0

	statuses := []HealthStatus{
		result.Agent.Status,
		result.Cluster.Status,
		result.Services.Status,
		result.KV.Status,
	}

	for _, status := range statuses {
		switch status {
		case HealthStatusUnhealthy:
			unhealthyCount++
		case HealthStatusDegraded:
			degradedCount++
		}
	}

	// Overall health logic
	if unhealthyCount > 0 {
		return HealthStatusUnhealthy
	} else if degradedCount > 0 {
		return HealthStatusDegraded
	}

	return HealthStatusHealthy
}

func generateRecommendations(result *HealthCheckResult) []string {
	recommendations := make([]string, 0)

	// Agent recommendations
	if !result.Agent.Running {
		recommendations = append(recommendations, "Start Consul service: sudo systemctl start consul")
	}
	if !result.Agent.Reachable {
		recommendations = append(recommendations, "Check Consul logs: sudo journalctl -u consul -n 100")
	}

	// Cluster recommendations
	if !result.Cluster.LeaderPresent {
		recommendations = append(recommendations, "Check raft status: consul operator raft list-peers")
	}
	if result.Cluster.MemberCount < 3 && result.Agent.Mode == "server" {
		recommendations = append(recommendations, "Consider adding more servers for production (minimum 3 recommended)")
	}

	// Services recommendations
	if result.Services.HealthyServices < result.Services.TotalServices {
		recommendations = append(recommendations, "Check failing services: consul catalog services")
	}

	// KV recommendations
	if !result.KV.Accessible {
		recommendations = append(recommendations, "Check KV store permissions and Consul ACLs")
	}

	return recommendations
}
