// pkg/consul/health_check.go
// Business logic for Consul cluster health checks

package consul

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HealthCheckResult contains the comprehensive health status of Consul
type HealthCheckResult struct {
	Timestamp      time.Time
	Overall        HealthStatus
	Agent          AgentHealth
	Cluster        ClusterHealth
	Services       ServicesHealth
	KV             KVHealth
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
	Status         HealthStatus
	MemberCount    int
	Members        []ClusterMemberHealth
	LeaderPresent  bool
	Leader         string
	RaftHealth     string
	QuorumSize     int
	ConsensusOK    bool
	Issues         []string
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
	Status         HealthStatus
	TotalServices  int
	HealthyServices int
	Services       []ServiceHealth
	Issues         []string
}

// ServiceHealth represents a single service's health
type ServiceHealth struct {
	Name    string
	Healthy bool
	Checks  int
	Passing int
	Warning int
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

// checkAgentHealth checks the local Consul agent's health
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

	// Try to get agent info
	infoOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"info"},
		Capture: true,
	})

	if err != nil {
		health.Reachable = false
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, "Consul agent not responding to queries")
		return health, nil
	}

	health.Reachable = true

	// Parse agent info
	info := parseConsulInfo(infoOutput)

	if agent, ok := info["agent"].(map[string]string); ok {
		health.Mode = agent["server"]
		health.NodeName = agent["node"]
		health.Datacenter = agent["datacenter"]
	}

	if build, ok := info["build"].(map[string]string); ok {
		health.Version = build["version"]
	}

	if raft, ok := info["raft"].(map[string]string); ok {
		if state, ok := raft["state"]; ok && state != "Leader" && state != "Follower" {
			health.Issues = append(health.Issues, fmt.Sprintf("Raft state unusual: %s", state))
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

// checkClusterHealth checks the health of the Consul cluster
func checkClusterHealth(rc *eos_io.RuntimeContext) (*ClusterHealth, error) {
	health := &ClusterHealth{
		Status:  HealthStatusUnknown,
		Members: make([]ClusterMemberHealth, 0),
		Issues:  make([]string, 0),
	}

	// Get cluster members
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"members", "-detailed"},
		Capture: true,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get cluster members: %w", err)
	}

	// Parse members
	lines := strings.Split(output, "\n")
	aliveCount := 0

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header and empty lines
		}

		member := parseClusterMember(line)
		if member != nil {
			health.Members = append(health.Members, *member)
			if member.Status == "alive" {
				aliveCount++
			}
		}
	}

	health.MemberCount = len(health.Members)

	// Check for leader
	leaderOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"operator", "raft", "list-peers"},
		Capture: true,
	})

	if err == nil {
		health.LeaderPresent, health.Leader = parseLeaderInfo(leaderOutput)
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

// checkServicesHealth checks the health of registered services
func checkServicesHealth(rc *eos_io.RuntimeContext) (*ServicesHealth, error) {
	health := &ServicesHealth{
		Status:   HealthStatusUnknown,
		Services: make([]ServiceHealth, 0),
		Issues:   make([]string, 0),
	}

	// Get list of services
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"catalog", "services"},
		Capture: true,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	serviceNames := strings.Split(strings.TrimSpace(output), "\n")
	health.TotalServices = len(serviceNames)

	// Check health of each service
	for _, serviceName := range serviceNames {
		serviceName = strings.TrimSpace(serviceName)
		if serviceName == "" || serviceName == "consul" {
			continue // Skip empty and consul service itself
		}

		serviceHealth := checkServiceHealth(rc, serviceName)
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

// checkServiceHealth checks the health of a single service
func checkServiceHealth(rc *eos_io.RuntimeContext, serviceName string) ServiceHealth {
	health := ServiceHealth{
		Name:    serviceName,
		Healthy: false,
	}

	// Get service health checks
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"health", "service", serviceName, "-format=json"},
		Capture: true,
	})

	if err != nil {
		return health
	}

	// Parse JSON
	var checks []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &checks); err != nil {
		return health
	}

	health.Checks = len(checks)

	for _, check := range checks {
		if checksList, ok := check["Checks"].([]interface{}); ok {
			for _, c := range checksList {
				if checkData, ok := c.(map[string]interface{}); ok {
					status := checkData["Status"].(string)
					switch status {
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
	}

	health.Healthy = health.Critical == 0 && health.Checks > 0

	return health
}

// checkKVHealth checks the health of the KV store
func checkKVHealth(rc *eos_io.RuntimeContext) (*KVHealth, error) {
	health := &KVHealth{
		Status: HealthStatusUnknown,
		Issues: make([]string, 0),
	}

	testKey := "eos/health/check/" + fmt.Sprintf("%d", time.Now().Unix())
	testValue := "health-check-test"

	// Try to write
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"kv", "put", testKey, testValue},
		Capture: true,
	})

	if err != nil {
		health.Accessible = false
		health.Writeable = false
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, "KV store not writeable")
		return health, nil
	}

	health.Writeable = true

	// Try to read
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"kv", "get", testKey},
		Capture: true,
	})

	if err != nil || strings.TrimSpace(output) != testValue {
		health.Accessible = false
		health.Status = HealthStatusDegraded
		health.Issues = append(health.Issues, "KV store read failed")
	} else {
		health.Accessible = true
		health.Status = HealthStatusHealthy
	}

	// Clean up test key
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"kv", "delete", testKey},
		Capture: true,
	})

	return health, nil
}

// Helper functions

func parseConsulInfo(output string) map[string]interface{} {
	info := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	currentSection := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Section headers
		if !strings.Contains(line, "=") && !strings.Contains(line, ":") {
			currentSection = line
			info[currentSection] = make(map[string]string)
			continue
		}

		// Key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if currentSection != "" {
				if sectionMap, ok := info[currentSection].(map[string]string); ok {
					sectionMap[key] = value
				}
			} else {
				info[key] = value
			}
		}
	}

	return info
}

func parseClusterMember(line string) *ClusterMemberHealth {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	member := &ClusterMemberHealth{
		Name:    fields[0],
		Address: fields[1],
		Status:  fields[2],
		Tags:    make(map[string]string),
	}

	// Parse tags (dc=dc1,role=node,...)
	if len(fields) > 4 {
		tagsPart := strings.Join(fields[4:], " ")
		tags := strings.Split(tagsPart, ",")
		for _, tag := range tags {
			parts := strings.SplitN(tag, "=", 2)
			if len(parts) == 2 {
				member.Tags[parts[0]] = parts[1]
			}
		}

		if role, ok := member.Tags["role"]; ok {
			member.Role = role
		}
	}

	return member
}

func parseLeaderInfo(output string) (bool, string) {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		if strings.Contains(line, "leader") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				return true, fields[0]
			}
		}
	}
	return false, ""
}

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
