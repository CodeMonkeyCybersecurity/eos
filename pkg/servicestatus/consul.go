// pkg/servicestatus/consul.go
package servicestatus

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulStatusProvider implements StatusProvider for Consul
type ConsulStatusProvider struct{}

// NewConsulStatusProvider creates a new Consul status provider
func NewConsulStatusProvider() *ConsulStatusProvider {
	return &ConsulStatusProvider{}
}

// ServiceName returns "Consul"
func (p *ConsulStatusProvider) ServiceName() string {
	return "Consul"
}

// GetStatus retrieves comprehensive Consul status
func (p *ConsulStatusProvider) GetStatus(rc *eos_io.RuntimeContext) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Gathering Consul status")

	status := &ServiceStatus{
		Name:      "Consul",
		CheckedAt: time.Now(),
		CheckedBy: getHostname(),
	}

	// Get basic status from existing consul package
	consulStatus, err := consul.CheckStatus(rc)
	if err != nil {
		logger.Warn("Failed to get consul status", zap.Error(err))
		consulStatus = &consul.Status{} // Use empty status
	}

	// Installation info
	status.Installation = p.getInstallationInfo(consulStatus)
	status.Version = consulStatus.Version

	// Service info
	status.Service = p.getServiceInfo(rc, consulStatus)

	// Configuration info
	status.Configuration = p.getConfigurationInfo(consulStatus)

	// Health info
	status.Health = p.getHealthInfo(rc)

	// Network info
	status.Network = p.getNetworkInfo(rc)

	// Integrations
	status.Integrations = p.getIntegrations(rc)

	// Cluster info
	status.Cluster = p.getClusterInfo(rc)

	return status, nil
}

// QuickCheck performs a fast health check
func (p *ConsulStatusProvider) QuickCheck(rc *eos_io.RuntimeContext) (HealthStatus, error) {
	// Quick systemctl check
	cmd := exec.Command("systemctl", "is-active", "consul")
	output, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(output)) != "active" {
		return HealthStatusUnhealthy, nil
	}

	// Quick HTTP API check
	cmd = exec.Command("consul", "operator", "raft", "list-peers")
	if err := cmd.Run(); err != nil {
		return HealthStatusDegraded, nil
	}

	return HealthStatusHealthy, nil
}

func (p *ConsulStatusProvider) getInstallationInfo(consulStatus *consul.Status) InstallationInfo {
	info := InstallationInfo{
		Installed: consulStatus.Installed,
		Version:   consulStatus.Version,
		ConfigDir: "/etc/consul.d",
		DataDir:   "/opt/consul",
	}

	if binaryPath, err := exec.LookPath("consul"); err == nil {
		info.BinaryPath = binaryPath
	}

	return info
}

func (p *ConsulStatusProvider) getServiceInfo(rc *eos_io.RuntimeContext, consulStatus *consul.Status) ServiceInfo {
	logger := otelzap.Ctx(rc.Ctx)
	info := ServiceInfo{
		Running: consulStatus.Running,
		Status:  consulStatus.ServiceStatus,
	}

	if consulStatus.Failed {
		info.FailureReason = "Service in failed state - check journalctl -xeu consul"
	}

	// Get enabled status
	cmd := exec.Command("systemctl", "is-enabled", "consul")
	if output, err := cmd.Output(); err == nil {
		info.Enabled = strings.TrimSpace(string(output)) == "enabled"
	}

	// Get PID and uptime if running
	if info.Running {
		if pid := p.getServicePID(); pid > 0 {
			info.PID = pid
			info.Uptime = p.getProcessUptime(pid)
		}
	}

	// Get restart count from systemd
	cmd = exec.Command("systemctl", "show", "consul", "--property=NRestarts")
	if output, err := cmd.Output(); err == nil {
		parts := strings.Split(string(output), "=")
		if len(parts) == 2 {
			if count, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
				info.RestartCount = count
			}
		}
	}

	logger.Debug("Consul service info gathered",
		zap.Bool("running", info.Running),
		zap.Int("pid", info.PID))

	return info
}

func (p *ConsulStatusProvider) getConfigurationInfo(consulStatus *consul.Status) ConfigurationInfo {
	info := ConfigurationInfo{
		Valid:      consulStatus.ConfigValid,
		ConfigPath: "/etc/consul.d/consul.hcl",
		Details:    make(map[string]string),
	}

	// Try to read config details
	if configData, err := os.ReadFile("/etc/consul.d/consul.hcl"); err == nil {
		configStr := string(configData)

		// Extract datacenter
		if strings.Contains(configStr, "datacenter") {
			scanner := bufio.NewScanner(bytes.NewReader(configData))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "datacenter") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						dc := strings.Trim(strings.TrimSpace(parts[1]), `"`)
						info.Details["Datacenter"] = dc
					}
				}
			}
		}

		// Check for server mode
		if strings.Contains(configStr, `server = true`) {
			info.Details["Mode"] = "server"
		} else {
			info.Details["Mode"] = "client"
		}
	}

	// Validate config
	cmd := exec.Command("consul", "validate", "/etc/consul.d/")
	if err := cmd.Run(); err != nil {
		info.Valid = false
		info.Errors = append(info.Errors, "Configuration validation failed")
	}

	return info
}

func (p *ConsulStatusProvider) getHealthInfo(rc *eos_io.RuntimeContext) HealthInfo {
	logger := otelzap.Ctx(rc.Ctx)
	info := HealthInfo{
		Status: HealthStatusUnknown,
		Checks: []HealthCheck{},
	}

	startTime := time.Now()

	// Try to query Consul members to verify it's responding
	cmd := exec.Command("consul", "members", "-detailed")
	output, err := cmd.Output()
	responseTime := time.Since(startTime)
	info.ResponseTime = responseTime

	if err != nil {
		logger.Warn("Consul members command failed", zap.Error(err))
		info.Status = HealthStatusUnhealthy
		info.Message = "Unable to query Consul API"
		return info
	}

	// Check if we got valid output
	if len(output) == 0 {
		info.Status = HealthStatusDegraded
		info.Message = "Consul API returned empty response"
		return info
	}

	// API is responding
	info.Checks = append(info.Checks, HealthCheck{
		Name:    "API Responsive",
		Status:  HealthStatusHealthy,
		Message: fmt.Sprintf("Responded in %v", responseTime),
	})

	// Check leader status
	cmd = exec.Command("consul", "operator", "raft", "list-peers")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "leader") {
			isLeader := false
			info.IsLeader = &isLeader
			info.Checks = append(info.Checks, HealthCheck{
				Name:    "Leader Election",
				Status:  HealthStatusHealthy,
				Message: "Cluster has a leader",
			})
		}
	}

	info.Status = HealthStatusHealthy
	info.Message = "All health checks passed"
	info.LastHealthy = time.Now()

	return info
}

func (p *ConsulStatusProvider) getNetworkInfo(rc *eos_io.RuntimeContext) NetworkInfo {
	// Use internal hostname for network endpoints (same as Vault)
	hostname := shared.GetInternalHostname()

	info := NetworkInfo{
		Endpoints: []Endpoint{
			{
				Name:     "HTTP API",
				Protocol: "http",
				Address:  hostname, // Use internal hostname (e.g., vhost11)
				Port:     shared.PortConsul, // 8161
				Healthy:  true,
			},
			{
				Name:     "DNS",
				Protocol: "udp",
				Address:  hostname, // Use internal hostname for consistency
				Port:     8600,
				Healthy:  true,
			},
			{
				Name:     "Serf LAN",
				Protocol: "tcp",
				Address:  "0.0.0.0", // Keep as 0.0.0.0 (listens on all interfaces)
				Port:     8301,
				Healthy:  true,
			},
		},
		ListenAddr: hostname,
	}

	// Test HTTP API endpoint using internal hostname
	cmd := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
		fmt.Sprintf("http://%s:%d/v1/status/leader", hostname, shared.PortConsul))
	if output, err := cmd.Output(); err != nil || string(output) != "200" {
		info.Endpoints[0].Healthy = false
	}

	return info
}

func (p *ConsulStatusProvider) getIntegrations(rc *eos_io.RuntimeContext) []IntegrationInfo {
	integrations := []IntegrationInfo{}

	// Check if Vault is using Consul as storage backend
	if vaultConfigData, err := os.ReadFile("/etc/vault.d/vault.hcl"); err == nil {
		if strings.Contains(string(vaultConfigData), `storage "consul"`) {
			integrations = append(integrations, IntegrationInfo{
				ServiceName: "Vault",
				Type:        IntegrationTypeStorageBackend,
				Connected:   true,
				Healthy:     true,
				Details:     "Vault uses Consul for storage backend",
				Required:    false,
			})
		}
	}

	return integrations
}

func (p *ConsulStatusProvider) getClusterInfo(rc *eos_io.RuntimeContext) *ClusterInfo {
	logger := otelzap.Ctx(rc.Ctx)

	// Get cluster members
	cmd := exec.Command("consul", "members", "-detailed", "-format", "json")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("Failed to get consul members", zap.Error(err))
		return nil
	}

	var members []map[string]interface{}
	if err := json.Unmarshal(output, &members); err != nil {
		logger.Warn("Failed to parse consul members", zap.Error(err))
		return nil
	}

	if len(members) == 0 {
		return nil
	}

	cluster := &ClusterInfo{
		Members: []ClusterMember{},
	}

	// Get leader
	cmd = exec.Command("consul", "operator", "raft", "list-peers")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "leader") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					cluster.Leader = fields[0]
				}
			}
		}
	}

	// Parse members
	serverCount := 0
	for _, m := range members {
		name, _ := m["Name"].(string)
		addr, _ := m["Addr"].(string)
		status, _ := m["Status"].(string)
		tags, _ := m["Tags"].(map[string]interface{})

		role := "client"
		if tags != nil {
			if roleTag, ok := tags["role"].(string); ok {
				role = roleTag
			}
		}

		if role == "consul" || strings.Contains(fmt.Sprint(tags), "server") {
			role = "server"
			serverCount++
		}

		isLeader := (name == cluster.Leader || addr == cluster.Leader)

		member := ClusterMember{
			Name:    name,
			Address: addr,
			Role:    role,
			Status:  status,
			Leader:  isLeader,
		}

		cluster.Members = append(cluster.Members, member)

		// Set cluster properties from first member
		if cluster.Datacenter == "" {
			if dc, ok := tags["dc"].(string); ok {
				cluster.Datacenter = dc
			}
		}
	}

	// Determine mode from this node
	hostname, _ := os.Hostname()
	for _, member := range cluster.Members {
		if member.Name == hostname {
			cluster.Mode = member.Role
			cluster.NodeName = member.Name
			break
		}
	}

	cluster.Healthy = (cluster.Leader != "" && serverCount > 0)
	cluster.QuorumSize = (serverCount / 2) + 1
	cluster.VotingMembers = serverCount

	return cluster
}

// Helper functions

func (p *ConsulStatusProvider) getServicePID() int {
	cmd := exec.Command("systemctl", "show", "consul", "--property=MainPID")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	parts := strings.Split(string(output), "=")
	if len(parts) != 2 {
		return 0
	}

	pid, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0
	}

	return pid
}

func (p *ConsulStatusProvider) getProcessUptime(pid int) time.Duration {
	// Read /proc/{pid}/stat to get process start time
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}

	// Parse stat file - starttime is the 22nd field
	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return 0
	}

	startTime, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return 0
	}

	// Get system uptime
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}

	uptimeFields := strings.Fields(string(uptimeData))
	if len(uptimeFields) == 0 {
		return 0
	}

	systemUptime, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return 0
	}

	// Calculate process uptime
	// startTime is in clock ticks since boot
	clockTicks := 100.0 // Typical value for USER_HZ
	processStartSecs := float64(startTime) / clockTicks
	processUptime := systemUptime - processStartSecs

	return time.Duration(processUptime * float64(time.Second))
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}
