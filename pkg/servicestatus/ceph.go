// pkg/servicestatus/ceph.go
package servicestatus

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CephStatusProvider implements StatusProvider for Ceph
type CephStatusProvider struct{}

// NewCephStatusProvider creates a new Ceph status provider
func NewCephStatusProvider() *CephStatusProvider {
	return &CephStatusProvider{}
}

// ServiceName returns "Ceph"
func (p *CephStatusProvider) ServiceName() string {
	return "Ceph"
}

// GetStatus retrieves comprehensive Ceph status
func (p *CephStatusProvider) GetStatus(rc *eos_io.RuntimeContext) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Gathering Ceph status")

	status := &ServiceStatus{
		Name:      "Ceph",
		CheckedAt: time.Now(),
		CheckedBy: getHostname(),
	}

	// Installation info
	status.Installation = p.getInstallationInfo()

	// Get version
	if cmd := exec.Command("ceph", "--version"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			version := strings.TrimSpace(string(output))
			// Extract version number (e.g., "ceph version 17.2.6" -> "17.2.6")
			if parts := strings.Fields(version); len(parts) >= 3 {
				status.Version = parts[2]
				status.Installation.Version = parts[2]
			}
		}
	}

	// Service info (ceph-mon, ceph-mgr, ceph-osd services)
	status.Service = p.getServiceInfo(rc)

	// Configuration info
	status.Configuration = p.getConfigurationInfo()

	// Health info
	status.Health = p.getHealthInfo(rc)

	// Network info
	status.Network = p.getNetworkInfo(rc)

	// Integrations
	status.Integrations = p.getIntegrations()

	// Cluster info
	status.Cluster = p.getClusterInfo(rc)

	return status, nil
}

// QuickCheck performs a fast health check
func (p *CephStatusProvider) QuickCheck(rc *eos_io.RuntimeContext) (HealthStatus, error) {
	// Quick ceph status check
	cmd := exec.Command("ceph", "health")
	output, err := cmd.Output()
	if err != nil {
		return HealthStatusUnhealthy, nil
	}

	healthStr := strings.TrimSpace(string(output))
	switch {
	case strings.Contains(healthStr, "HEALTH_OK"):
		return HealthStatusHealthy, nil
	case strings.Contains(healthStr, "HEALTH_WARN"):
		return HealthStatusDegraded, nil
	default:
		return HealthStatusUnhealthy, nil
	}
}

func (p *CephStatusProvider) getInstallationInfo() InstallationInfo {
	info := InstallationInfo{
		ConfigDir: "/etc/ceph",
		DataDir:   "/var/lib/ceph",
	}

	if binaryPath, err := exec.LookPath("ceph"); err == nil {
		info.Installed = true
		info.BinaryPath = binaryPath
	}

	return info
}

func (p *CephStatusProvider) getServiceInfo(rc *eos_io.RuntimeContext) ServiceInfo {
	logger := otelzap.Ctx(rc.Ctx)
	info := ServiceInfo{}

	// Check for ceph-mon service (most fundamental service)
	cmd := exec.Command("systemctl", "is-active", "ceph-mon.target")
	if output, err := cmd.Output(); err == nil {
		status := strings.TrimSpace(string(output))
		info.Status = status
		info.Running = (status == "active")
	} else {
		// Try checking individual services
		services := []string{"ceph-mon@*", "ceph-mgr@*", "ceph-osd@*"}
		activeCount := 0
		for _, svc := range services {
			cmd := exec.Command("systemctl", "list-units", svc, "--state=active", "--no-legend")
			if output, err := cmd.Output(); err == nil && len(output) > 0 {
				activeCount++
			}
		}
		if activeCount > 0 {
			info.Running = true
			info.Status = fmt.Sprintf("%d services active", activeCount)
		}
	}

	// Get uptime from ceph mon daemon if available
	if info.Running {
		cmd := exec.Command("ceph", "mon", "stat")
		if output, err := cmd.Output(); err == nil {
			logger.Debug("Mon stat output", zap.String("output", string(output)))
		}
	}

	return info
}

func (p *CephStatusProvider) getConfigurationInfo() ConfigurationInfo {
	info := ConfigurationInfo{
		ConfigPath: "/etc/ceph/ceph.conf",
		Details:    make(map[string]string),
	}

	// Check if ceph.conf exists
	cmd := exec.Command("test", "-f", "/etc/ceph/ceph.conf")
	if err := cmd.Run(); err == nil {
		info.Valid = true
	}

	// Get FSID
	cmd = exec.Command("ceph", "fsid")
	if output, err := cmd.Output(); err == nil {
		fsid := strings.TrimSpace(string(output))
		info.Details["FSID"] = fsid
	}

	// Get cluster name
	info.Details["Cluster Name"] = "ceph" // Default

	return info
}

func (p *CephStatusProvider) getHealthInfo(rc *eos_io.RuntimeContext) HealthInfo {
	logger := otelzap.Ctx(rc.Ctx)
	info := HealthInfo{
		Status: HealthStatusUnknown,
		Checks: []HealthCheck{},
	}

	startTime := time.Now()

	// Get cluster health
	cmd := exec.Command("ceph", "health", "detail")
	output, err := cmd.Output()
	responseTime := time.Since(startTime)
	info.ResponseTime = responseTime

	if err != nil {
		logger.Warn("Ceph health check failed", zap.Error(err))
		info.Status = HealthStatusUnhealthy
		info.Message = fmt.Sprintf("Health check failed: %v", err)
		return info
	}

	healthOutput := string(output)
	lines := strings.Split(healthOutput, "\n")

	// Parse health status
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		switch {
		case strings.HasPrefix(firstLine, "HEALTH_OK"):
			info.Status = HealthStatusHealthy
			info.Message = "Cluster is healthy"
			info.LastHealthy = time.Now()
		case strings.HasPrefix(firstLine, "HEALTH_WARN"):
			info.Status = HealthStatusDegraded
			info.Message = "Cluster has warnings"
		case strings.HasPrefix(firstLine, "HEALTH_ERR"):
			info.Status = HealthStatusUnhealthy
			info.Message = "Cluster has errors"
		default:
			info.Status = HealthStatusUnknown
			info.Message = firstLine
		}
	}

	// Parse detailed health checks
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		checkStatus := HealthStatusHealthy
		if strings.Contains(line, "WARN") {
			checkStatus = HealthStatusDegraded
		} else if strings.Contains(line, "ERR") {
			checkStatus = HealthStatusUnhealthy
		}

		info.Checks = append(info.Checks, HealthCheck{
			Name:    "Health Check",
			Status:  checkStatus,
			Message: line,
		})
	}

	// Add API responsive check
	info.Checks = append(info.Checks, HealthCheck{
		Name:    "API Responsive",
		Status:  HealthStatusHealthy,
		Message: fmt.Sprintf("Responded in %v", responseTime),
	})

	return info
}

func (p *CephStatusProvider) getNetworkInfo(rc *eos_io.RuntimeContext) NetworkInfo {
	info := NetworkInfo{
		Endpoints: []Endpoint{},
	}

	// Get MON addresses
	cmd := exec.Command("ceph", "mon", "dump", "-f", "json")
	if output, err := cmd.Output(); err == nil {
		var monDump map[string]interface{}
		if err := json.Unmarshal(output, &monDump); err == nil {
			if mons, ok := monDump["mons"].([]interface{}); ok {
				for _, mon := range mons {
					if monMap, ok := mon.(map[string]interface{}); ok {
						if addr, ok := monMap["addr"].(string); ok {
							// Parse address (format: "192.168.1.10:6789/0")
							parts := strings.Split(addr, ":")
							if len(parts) >= 2 {
								ip := parts[0]
								portStr := strings.Split(parts[1], "/")[0]
								port, _ := strconv.Atoi(portStr)

								name := "Monitor"
								if monName, ok := monMap["name"].(string); ok {
									name = fmt.Sprintf("MON %s", monName)
								}

								info.Endpoints = append(info.Endpoints, Endpoint{
									Name:     name,
									Protocol: "tcp",
									Address:  ip,
									Port:     port,
									Healthy:  true,
								})
							}
						}
					}
				}
			}
		}
	}

	return info
}

func (p *CephStatusProvider) getIntegrations() []IntegrationInfo {
	integrations := []IntegrationInfo{}

	// Check for CephFS
	cmd := exec.Command("ceph", "fs", "ls", "-f", "json")
	if output, err := cmd.Output(); err == nil {
		var fsList []map[string]interface{}
		if err := json.Unmarshal(output, &fsList); err == nil && len(fsList) > 0 {
			integrations = append(integrations, IntegrationInfo{
				ServiceName: "CephFS",
				Type:        "filesystem",
				Connected:   true,
				Healthy:     true,
				Details:     fmt.Sprintf("%d filesystem(s) available", len(fsList)),
				Required:    false,
			})
		}
	}

	// Check for RBD pools
	cmd = exec.Command("ceph", "osd", "pool", "ls")
	if output, err := cmd.Output(); err == nil {
		pools := strings.Split(strings.TrimSpace(string(output)), "\n")
		rbdCount := 0
		for _, pool := range pools {
			if strings.Contains(pool, "rbd") {
				rbdCount++
			}
		}
		if rbdCount > 0 {
			integrations = append(integrations, IntegrationInfo{
				ServiceName: "RBD",
				Type:        "block_storage",
				Connected:   true,
				Healthy:     true,
				Details:     fmt.Sprintf("%d RBD pool(s)", rbdCount),
				Required:    false,
			})
		}
	}

	return integrations
}

func (p *CephStatusProvider) getClusterInfo(rc *eos_io.RuntimeContext) *ClusterInfo {
	logger := otelzap.Ctx(rc.Ctx)

	cluster := &ClusterInfo{
		Mode:    "cluster",
		Members: []ClusterMember{},
	}

	// Get cluster status
	cmd := exec.Command("ceph", "status", "-f", "json")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("Failed to get ceph status", zap.Error(err))
		return nil
	}

	var status map[string]interface{}
	if err := json.Unmarshal(output, &status); err != nil {
		logger.Warn("Failed to parse ceph status", zap.Error(err))
		return nil
	}

	// Get cluster health
	if health, ok := status["health"].(map[string]interface{}); ok {
		if healthStatus, ok := health["status"].(string); ok {
			cluster.Healthy = (healthStatus == "HEALTH_OK")
		}
	}

	// Get MON quorum
	if monmap, ok := status["monmap"].(map[string]interface{}); ok {
		if mons, ok := monmap["mons"].([]interface{}); ok {
			cluster.VotingMembers = len(mons)
			cluster.QuorumSize = (len(mons) / 2) + 1
		}
	}

	// Get MON members
	cmd = exec.Command("ceph", "mon", "dump", "-f", "json")
	if output, err := cmd.Output(); err == nil {
		var monDump map[string]interface{}
		if err := json.Unmarshal(output, &monDump); err == nil {
			if mons, ok := monDump["mons"].([]interface{}); ok {
				for _, mon := range mons {
					if monMap, ok := mon.(map[string]interface{}); ok {
						name, _ := monMap["name"].(string)
						addr, _ := monMap["addr"].(string)

						member := ClusterMember{
							Name:    name,
							Address: addr,
							Role:    "monitor",
							Status:  "alive",
						}

						cluster.Members = append(cluster.Members, member)
					}
				}
			}
		}
	}

	// Get current node name
	cluster.NodeName = getHostname()

	return cluster
}
