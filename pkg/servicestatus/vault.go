// pkg/servicestatus/vault.go
package servicestatus

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultStatusProvider implements StatusProvider for Vault
type VaultStatusProvider struct{}

// NewVaultStatusProvider creates a new Vault status provider
func NewVaultStatusProvider() *VaultStatusProvider {
	return &VaultStatusProvider{}
}

// ServiceName returns "Vault"
func (p *VaultStatusProvider) ServiceName() string {
	return "Vault"
}

// GetStatus retrieves comprehensive Vault status
func (p *VaultStatusProvider) GetStatus(rc *eos_io.RuntimeContext) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Gathering Vault status")

	status := &ServiceStatus{
		Name:      "Vault",
		CheckedAt: time.Now(),
		CheckedBy: getHostname(),
	}

	// Installation info
	status.Installation = p.getInstallationInfo()

	// Get version
	if cmd := exec.Command("vault", "version"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimPrefix(strings.TrimSpace(lines[0]), "Vault ")
				status.Installation.Version = status.Version
			}
		}
	}

	// Service info
	status.Service = p.getServiceInfo(rc)

	// Configuration info
	status.Configuration = p.getConfigurationInfo(rc)

	// Health info
	status.Health = p.getHealthInfo(rc)

	// Network info
	status.Network = p.getNetworkInfo()

	// Integrations
	status.Integrations = p.getIntegrations()

	// Cluster info (if applicable)
	status.Cluster = p.getClusterInfo(rc)

	return status, nil
}

// QuickCheck performs a fast health check
func (p *VaultStatusProvider) QuickCheck(rc *eos_io.RuntimeContext) (HealthStatus, error) {
	// Quick systemctl check
	cmd := exec.Command("systemctl", "is-active", "vault")
	output, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(output)) != "active" {
		return HealthStatusUnhealthy, nil
	}

	// Quick health check
	healthy, err := vault.CheckVaultHealth(rc)
	if err != nil || !healthy {
		return HealthStatusDegraded, nil
	}

	return HealthStatusHealthy, nil
}

func (p *VaultStatusProvider) getInstallationInfo() InstallationInfo {
	info := InstallationInfo{
		ConfigDir: "/etc/vault.d",
		DataDir:   "/opt/vault",
	}

	if binaryPath, err := exec.LookPath("vault"); err == nil {
		info.Installed = true
		info.BinaryPath = binaryPath
	}

	return info
}

func (p *VaultStatusProvider) getServiceInfo(rc *eos_io.RuntimeContext) ServiceInfo {
	info := ServiceInfo{}

	// Check service status
	cmd := exec.Command("systemctl", "is-active", "vault")
	if output, err := cmd.Output(); err == nil {
		status := strings.TrimSpace(string(output))
		info.Status = status
		info.Running = (status == "active")
	}

	// Check if enabled
	cmd = exec.Command("systemctl", "is-enabled", "vault")
	if output, err := cmd.Output(); err == nil {
		info.Enabled = strings.TrimSpace(string(output)) == "enabled"
	}

	// Get PID and uptime if running
	if info.Running {
		cmd = exec.Command("systemctl", "show", "vault", "--property=MainPID")
		if output, err := cmd.Output(); err == nil {
			parts := strings.Split(string(output), "=")
			if len(parts) == 2 {
				if pid, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && pid > 0 {
					info.PID = pid
					info.Uptime = p.getProcessUptime(pid)
				}
			}
		}
	}

	// Get restart count
	cmd = exec.Command("systemctl", "show", "vault", "--property=NRestarts")
	if output, err := cmd.Output(); err == nil {
		parts := strings.Split(string(output), "=")
		if len(parts) == 2 {
			if count, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
				info.RestartCount = count
			}
		}
	}

	// Check for failure
	cmd = exec.Command("systemctl", "is-failed", "vault")
	if err := cmd.Run(); err == nil {
		info.FailureReason = "Service in failed state - check journalctl -xeu vault"
	}

	return info
}

func (p *VaultStatusProvider) getConfigurationInfo(rc *eos_io.RuntimeContext) ConfigurationInfo {
	logger := otelzap.Ctx(rc.Ctx)
	info := ConfigurationInfo{
		ConfigPath: shared.VaultConfigPath,
		Details:    make(map[string]string),
	}

	// Validate config using existing vault package
	result, err := vault.ValidateConfigWithFallback(rc, shared.VaultConfigPath)
	if err != nil {
		logger.Warn("Config validation failed", zap.Error(err))
		info.Valid = false
		info.Errors = append(info.Errors, err.Error())
	} else {
		info.Valid = result.Valid
		info.Errors = result.Errors
		info.Warnings = result.Warnings
	}

	// Extract config details
	if configData, err := os.ReadFile(shared.VaultConfigPath); err == nil {
		configStr := string(configData)

		// Extract storage backend
		if strings.Contains(configStr, `storage "consul"`) {
			info.Details["Storage Backend"] = "Consul"
		} else if strings.Contains(configStr, `storage "raft"`) {
			info.Details["Storage Backend"] = "Raft"
		} else if strings.Contains(configStr, `storage "file"`) {
			info.Details["Storage Backend"] = "File"
		}

		// Check for TLS
		if strings.Contains(configStr, "tls_cert_file") {
			info.Details["TLS"] = "Enabled"
		} else if strings.Contains(configStr, "tls_disable = 1") || strings.Contains(configStr, "tls_disable=1") {
			info.Details["TLS"] = "Disabled"
			info.Warnings = append(info.Warnings, "TLS is disabled - not recommended for production")
		}

		// Check for UI
		if strings.Contains(configStr, "ui = true") {
			info.Details["UI"] = "Enabled"
		}

		// Extract API address
		scanner := bufio.NewScanner(bytes.NewReader(configData))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "api_addr") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					addr := strings.Trim(strings.TrimSpace(parts[1]), `"`)
					info.Details["API Address"] = addr
				}
			}
		}
	}

	return info
}

func (p *VaultStatusProvider) getHealthInfo(rc *eos_io.RuntimeContext) HealthInfo {
	logger := otelzap.Ctx(rc.Ctx)
	info := HealthInfo{
		Status: HealthStatusUnknown,
		Checks: []HealthCheck{},
	}

	startTime := time.Now()

	// Check Vault health
	healthy, err := vault.CheckVaultHealth(rc)
	responseTime := time.Since(startTime)
	info.ResponseTime = responseTime

	if err != nil {
		logger.Warn("Vault health check failed", zap.Error(err))
		info.Status = HealthStatusUnhealthy
		info.Message = fmt.Sprintf("Health check failed: %v", err)
		return info
	}

	// API is responding
	info.Checks = append(info.Checks, HealthCheck{
		Name:    "API Responsive",
		Status:  HealthStatusHealthy,
		Message: fmt.Sprintf("Responded in %v", responseTime),
	})

	// Get Vault client
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		logger.Warn("Failed to get Vault client", zap.Error(err))
		info.Status = HealthStatusDegraded
		info.Message = "Unable to connect to Vault API"
		return info
	}

	// Check initialization status
	initialized, err := vault.IsVaultInitialized(rc, client)
	if err != nil {
		logger.Warn("Failed to check Vault initialization", zap.Error(err))
	} else {
		if initialized {
			info.Checks = append(info.Checks, HealthCheck{
				Name:    "Initialized",
				Status:  HealthStatusHealthy,
				Message: "Vault is initialized",
			})
		} else {
			info.Checks = append(info.Checks, HealthCheck{
				Name:    "Initialized",
				Status:  HealthStatusUnhealthy,
				Message: "Vault is not initialized",
			})
			info.Status = HealthStatusUnhealthy
			info.Message = "Vault is not initialized"
			return info
		}
	}

	// Check seal status
	sealed := vault.IsVaultSealed(rc, client)
	isSealed := sealed
	info.IsSealed = &isSealed

	if sealed {
		info.Checks = append(info.Checks, HealthCheck{
			Name:    "Seal Status",
			Status:  HealthStatusUnhealthy,
			Message: "Vault is sealed",
		})
		info.Status = HealthStatusUnhealthy
		info.Message = "Vault is sealed"
		return info
	} else {
		info.Checks = append(info.Checks, HealthCheck{
			Name:    "Seal Status",
			Status:  HealthStatusHealthy,
			Message: "Vault is unsealed",
		})
	}

	// If we got here, Vault is healthy
	if healthy {
		info.Status = HealthStatusHealthy
		info.Message = "All health checks passed"
		info.LastHealthy = time.Now()
	} else {
		info.Status = HealthStatusDegraded
		info.Message = "Health check returned degraded status"
	}

	return info
}

func (p *VaultStatusProvider) getNetworkInfo() NetworkInfo {
	// Use internal hostname for network endpoints (same as Consul)
	hostname := shared.GetInternalHostname()

	info := NetworkInfo{
		Endpoints: []Endpoint{
			{
				Name:     "HTTPS API",
				Protocol: "https",
				Address:  hostname, // Use internal hostname (e.g., vhost11)
				Port:     shared.PortVault, // 8200 (HashiCorp standard)
				Healthy:  true,
			},
		},
		ListenAddr: fmt.Sprintf("0.0.0.0:%d", shared.PortVault),
	}

	// Test HTTPS API endpoint (with skip-verify for self-signed certs)
	// Use hostname for health check to match displayed endpoint
	cmd := exec.Command("curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
		fmt.Sprintf("https://%s:%d/v1/sys/health", hostname, shared.PortVault))
	if output, err := cmd.Output(); err != nil {
		info.Endpoints[0].Healthy = false
	} else {
		// Vault returns various codes for different states, all are valid responses
		code := string(output)
		info.Endpoints[0].Healthy = (code == "200" || code == "429" || code == "472" || code == "473" || code == "501" || code == "503")
	}

	return info
}

func (p *VaultStatusProvider) getIntegrations() []IntegrationInfo {
	integrations := []IntegrationInfo{}

	// Check if using Consul storage
	if configData, err := os.ReadFile(shared.VaultConfigPath); err == nil {
		configStr := string(configData)

		if strings.Contains(configStr, `storage "consul"`) {
			// Extract Consul address
			consulAddr := shared.GetConsulDefaultAddr()
			scanner := bufio.NewScanner(bytes.NewReader(configData))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.Contains(line, "address") && strings.Contains(line, "=") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						consulAddr = strings.Trim(strings.TrimSpace(parts[1]), `"`)
						break
					}
				}
			}

			// Check if Consul is actually reachable
			consulHealthy := false
			cmd := exec.Command("systemctl", "is-active", "consul")
			if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) == "active" {
				consulHealthy = true
			}

			integrations = append(integrations, IntegrationInfo{
				ServiceName: "Consul",
				Type:        IntegrationTypeStorageBackend,
				Connected:   true,
				Healthy:     consulHealthy,
				Details:     fmt.Sprintf("Storage backend at %s", consulAddr),
				Required:    true,
			})
		}

		// Check for service registration
		if strings.Contains(configStr, `service_registration "consul"`) {
			integrations = append(integrations, IntegrationInfo{
				ServiceName: "Consul",
				Type:        IntegrationTypeServiceDiscovery,
				Connected:   true,
				Healthy:     true,
				Details:     "Registered in Consul service catalog",
				Required:    false,
			})
		}
	}

	return integrations
}

func (p *VaultStatusProvider) getClusterInfo(rc *eos_io.RuntimeContext) *ClusterInfo {
	logger := otelzap.Ctx(rc.Ctx)

	// Only applicable for Raft storage
	configData, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		return nil
	}

	if !strings.Contains(string(configData), `storage "raft"`) {
		return nil
	}

	// Get Vault client
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		logger.Warn("Failed to get Vault client for cluster info", zap.Error(err))
		return nil
	}

	// Check if sealed (can't get cluster info if sealed)
	if vault.IsVaultSealed(rc, client) {
		return nil
	}

	cluster := &ClusterInfo{
		Mode: "server", // Raft storage means server mode
	}

	// Try to get hostname as node name
	if hostname, err := os.Hostname(); err == nil {
		cluster.NodeName = hostname
	}

	// TODO: Could enhance this with actual Raft cluster member queries
	// For now, basic info is sufficient

	return cluster
}

func (p *VaultStatusProvider) getProcessUptime(pid int) time.Duration {
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
	clockTicks := 100.0 // Typical value for USER_HZ
	processStartSecs := float64(startTime) / clockTicks
	processUptime := systemUptime - processStartSecs

	return time.Duration(processUptime * float64(time.Second))
}
