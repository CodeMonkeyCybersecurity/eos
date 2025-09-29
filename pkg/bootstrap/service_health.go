// pkg/bootstrap/service_health.go
//
// Comprehensive service health checking for HashiCorp stack components
// with proper port validation and initialization status checks.
//
package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceHealth represents the health status of a service
type ServiceHealth struct {
	Name           string
	Healthy        bool
	Enabled        bool
	Running        bool
	PortsListening map[int]bool
	Version        string
	Status         string
	Details        map[string]interface{}
	Errors         []string
}

// VaultStatus represents Vault health response
type VaultStatus struct {
	Initialized          bool   `json:"initialized"`
	Sealed               bool   `json:"sealed"`
	Standby              bool   `json:"standby"`
	Version              string `json:"version"`
	ClusterName          string `json:"cluster_name"`
	ClusterID            string `json:"cluster_id"`
	PerformanceStandby   bool   `json:"performance_standby"`
	ReplicationPerformance int  `json:"replication_perf_mode"`
	ReplicationDR        int    `json:"replication_dr_mode"`
}

// ConsulStatus represents Consul health response
type ConsulStatus struct {
	Config struct {
		Datacenter string `json:"Datacenter"`
		NodeName   string `json:"NodeName"`
		Server     bool   `json:"Server"`
		Version    string `json:"Version"`
	} `json:"Config"`
	Stats struct {
		Consul struct {
			Leader string `json:"leader"`
		} `json:"consul"`
	} `json:"Stats"`
}

// CheckServiceHealth performs comprehensive health check for a service
func CheckServiceHealth(rc *eos_io.RuntimeContext, serviceName string) (*ServiceHealth, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking service health", zap.String("service", serviceName))

	health := &ServiceHealth{
		Name:           serviceName,
		PortsListening: make(map[int]bool),
		Details:        make(map[string]interface{}),
		Errors:         []string{},
	}

	// Check if service is enabled in systemd
	health.Enabled = checkSystemdEnabled(rc, serviceName)

	// Check if service is running
	health.Running = checkSystemdRunning(rc, serviceName)

	// Get service-specific ports from shared package
	ports := getServicePorts(serviceName)

	// Check each port
	for _, port := range ports {
		health.PortsListening[port] = checkPortListening(rc, port)
	}

	// Service-specific health checks
	switch serviceName {
	case "vault":
		checkVaultHealth(rc, health)
	case "consul":
		checkConsulHealth(rc, health)
	case "nomad":
		checkNomadHealth(rc, health)
	}

	// Determine overall health
	health.Healthy = determineOverallHealth(health)

	return health, nil
}

// checkSystemdEnabled checks if service is enabled in systemd
func checkSystemdEnabled(rc *eos_io.RuntimeContext, serviceName string) bool {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-enabled", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	return err == nil && strings.TrimSpace(output) == "enabled"
}

// checkSystemdRunning checks if service is running in systemd
func checkSystemdRunning(rc *eos_io.RuntimeContext, serviceName string) bool {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	return err == nil && strings.TrimSpace(output) == "active"
}

// checkPortListening checks if a port is listening
func checkPortListening(rc *eos_io.RuntimeContext, port int) bool {
	logger := otelzap.Ctx(rc.Ctx)

	// Try to connect to the port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 2*time.Second)
	if err != nil {
		logger.Debug("Port not listening",
			zap.Int("port", port),
			zap.Error(err))
		return false
	}
	conn.Close()

	logger.Debug("Port is listening", zap.Int("port", port))
	return true
}

// getServicePorts returns the ports for a service using the shared ports package
func getServicePorts(serviceName string) []int {
	switch serviceName {
	case "vault":
		// Vault uses custom port 8179 and original 8200
		return []int{shared.PortVault, shared.PortVaultOriginal}
	case "consul":
		// Consul uses custom and original ports
		return []int{
			shared.PortConsul,         // 8161
			shared.PortConsulOriginal, // 8500
			shared.PortConsulRPC,      // 8431
			shared.PortConsulSerfLAN,  // 8443
			shared.PortConsulSerfWAN,  // 8447
			shared.PortConsulDNS,      // 8389
		}
	case "nomad":
		// Nomad uses custom and original ports
		return []int{
			shared.PortNomad,            // 8243
			shared.PortNomadOriginal,    // 4646
			shared.PortNomadRPCOriginal, // 4647
			shared.PortNomadSerf,        // 8377
		}
	default:
		return []int{}
	}
}

// checkVaultHealth performs Vault-specific health checks
func checkVaultHealth(rc *eos_io.RuntimeContext, health *ServiceHealth) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check Vault API health endpoint
	client := &http.Client{Timeout: 5 * time.Second}

	// Try HTTPS first (port 8179)
	url := fmt.Sprintf("https://localhost:%d/v1/sys/health", shared.PortVault)
	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Failed to create request: %v", err))
		return
	}

	// Allow self-signed certs for now
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client.Transport = transport

	resp, err := client.Do(req)
	if err != nil {
		// Try HTTP fallback (port 8200)
		url = fmt.Sprintf("http://localhost:%d/v1/sys/health", shared.PortVaultOriginal)
		req, _ = http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
		resp, err = client.Do(req)
		if err != nil {
			health.Errors = append(health.Errors, fmt.Sprintf("Vault API unreachable: %v", err))
			return
		}
	}
	defer resp.Body.Close()

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Failed to read Vault response: %v", err))
		return
	}

	var vaultStatus VaultStatus
	if err := json.Unmarshal(body, &vaultStatus); err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Failed to parse Vault response: %v", err))
		return
	}

	// Set health details
	health.Version = vaultStatus.Version
	health.Details["initialized"] = vaultStatus.Initialized
	health.Details["sealed"] = vaultStatus.Sealed
	health.Details["standby"] = vaultStatus.Standby
	health.Details["cluster_id"] = vaultStatus.ClusterID

	// Determine status
	if !vaultStatus.Initialized {
		health.Status = "uninitialized"
		health.Errors = append(health.Errors, "Vault is not initialized - run: eos create vault-init")
	} else if vaultStatus.Sealed {
		health.Status = "sealed"
		health.Errors = append(health.Errors, "Vault is sealed - run: eos create vault-unseal")
	} else {
		health.Status = "healthy"
	}

	logger.Info("Vault health check completed",
		zap.String("status", health.Status),
		zap.Bool("initialized", vaultStatus.Initialized),
		zap.Bool("sealed", vaultStatus.Sealed))
}

// checkConsulHealth performs Consul-specific health checks
func checkConsulHealth(rc *eos_io.RuntimeContext, health *ServiceHealth) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check Consul API health endpoint
	client := &http.Client{Timeout: 5 * time.Second}

	// Check leader endpoint - try both ports
	url := fmt.Sprintf("http://localhost:%d/v1/status/leader", shared.PortConsulOriginal)
	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Failed to create request: %v", err))
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Consul API unreachable: %v", err))
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Failed to read Consul response: %v", err))
		return
	}

	leader := strings.Trim(string(body), "\"\\n")
	if leader == "" {
		health.Status = "no-leader"
		health.Errors = append(health.Errors, "Consul cluster has no leader")
	} else {
		health.Status = "healthy"
		health.Details["leader"] = leader
	}

	// Get agent info
	url = fmt.Sprintf("http://localhost:%d/v1/agent/self", shared.PortConsulOriginal)
	req, _ = http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	resp, err = client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		var agentInfo ConsulStatus
		if json.NewDecoder(resp.Body).Decode(&agentInfo) == nil {
			health.Version = agentInfo.Config.Version
			health.Details["datacenter"] = agentInfo.Config.Datacenter
			health.Details["node_name"] = agentInfo.Config.NodeName
			health.Details["server"] = agentInfo.Config.Server
		}
	}

	logger.Info("Consul health check completed",
		zap.String("status", health.Status),
		zap.String("leader", leader))
}

// checkNomadHealth performs Nomad-specific health checks
func checkNomadHealth(rc *eos_io.RuntimeContext, health *ServiceHealth) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check Nomad API health endpoint
	client := &http.Client{Timeout: 5 * time.Second}

	// Check leader endpoint - try original port
	url := fmt.Sprintf("http://localhost:%d/v1/status/leader", shared.PortNomadOriginal)
	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Failed to create request: %v", err))
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Nomad API unreachable: %v", err))
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		health.Errors = append(health.Errors, fmt.Sprintf("Failed to read Nomad response: %v", err))
		return
	}

	leader := strings.Trim(string(body), "\"\\n")
	if leader == "" {
		health.Status = "no-leader"
		health.Errors = append(health.Errors, "Nomad cluster has no leader")
	} else {
		health.Status = "healthy"
		health.Details["leader"] = leader
	}

	logger.Info("Nomad health check completed",
		zap.String("status", health.Status),
		zap.String("leader", leader))
}

// determineOverallHealth determines if service is overall healthy
func determineOverallHealth(health *ServiceHealth) bool {
	// Service must be enabled and running
	if !health.Enabled || !health.Running {
		return false
	}

	// At least one port must be listening
	hasListeningPort := false
	for _, listening := range health.PortsListening {
		if listening {
			hasListeningPort = true
			break
		}
	}

	if !hasListeningPort {
		return false
	}

	// No critical errors
	if len(health.Errors) > 0 {
		return false
	}

	// Status should be healthy
	return health.Status == "healthy" || health.Status == ""
}

// ValidateRequiredServices validates that required services are healthy
func ValidateRequiredServices(rc *eos_io.RuntimeContext, requiredServices []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating required services", zap.Strings("services", requiredServices))

	failedServices := []string{}
	serviceErrors := map[string][]string{}

	for _, serviceName := range requiredServices {
		health, err := CheckServiceHealth(rc, serviceName)
		if err != nil {
			failedServices = append(failedServices, serviceName)
			serviceErrors[serviceName] = []string{err.Error()}
			continue
		}

		if !health.Healthy {
			failedServices = append(failedServices, serviceName)
			serviceErrors[serviceName] = health.Errors

			// Log detailed status
			logger.Error("Service validation failed",
				zap.String("service", serviceName),
				zap.Bool("enabled", health.Enabled),
				zap.Bool("running", health.Running),
				zap.String("status", health.Status),
				zap.Any("ports", health.PortsListening),
				zap.Strings("errors", health.Errors))
		} else {
			logger.Info("Service validation passed",
				zap.String("service", serviceName),
				zap.String("version", health.Version),
				zap.String("status", health.Status))
		}
	}

	if len(failedServices) > 0 {
		// Build detailed error message
		var errorDetails []string
		for service, errors := range serviceErrors {
			errorDetails = append(errorDetails,
				fmt.Sprintf("%s: %s", service, strings.Join(errors, "; ")))
		}

		return fmt.Errorf("required services not healthy: %s\nDetails:\n%s",
			strings.Join(failedServices, ", "),
			strings.Join(errorDetails, "\n"))
	}

	return nil
}

// EnableAndStartService enables and starts a systemd service
func EnableAndStartService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Enabling and starting service", zap.String("service", serviceName))

	// Enable the service
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", serviceName},
		Capture: false,
		Timeout: 10 * time.Second,
	}); err != nil {
		return fmt.Errorf("failed to enable %s: %w", serviceName, err)
	}

	// Start the service
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", serviceName},
		Capture: false,
		Timeout: 30 * time.Second,
	}); err != nil {
		return fmt.Errorf("failed to start %s: %w", serviceName, err)
	}

	// Wait for service to be ready
	return WaitForServiceReady(rc, serviceName, 60*time.Second)
}

// WaitForServiceReady waits for a service to become ready
func WaitForServiceReady(rc *eos_io.RuntimeContext, serviceName string, timeout time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Waiting for service to be ready",
		zap.String("service", serviceName),
		zap.Duration("timeout", timeout))

	ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s to be ready", serviceName)
		case <-ticker.C:
			health, err := CheckServiceHealth(rc, serviceName)
			if err == nil && health.Healthy {
				logger.Info("Service is ready", zap.String("service", serviceName))
				return nil
			}

			if health != nil && len(health.Errors) > 0 {
				logger.Debug("Service not ready yet",
					zap.String("service", serviceName),
					zap.Strings("errors", health.Errors))
			}
		}
	}
}