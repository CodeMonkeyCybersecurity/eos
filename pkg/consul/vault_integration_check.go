// pkg/consul/vault_integration_check.go
// Functions to check Vault/Consul integration status

package consul

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultIntegrationStatus represents the integration status between Vault and Consul
type VaultIntegrationStatus struct {
	VaultInstalled     bool
	VaultRunning       bool
	VaultRegistered    bool
	VaultHealthy       bool
	VaultServiceID     string
	VaultAddress       string
	HealthChecks       []VaultHealthCheck
	KVStoreUsed        bool
	KVPath             string
	KVKeyCount         int
	StorageBackend     string
	IntegrationHealthy bool
	Issues             []string
}

// VaultHealthCheck represents a single health check for Vault service
type VaultHealthCheck struct {
	CheckID string
	Name    string
	Status  string
	Output  string
}

// CheckVaultIntegration checks if Vault is integrated with Consul
func CheckVaultIntegration(ctx context.Context) (*VaultIntegrationStatus, error) {
	logger := otelzap.Ctx(ctx)
	status := &VaultIntegrationStatus{
		Issues: make([]string, 0),
	}

	// Check if Vault binary exists
	if _, err := exec.LookPath("vault"); err == nil {
		status.VaultInstalled = true
		logger.Debug("Vault binary found")
	} else {
		logger.Debug("Vault binary not found", zap.Error(err))
		return status, nil
	}

	// Check if Vault service is running
	if err := exec.Command("systemctl", "is-active", "vault").Run(); err == nil {
		status.VaultRunning = true
		logger.Debug("Vault service is running")
	} else {
		logger.Debug("Vault service is not running")
		status.Issues = append(status.Issues, "Vault service is not running")
		return status, nil
	}

	// Check if Vault is registered in Consul
	vaultService, err := checkVaultServiceRegistration(ctx)
	if err != nil {
		logger.Debug("Failed to check Vault service registration", zap.Error(err))
	} else if vaultService != nil {
		status.VaultRegistered = true
		status.VaultServiceID = vaultService.ServiceID
		status.VaultAddress = vaultService.Address
		status.HealthChecks = vaultService.HealthChecks

		// Check if all health checks are passing
		status.VaultHealthy = true
		for _, check := range status.HealthChecks {
			if check.Status != "passing" {
				status.VaultHealthy = false
				status.Issues = append(status.Issues, fmt.Sprintf("Health check '%s' is %s", check.Name, check.Status))
			}
		}

		logger.Debug("Vault service registered in Consul",
			zap.String("service_id", status.VaultServiceID),
			zap.Bool("healthy", status.VaultHealthy))
	} else {
		logger.Debug("Vault service not registered in Consul")
		status.Issues = append(status.Issues, "Vault is not registered in Consul service catalog")
	}

	// Check if Vault is using Consul KV store
	kvUsage, err := checkConsulKVUsage(ctx)
	if err != nil {
		logger.Debug("Failed to check Consul KV usage", zap.Error(err))
	} else {
		status.KVStoreUsed = kvUsage.Used
		status.KVPath = kvUsage.Path
		status.KVKeyCount = kvUsage.KeyCount

		if kvUsage.Used {
			logger.Debug("Vault is using Consul KV store",
				zap.String("path", kvUsage.Path),
				zap.Int("key_count", kvUsage.KeyCount))
		}
	}

	// Determine overall integration health
	status.IntegrationHealthy = status.VaultInstalled &&
		status.VaultRunning &&
		status.VaultRegistered &&
		status.VaultHealthy &&
		len(status.Issues) == 0

	return status, nil
}

// VaultServiceInfo represents Vault service registration in Consul
type VaultServiceInfo struct {
	ServiceID    string
	Address      string
	HealthChecks []VaultHealthCheck
}

// checkVaultServiceRegistration checks if Vault is registered as a service in Consul
func checkVaultServiceRegistration(ctx context.Context) (*VaultServiceInfo, error) {
	logger := otelzap.Ctx(ctx)

	// Get catalog services
	output, err := exec.Command("consul", "catalog", "services", "-tags").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get catalog services: %w", err)
	}

	// Check if vault service exists
	services := strings.Split(strings.TrimSpace(string(output)), "\n")
	vaultFound := false
	for _, service := range services {
		if strings.HasPrefix(service, "vault") {
			vaultFound = true
			break
		}
	}

	if !vaultFound {
		return nil, nil
	}

	// Get detailed service information
	output, err = exec.Command("consul", "catalog", "service", "vault", "-detailed").Output()
	if err != nil {
		logger.Debug("Failed to get detailed vault service info", zap.Error(err))
		// Service exists but can't get details
		return &VaultServiceInfo{
			ServiceID: "vault",
		}, nil
	}

	// Parse service details (basic parsing)
	lines := strings.Split(string(output), "\n")
	serviceInfo := &VaultServiceInfo{
		ServiceID:    "vault",
		HealthChecks: make([]VaultHealthCheck, 0),
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Address:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				serviceInfo.Address = strings.TrimSpace(parts[1])
			}
		}
	}

	// Get health checks for vault service
	healthOutput, err := exec.Command("consul", "health", "service", "vault", "-format=json").Output()
	if err == nil {
		var healthData []map[string]interface{}
		if err := json.Unmarshal(healthOutput, &healthData); err == nil && len(healthData) > 0 {
			if checks, ok := healthData[0]["Checks"].([]interface{}); ok {
				for _, checkInterface := range checks {
					if check, ok := checkInterface.(map[string]interface{}); ok {
						healthCheck := VaultHealthCheck{
							CheckID: getString(check, "CheckID"),
							Name:    getString(check, "Name"),
							Status:  getString(check, "Status"),
							Output:  getString(check, "Output"),
						}
						serviceInfo.HealthChecks = append(serviceInfo.HealthChecks, healthCheck)
					}
				}
			}
		}
	}

	return serviceInfo, nil
}

// ConsulKVUsage represents Consul KV store usage by Vault
type ConsulKVUsage struct {
	Used     bool
	Path     string
	KeyCount int
}

// checkConsulKVUsage checks if Vault is using Consul KV store
func checkConsulKVUsage(ctx context.Context) (*ConsulKVUsage, error) {
	logger := otelzap.Ctx(ctx)

	usage := &ConsulKVUsage{
		Path: "vault/",
	}

	// Try to list keys under vault/ prefix
	output, err := exec.Command("consul", "kv", "get", "-keys", "-recurse", "vault/").Output()
	if err != nil {
		// If error, vault/ might not exist
		logger.Debug("No vault/ keys found in Consul KV", zap.Error(err))
		return usage, nil
	}

	// Count keys
	keys := strings.Split(strings.TrimSpace(string(output)), "\n")
	keyCount := 0
	for _, key := range keys {
		if strings.TrimSpace(key) != "" {
			keyCount++
		}
	}

	if keyCount > 0 {
		usage.Used = true
		usage.KeyCount = keyCount
		logger.Debug("Vault is using Consul KV store",
			zap.Int("key_count", keyCount))
	}

	return usage, nil
}

// Helper function to safely get string from map
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}
