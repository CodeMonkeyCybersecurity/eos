// pkg/vault/consul_integration_check.go
// Functions to check Vault's Consul storage backend integration

package vault

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulIntegrationStatus represents Vault's integration with Consul
type ConsulIntegrationStatus struct {
	ConsulInstalled       bool
	ConsulRunning         bool
	UsingConsulStorage    bool
	ConsulAddress         string
	ConsulPath            string
	RegisteredInConsul    bool
	HealthChecksEnabled   bool
	ConfigurationPath     string
	IntegrationHealthy    bool
	Issues                []string
}

// CheckConsulIntegration checks if Vault is using Consul as storage backend
func CheckConsulIntegration(ctx context.Context) (*ConsulIntegrationStatus, error) {
	logger := otelzap.Ctx(ctx)
	status := &ConsulIntegrationStatus{
		Issues: make([]string, 0),
	}

	// Check if Consul binary exists
	if _, err := exec.LookPath("consul"); err == nil {
		status.ConsulInstalled = true
		logger.Debug("Consul binary found")
	} else {
		logger.Debug("Consul binary not found")
		status.Issues = append(status.Issues, "Consul is not installed")
	}

	// Check if Consul service is running
	if status.ConsulInstalled {
		if err := exec.Command("systemctl", "is-active", "consul").Run(); err == nil {
			status.ConsulRunning = true
			logger.Debug("Consul service is running")
		} else {
			logger.Debug("Consul service is not running")
			status.Issues = append(status.Issues, "Consul service is not running")
		}
	}

	// Check Vault configuration for Consul storage backend
	configPath := "/etc/vault.d/vault.hcl"
	status.ConfigurationPath = configPath

	if _, err := os.Stat(configPath); err == nil {
		configData, err := os.ReadFile(configPath)
		if err != nil {
			logger.Debug("Failed to read Vault configuration", zap.Error(err))
			status.Issues = append(status.Issues, "Cannot read Vault configuration file")
		} else {
			// Parse configuration for Consul storage
			consulStorage := parseConsulStorageConfig(string(configData))
			if consulStorage != nil {
				status.UsingConsulStorage = true
				status.ConsulAddress = consulStorage.Address
				status.ConsulPath = consulStorage.Path
				status.HealthChecksEnabled = consulStorage.ServiceRegistration

				logger.Debug("Vault is configured to use Consul storage",
					zap.String("address", status.ConsulAddress),
					zap.String("path", status.ConsulPath))
			} else {
				logger.Debug("Vault is not using Consul storage backend")
			}
		}
	} else {
		logger.Debug("Vault configuration file not found", zap.Error(err))
		status.Issues = append(status.Issues, "Vault configuration file not found")
	}

	// Check if Vault is registered in Consul (if both are running)
	if status.ConsulRunning && status.UsingConsulStorage {
		output, err := exec.Command("consul", "catalog", "services").Output()
		if err == nil {
			services := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, service := range services {
				if strings.TrimSpace(service) == "vault" {
					status.RegisteredInConsul = true
					logger.Debug("Vault is registered in Consul service catalog")
					break
				}
			}

			if !status.RegisteredInConsul {
				status.Issues = append(status.Issues, "Vault is not registered in Consul service catalog")
			}
		}
	}

	// Determine overall integration health
	status.IntegrationHealthy = status.UsingConsulStorage &&
		status.ConsulInstalled &&
		status.ConsulRunning &&
		len(status.Issues) == 0

	return status, nil
}

// ConsulStorageConfig represents parsed Consul storage configuration
type ConsulStorageConfig struct {
	Address             string
	Path                string
	ServiceRegistration bool
}

// parseConsulStorageConfig parses Vault HCL config for Consul storage settings
func parseConsulStorageConfig(configData string) *ConsulStorageConfig {
	// Look for storage "consul" block
	storageRegex := regexp.MustCompile(`storage\s+"consul"\s*{([^}]+)}`)
	matches := storageRegex.FindStringSubmatch(configData)

	if len(matches) < 2 {
		return nil
	}

	storageBlock := matches[1]
	config := &ConsulStorageConfig{
		Path: "vault/", // default
	}

	// Extract address
	addressRegex := regexp.MustCompile(`address\s*=\s*"([^"]+)"`)
	if addrMatch := addressRegex.FindStringSubmatch(storageBlock); len(addrMatch) > 1 {
		config.Address = addrMatch[1]
	}

	// Extract path
	pathRegex := regexp.MustCompile(`path\s*=\s*"([^"]+)"`)
	if pathMatch := pathRegex.FindStringSubmatch(storageBlock); len(pathMatch) > 1 {
		config.Path = pathMatch[1]
	}

	// Check for service_registration
	if strings.Contains(configData, `service_registration "consul"`) {
		config.ServiceRegistration = true
	}

	return config
}
