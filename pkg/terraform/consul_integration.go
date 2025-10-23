// pkg/terraform/consul_integration.go

package terraform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulIntegration holds configuration for Consul-Terraform integration
type ConsulIntegration struct {
	ConsulAddr      string
	ConsulToken     string
	Datacenter      string
	EnableDiscovery bool
	EnableKV        bool
	EnableConnect   bool
	ServicePrefix   string
	KVPrefix        string
}

// ConsulService represents a service to register in Consul
type ConsulService struct {
	ID      string
	Name    string
	Tags    []string
	Port    int
	Address string
	Meta    map[string]string
	Check   *ConsulHealthCheck
	Connect *ConsulConnect
}

// ConsulHealthCheck represents a Consul health check
type ConsulHealthCheck struct {
	HTTP                           string
	TCP                            string
	Script                         string
	Interval                       string
	Timeout                        string
	DeregisterCriticalServiceAfter string
}

// ConsulConnect represents Consul Connect configuration
type ConsulConnect struct {
	SidecarService *ConsulSidecarService
	Native         bool
}

// ConsulSidecarService represents a Consul Connect sidecar
type ConsulSidecarService struct {
	Port  int
	Proxy *ConsulProxy
}

// ConsulProxy represents Consul Connect proxy configuration
type ConsulProxy struct {
	Upstreams []ConsulUpstream
	Config    map[string]any
}

// ConsulUpstream represents an upstream service for Consul Connect
type ConsulUpstream struct {
	DestinationName string
	LocalBindPort   int
	Datacenter      string
}

// ConsulKVPair represents a key-value pair for Consul KV store
type ConsulKVPair struct {
	Key   string
	Value string
	Flags uint64
}

// ConfigureConsulIntegration sets up Consul integration for the Terraform manager
func (m *Manager) ConfigureConsulIntegration(rc *eos_io.RuntimeContext, config ConsulIntegration) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Consul integration for Terraform",
		zap.String("consul_addr", config.ConsulAddr),
		zap.Bool("enable_discovery", config.EnableDiscovery),
		zap.Bool("enable_kv", config.EnableKV),
		zap.Bool("enable_connect", config.EnableConnect))

	// Validate Consul connectivity
	if err := m.validateConsulConnection(rc, config); err != nil {
		return fmt.Errorf("consul connection validation failed: %w", err)
	}

	// Generate Consul provider configuration
	if err := m.generateConsulProvider(rc, config); err != nil {
		return fmt.Errorf("consul provider generation failed: %w", err)
	}

	// Set up KV store if enabled
	if config.EnableKV {
		if err := m.setupConsulKV(rc, config); err != nil {
			return fmt.Errorf("consul KV setup failed: %w", err)
		}
	}

	logger.Info("Consul integration configured successfully")
	return nil
}

// RegisterServicesInConsul registers Terraform-deployed services in Consul
func (m *Manager) RegisterServicesInConsul(rc *eos_io.RuntimeContext, services []ConsulService) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Registering services in Consul", zap.Int("service_count", len(services)))

	client, err := m.getConsulClient(rc)
	if err != nil {
		return fmt.Errorf("failed to create consul client: %w", err)
	}

	for _, service := range services {
		if err := m.registerSingleService(rc, client, service); err != nil {
			logger.Error("Failed to register service",
				zap.String("service_name", service.Name),
				zap.String("service_id", service.ID),
				zap.Error(err))
			return fmt.Errorf("failed to register service %s: %w", service.Name, err)
		}

		logger.Info("Service registered successfully",
			zap.String("service_name", service.Name),
			zap.String("service_id", service.ID))
	}

	return nil
}

// StoreConfigInConsulKV stores configuration in Consul KV store
func (m *Manager) StoreConfigInConsulKV(rc *eos_io.RuntimeContext, kvPairs []ConsulKVPair) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Storing configuration in Consul KV", zap.Int("kv_count", len(kvPairs)))

	client, err := m.getConsulClient(rc)
	if err != nil {
		return fmt.Errorf("failed to create consul client: %w", err)
	}

	for _, kv := range kvPairs {
		pair := &api.KVPair{
			Key:   kv.Key,
			Value: []byte(kv.Value),
			Flags: kv.Flags,
		}

		_, err := client.KV().Put(pair, nil)
		if err != nil {
			logger.Error("Failed to store KV pair",
				zap.String("key", kv.Key),
				zap.Error(err))
			return fmt.Errorf("failed to store key %s: %w", kv.Key, err)
		}

		logger.Debug("KV pair stored", zap.String("key", kv.Key))
	}

	logger.Info("All configuration stored in Consul KV successfully")
	return nil
}

// RetrieveConfigFromConsulKV retrieves configuration from Consul KV store
func (m *Manager) RetrieveConfigFromConsulKV(rc *eos_io.RuntimeContext, keys []string) (map[string]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Retrieving configuration from Consul KV", zap.Strings("keys", keys))

	client, err := m.getConsulClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	result := make(map[string]string)

	for _, key := range keys {
		pair, _, err := client.KV().Get(key, nil)
		if err != nil {
			logger.Error("Failed to retrieve KV pair",
				zap.String("key", key),
				zap.Error(err))
			return nil, fmt.Errorf("failed to retrieve key %s: %w", key, err)
		}

		if pair != nil {
			result[key] = string(pair.Value)
			logger.Debug("KV pair retrieved", zap.String("key", key))
		} else {
			logger.Warn("Key not found in Consul KV", zap.String("key", key))
		}
	}

	return result, nil
}

// GenerateConsulServiceDiscovery creates Terraform data sources for Consul services
func (m *Manager) GenerateConsulServiceDiscovery(rc *eos_io.RuntimeContext, services []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Consul service discovery", zap.Strings("services", services))

	var dataSourcesHCL strings.Builder

	for _, service := range services {
		dataSourcesHCL.WriteString(fmt.Sprintf(`
data "consul_service" "%s" {
  name = "%s"
}

locals {
  %s_endpoints = [
    for service in data.consul_service.%s.service :
    "${service.address}:${service.port}"
  ]
}
`, service, service, service, service))
	}

	dataSourcesFile := filepath.Join(m.Config.WorkingDir, "consul_discovery.tf")
	if err := os.WriteFile(dataSourcesFile, []byte(dataSourcesHCL.String()), 0644); err != nil {
		return fmt.Errorf("failed to write consul service discovery: %w", err)
	}

	logger.Info("Consul service discovery generated", zap.String("file", dataSourcesFile))
	return nil
}

// SyncTerraformOutputsToConsulKV stores Terraform outputs in Consul KV
func (m *Manager) SyncTerraformOutputsToConsulKV(rc *eos_io.RuntimeContext, prefix string, outputNames []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Syncing Terraform outputs to Consul KV",
		zap.String("prefix", prefix),
		zap.Strings("outputs", outputNames))

	client, err := m.getConsulClient(rc)
	if err != nil {
		return fmt.Errorf("failed to create consul client: %w", err)
	}

	for _, outputName := range outputNames {
		output, err := m.Output(rc, outputName)
		if err != nil {
			logger.Warn("Failed to retrieve output",
				zap.String("output", outputName),
				zap.Error(err))
			continue
		}

		key := fmt.Sprintf("%s/%s", prefix, outputName)
		pair := &api.KVPair{
			Key:   key,
			Value: []byte(output),
		}

		_, err = client.KV().Put(pair, nil)
		if err != nil {
			logger.Error("Failed to store output in Consul KV",
				zap.String("key", key),
				zap.Error(err))
			return fmt.Errorf("failed to store output %s: %w", outputName, err)
		}

		logger.Debug("Output stored in Consul KV", zap.String("key", key))
	}

	logger.Info("Terraform outputs synced to Consul KV successfully")
	return nil
}

// validateConsulConnection checks if Consul is accessible
func (m *Manager) validateConsulConnection(rc *eos_io.RuntimeContext, config ConsulIntegration) error {
	client, err := m.createConsulClient(config)
	if err != nil {
		return fmt.Errorf("failed to create consul client: %w", err)
	}

	// Test connection with leader check
	leader, err := client.Status().Leader()
	if err != nil {
		return fmt.Errorf("consul leader check failed: %w", err)
	}

	if leader == "" {
		return fmt.Errorf("consul cluster has no leader")
	}

	return nil
}

// generateConsulProvider creates Consul provider configuration
func (m *Manager) generateConsulProvider(rc *eos_io.RuntimeContext, config ConsulIntegration) error {
	logger := otelzap.Ctx(rc.Ctx)

	providerHCL := fmt.Sprintf(`
provider "consul" {
  address    = "%s"
  datacenter = "%s"
  token      = var.consul_token
}

variable "consul_token" {
  description = "Consul ACL token"
  type        = string
  sensitive   = true
  default     = ""
}
`, config.ConsulAddr, config.Datacenter)

	providerFile := filepath.Join(m.Config.WorkingDir, "consul_provider.tf")
	if err := os.WriteFile(providerFile, []byte(providerHCL), 0644); err != nil {
		return fmt.Errorf("failed to write consul provider configuration: %w", err)
	}

	logger.Info("Consul provider configuration generated", zap.String("file", providerFile))
	return nil
}

// setupConsulKV initializes Consul KV structure for Terraform
func (m *Manager) setupConsulKV(rc *eos_io.RuntimeContext, config ConsulIntegration) error {
	logger := otelzap.Ctx(rc.Ctx)

	client, err := m.createConsulClient(config)
	if err != nil {
		return fmt.Errorf("failed to create consul client: %w", err)
	}

	// Create base KV structure
	baseKeys := []string{
		fmt.Sprintf("%s/terraform/", config.KVPrefix),
		fmt.Sprintf("%s/services/", config.KVPrefix),
		fmt.Sprintf("%s/config/", config.KVPrefix),
	}

	for _, key := range baseKeys {
		pair := &api.KVPair{
			Key:   key,
			Value: []byte("{}"),
		}

		_, err := client.KV().Put(pair, nil)
		if err != nil {
			logger.Warn("Failed to create base KV structure",
				zap.String("key", key),
				zap.Error(err))
			// Continue with other keys even if one fails
		}
	}

	logger.Info("Consul KV structure initialized")
	return nil
}

// getConsulClient returns a configured Consul client
func (m *Manager) getConsulClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	config := api.DefaultConfig()

	// Use unified address resolution (env var → hostname fallback)
	config.Address = shared.GetConsulAddrWithEnv()

	if token := os.Getenv("CONSUL_HTTP_TOKEN"); token != "" {
		config.Token = token
	}

	return api.NewClient(config)
}

// createConsulClient creates a Consul client with specific configuration
func (m *Manager) createConsulClient(config ConsulIntegration) (*api.Client, error) {
	clientConfig := api.DefaultConfig()
	clientConfig.Address = config.ConsulAddr
	clientConfig.Token = config.ConsulToken
	clientConfig.Datacenter = config.Datacenter

	return api.NewClient(clientConfig)
}

// registerSingleService registers a single service in Consul
func (m *Manager) registerSingleService(rc *eos_io.RuntimeContext, client *api.Client, service ConsulService) error {
	registration := &api.AgentServiceRegistration{
		ID:      service.ID,
		Name:    service.Name,
		Tags:    service.Tags,
		Port:    service.Port,
		Address: service.Address,
		Meta:    service.Meta,
	}

	// Add health check if specified
	if service.Check != nil {
		check := &api.AgentServiceCheck{
			Interval:                       service.Check.Interval,
			Timeout:                        service.Check.Timeout,
			DeregisterCriticalServiceAfter: service.Check.DeregisterCriticalServiceAfter,
		}

		if service.Check.HTTP != "" {
			check.HTTP = service.Check.HTTP
		} else if service.Check.TCP != "" {
			check.TCP = service.Check.TCP
		} else if service.Check.Script != "" {
			// Note: Script checks are deprecated in newer Consul versions
			// Consider using HTTP or TCP checks instead
			check.Args = []string{"/bin/sh", "-c", service.Check.Script}
		}

		registration.Check = check
	}

	// Add Consul Connect if enabled
	if service.Connect != nil {
		connect := &api.AgentServiceConnect{
			Native: service.Connect.Native,
		}

		if service.Connect.SidecarService != nil {
			sidecar := &api.AgentServiceRegistration{
				Port: service.Connect.SidecarService.Port,
			}

			if service.Connect.SidecarService.Proxy != nil {
				proxy := &api.AgentServiceConnectProxyConfig{
					Config: service.Connect.SidecarService.Proxy.Config,
				}

				for _, upstream := range service.Connect.SidecarService.Proxy.Upstreams {
					proxy.Upstreams = append(proxy.Upstreams, api.Upstream{
						DestinationName: upstream.DestinationName,
						LocalBindPort:   upstream.LocalBindPort,
						Datacenter:      upstream.Datacenter,
					})
				}

				sidecar.Proxy = proxy
			}

			connect.SidecarService = sidecar
		}

		registration.Connect = connect
	}

	return client.Agent().ServiceRegister(registration)
}
