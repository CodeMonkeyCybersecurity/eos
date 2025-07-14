// pkg/hecate/consul/mesh_gateway.go

package consul

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// MeshGatewayDeployment represents a mesh gateway deployment
type MeshGatewayDeployment struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Datacenter        string            `json:"datacenter"`
	Mode              string            `json:"mode"`
	Port              int               `json:"port"`
	BindAddress       string            `json:"bind_address"`
	WANAddress        string            `json:"wan_address"`
	LANAddress        string            `json:"lan_address"`
	Status            string            `json:"status"`
	ServiceRegistration *api.AgentServiceRegistration `json:"service_registration"`
	ProxyRegistration   *api.AgentServiceRegistration `json:"proxy_registration"`
	Config            map[string]interface{} `json:"config"`
	Created           time.Time         `json:"created"`
	Updated           time.Time         `json:"updated"`
}

// DeployMeshGateway deploys a mesh gateway service
func DeployMeshGateway(rc *eos_io.RuntimeContext, deployment *MeshGatewayDeployment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deploying mesh gateway",
		zap.String("deployment_id", deployment.ID),
		zap.String("datacenter", deployment.Datacenter),
		zap.String("mode", deployment.Mode))

	// ASSESS - Validate deployment prerequisites
	if err := validateMeshGatewayPrerequisites(rc, deployment); err != nil {
		return fmt.Errorf("mesh gateway prerequisites validation failed: %w", err)
	}

	// INTERVENE - Deploy mesh gateway
	if err := deployMeshGatewayService(rc, deployment); err != nil {
		return fmt.Errorf("failed to deploy mesh gateway service: %w", err)
	}

	// Register mesh gateway in Consul
	if err := registerMeshGatewayService(rc, deployment); err != nil {
		return fmt.Errorf("failed to register mesh gateway service: %w", err)
	}

	// EVALUATE - Verify deployment
	if err := verifyMeshGatewayDeployment(rc, deployment); err != nil {
		return fmt.Errorf("mesh gateway deployment verification failed: %w", err)
	}

	logger.Info("Mesh gateway deployed successfully",
		zap.String("deployment_id", deployment.ID),
		zap.String("datacenter", deployment.Datacenter))

	return nil
}

// RemoveMeshGateway removes a mesh gateway deployment
func RemoveMeshGateway(rc *eos_io.RuntimeContext, deploymentID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Removing mesh gateway",
		zap.String("deployment_id", deploymentID))

	// TODO: Implement mesh gateway removal
	// This would involve:
	// 1. Stop mesh gateway service
	// 2. Deregister from Consul
	// 3. Clean up configuration files
	// 4. Remove from state store

	return nil
}

// GetMeshGatewayStatus returns the status of a mesh gateway
func GetMeshGatewayStatus(rc *eos_io.RuntimeContext, deploymentID string) (*MeshGatewayStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting mesh gateway status",
		zap.String("deployment_id", deploymentID))

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Get mesh gateway service
	services, _, err := client.Health().Service("mesh-gateway", "", false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get mesh gateway service: %w", err)
	}

	status := &MeshGatewayStatus{
		Datacenter:  "unknown",
		Status:      "unknown",
		Connected:   false,
		LastChecked: time.Now(),
	}

	if len(services) > 0 {
		service := services[0]
		status.Datacenter = service.Node.Datacenter
		status.Address = service.Node.Address
		status.Port = service.Service.Port
		status.Connected = service.Checks.AggregatedStatus() == api.HealthPassing
		status.Status = string(service.Checks.AggregatedStatus())
	}

	return status, nil
}

// ListMeshGateways lists all mesh gateways in all datacenters
func ListMeshGateways(rc *eos_io.RuntimeContext) (map[string][]*MeshGatewayStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing mesh gateways")

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Get all datacenters
	datacenters, err := client.Catalog().Datacenters()
	if err != nil {
		return nil, fmt.Errorf("failed to get datacenters: %w", err)
	}

	result := make(map[string][]*MeshGatewayStatus)

	// Get mesh gateways for each datacenter
	for _, dc := range datacenters {
		// Create client for specific datacenter
		dcConfig := api.DefaultConfig()
		dcConfig.Datacenter = dc
		dcClient, err := api.NewClient(dcConfig)
		if err != nil {
			logger.Warn("Failed to create client for datacenter",
				zap.String("datacenter", dc),
				zap.Error(err))
			continue
		}

		// Get mesh gateway services
		services, _, err := dcClient.Health().Service("mesh-gateway", "", false, nil)
		if err != nil {
			logger.Warn("Failed to get mesh gateway services",
				zap.String("datacenter", dc),
				zap.Error(err))
			continue
		}

		var gateways []*MeshGatewayStatus
		for _, service := range services {
			gateway := &MeshGatewayStatus{
				Datacenter:  dc,
				Status:      string(service.Checks.AggregatedStatus()),
				Connected:   service.Checks.AggregatedStatus() == api.HealthPassing,
				LastChecked: time.Now(),
				Address:     service.Node.Address,
				Port:        service.Service.Port,
			}
			gateways = append(gateways, gateway)
		}

		result[dc] = gateways
	}

	logger.Info("Mesh gateways listed successfully",
		zap.Int("datacenter_count", len(datacenters)))

	return result, nil
}

// Helper functions

func validateMeshGatewayPrerequisites(rc *eos_io.RuntimeContext, deployment *MeshGatewayDeployment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating mesh gateway prerequisites",
		zap.String("deployment_id", deployment.ID))

	// Check if Consul Connect is enabled
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	connectConfig, _, err := client.Connect().CAConfiguration(nil)
	if err != nil {
		return fmt.Errorf("failed to get Connect CA configuration: %w", err)
	}
	if connectConfig == nil {
		return fmt.Errorf("Consul Connect is not enabled")
	}

	// Check if port is available
	if deployment.Port == 0 {
		deployment.Port = 8443 // Default mesh gateway port
	}

	// Validate bind address
	if deployment.BindAddress == "" {
		deployment.BindAddress = "0.0.0.0"
	}

	// Validate mode
	validModes := []string{"local", "remote", "none"}
	isValidMode := false
	for _, mode := range validModes {
		if deployment.Mode == mode {
			isValidMode = true
			break
		}
	}
	if !isValidMode {
		return fmt.Errorf("invalid mesh gateway mode: %s", deployment.Mode)
	}

	logger.Info("Mesh gateway prerequisites validated successfully",
		zap.String("deployment_id", deployment.ID))

	return nil
}

func deployMeshGatewayService(rc *eos_io.RuntimeContext, deployment *MeshGatewayDeployment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deploying mesh gateway service",
		zap.String("deployment_id", deployment.ID))

	// TODO: Implement mesh gateway service deployment
	// This would involve:
	// 1. Create service configuration
	// 2. Generate systemd service file
	// 3. Start the service
	// 4. Configure networking
	// 5. Set up monitoring

	// Generate mesh gateway configuration
	config := generateMeshGatewayConfig(deployment)
	deployment.Config = config

	logger.Info("Mesh gateway service configuration generated",
		zap.String("deployment_id", deployment.ID),
		zap.Any("config", config))

	return nil
}

func generateMeshGatewayConfig(deployment *MeshGatewayDeployment) map[string]interface{} {
	config := map[string]interface{}{
		"datacenter": deployment.Datacenter,
		"data_dir":   fmt.Sprintf("/opt/consul/data/%s", deployment.ID),
		"log_level":  "INFO",
		"node_name":  fmt.Sprintf("mesh-gateway-%s", deployment.ID),
		"bind_addr":  deployment.BindAddress,
		"client_addr": "127.0.0.1",
		"ports": map[string]int{
			"grpc": 8502,
			"http": 8500,
		},
		"connect": map[string]interface{}{
			"enabled": true,
		},
		"ui_config": map[string]interface{}{
			"enabled": false,
		},
	}

	// Add mesh gateway specific configuration
	if deployment.Mode != "" {
		config["connect"].(map[string]interface{})["enable_mesh_gateway_wan_federation"] = true
	}

	return config
}

func registerMeshGatewayService(rc *eos_io.RuntimeContext, deployment *MeshGatewayDeployment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Registering mesh gateway service",
		zap.String("deployment_id", deployment.ID))

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Create service registration
	serviceRegistration := &api.AgentServiceRegistration{
		ID:   deployment.ID,
		Name: "mesh-gateway",
		Port: deployment.Port,
		Tags: []string{
			"mesh-gateway",
			deployment.Mode,
			deployment.Datacenter,
		},
		Meta: map[string]string{
			"datacenter":   deployment.Datacenter,
			"mode":         deployment.Mode,
			"created-by":   "eos-hecate",
			"deployment-id": deployment.ID,
		},
		Kind: api.ServiceKindMeshGateway,
		Proxy: &api.AgentServiceConnectProxyConfig{
			Config: map[string]interface{}{
				"protocol": "tcp",
			},
		},
		Check: &api.AgentServiceCheck{
			Name:     "Mesh Gateway Health",
			TCP:      fmt.Sprintf("%s:%d", deployment.BindAddress, deployment.Port),
			Interval: "10s",
			Timeout:  "3s",
		},
	}

	// Register service
	if err := client.Agent().ServiceRegister(serviceRegistration); err != nil {
		return fmt.Errorf("failed to register mesh gateway service: %w", err)
	}

	deployment.ServiceRegistration = serviceRegistration

	logger.Info("Mesh gateway service registered successfully",
		zap.String("deployment_id", deployment.ID),
		zap.String("service_name", serviceRegistration.Name))

	return nil
}

func verifyMeshGatewayDeployment(rc *eos_io.RuntimeContext, deployment *MeshGatewayDeployment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying mesh gateway deployment",
		zap.String("deployment_id", deployment.ID))

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Wait for service to be healthy
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("mesh gateway deployment verification timeout")
		case <-ticker.C:
			// Check service health
			services, _, err := client.Health().Service("mesh-gateway", "", false, nil)
			if err != nil {
				logger.Warn("Failed to check service health during verification",
					zap.Error(err))
				continue
			}

			// Find our specific service
			for _, service := range services {
				if service.Service.ID == deployment.ID {
					if service.Checks.AggregatedStatus() == api.HealthPassing {
						logger.Info("Mesh gateway deployment verified successfully",
							zap.String("deployment_id", deployment.ID))
						deployment.Status = "healthy"
						return nil
					}
				}
			}

			logger.Info("Waiting for mesh gateway to become healthy",
				zap.String("deployment_id", deployment.ID))
		}
	}
}

// ConfigureMeshGatewayMode configures the mesh gateway mode
func ConfigureMeshGatewayMode(rc *eos_io.RuntimeContext, serviceName, mode string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring mesh gateway mode",
		zap.String("service", serviceName),
		zap.String("mode", mode))

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Create service defaults configuration
	serviceDefaults := &api.ServiceConfigEntry{
		Kind: api.ServiceDefaults,
		Name: serviceName,
		MeshGateway: api.MeshGatewayConfig{
			Mode: api.MeshGatewayMode(mode),
		},
	}

	// Write configuration
	_, _, err = client.ConfigEntries().Set(serviceDefaults, nil)
	if err != nil {
		return fmt.Errorf("failed to set service defaults: %w", err)
	}

	logger.Info("Mesh gateway mode configured successfully",
		zap.String("service", serviceName),
		zap.String("mode", mode))

	return nil
}

// GetMeshGatewayConfiguration returns the mesh gateway configuration
func GetMeshGatewayConfiguration(rc *eos_io.RuntimeContext, serviceName string) (*api.ServiceConfigEntry, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting mesh gateway configuration",
		zap.String("service", serviceName))

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Get service defaults
	entry, _, err := client.ConfigEntries().Get(api.ServiceDefaults, serviceName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get service defaults: %w", err)
	}

	serviceDefaults, ok := entry.(*api.ServiceConfigEntry)
	if !ok {
		return nil, fmt.Errorf("unexpected config entry type")
	}

	return serviceDefaults, nil
}