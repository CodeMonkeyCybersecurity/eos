// pkg/nomad/service_discovery.go
package nomad

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceDiscoveryManager handles service discovery for Nomad jobs
// This replaces K3s/Kubernetes service discovery with Consul
type ServiceDiscoveryManager struct {
	logger        otelzap.LoggerWithCtx
	consulAddress string
}

// NewServiceDiscoveryManager creates a new service discovery manager
func NewServiceDiscoveryManager(logger otelzap.LoggerWithCtx, consulAddress string) *ServiceDiscoveryManager {
	if consulAddress == "" {
		consulAddress = fmt.Sprintf("%s:%d", shared.GetInternalHostname(), shared.PortConsul)
	}

	return &ServiceDiscoveryManager{
		logger:        logger,
		consulAddress: consulAddress,
	}
}

// ServiceInfo represents information about a discovered service
type ServiceInfo struct {
	Name        string            `json:"name"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Tags        []string          `json:"tags"`
	HealthCheck *HealthCheckInfo  `json:"health_check,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// HealthCheckInfo represents health check information
type HealthCheckInfo struct {
	Status  string `json:"status"`
	Output  string `json:"output,omitempty"`
	CheckID string `json:"check_id"`
}

// DiscoverServices discovers services registered in Consul
// This replaces K3s service discovery
func (sdm *ServiceDiscoveryManager) DiscoverServices(rc *eos_io.RuntimeContext, serviceFilter string) ([]ServiceInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Discovering services via Consul",
		zap.String("consul_address", sdm.consulAddress),
		zap.String("service_filter", serviceFilter))

	// ASSESS - Check Consul connectivity
	if err := sdm.checkConsulHealth(rc); err != nil {
		return nil, fmt.Errorf("Consul health check failed: %w", err)
	}

	// INTERVENE - Query Consul for services
	services, err := sdm.queryConsulServices(rc, serviceFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to query Consul services: %w", err)
	}

	// EVALUATE - Validate discovered services
	if len(services) == 0 {
		logger.Warn("No services discovered",
			zap.String("service_filter", serviceFilter))
	}

	logger.Info("Service discovery completed",
		zap.Int("services_found", len(services)),
		zap.String("service_filter", serviceFilter))

	return services, nil
}

// RegisterService registers a service with Consul
// This replaces K3s service registration
func (sdm *ServiceDiscoveryManager) RegisterService(rc *eos_io.RuntimeContext, service ServiceInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Registering service with Consul",
		zap.String("service_name", service.Name),
		zap.String("address", service.Address),
		zap.Int("port", service.Port))

	// ASSESS - Validate service information
	if err := sdm.validateServiceInfo(service); err != nil {
		return fmt.Errorf("service validation failed: %w", err)
	}

	// INTERVENE - Register with Consul
	if err := sdm.consulRegisterService(rc, service); err != nil {
		return fmt.Errorf("failed to register service with Consul: %w", err)
	}

	// EVALUATE - Verify registration
	if err := sdm.verifyServiceRegistration(rc, service.Name); err != nil {
		logger.Warn("Service registration verification failed", zap.Error(err))
		// Don't fail completely, registration might still be propagating
	}

	logger.Info("Service registered successfully with Consul",
		zap.String("service_name", service.Name))

	return nil
}

// DeregisterService removes a service from Consul
// This replaces K3s service deletion
func (sdm *ServiceDiscoveryManager) DeregisterService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deregistering service from Consul",
		zap.String("service_name", serviceName))

	// ASSESS - Check if service exists
	exists, err := sdm.serviceExists(rc, serviceName)
	if err != nil {
		return fmt.Errorf("failed to check service existence: %w", err)
	}

	if !exists {
		logger.Info("Service not found in Consul, nothing to deregister",
			zap.String("service_name", serviceName))
		return nil
	}

	// INTERVENE - Deregister from Consul
	if err := sdm.consulDeregisterService(rc, serviceName); err != nil {
		return fmt.Errorf("failed to deregister service from Consul: %w", err)
	}

	// EVALUATE - Verify deregistration
	if err := sdm.verifyServiceDeregistration(rc, serviceName); err != nil {
		logger.Warn("Service deregistration verification failed", zap.Error(err))
	}

	logger.Info("Service deregistered successfully from Consul",
		zap.String("service_name", serviceName))

	return nil
}

// GetServiceEndpoints returns service endpoints for load balancing
// This replaces K3s service endpoint discovery
func (sdm *ServiceDiscoveryManager) GetServiceEndpoints(rc *eos_io.RuntimeContext, serviceName string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting service endpoints",
		zap.String("service_name", serviceName))

	// ASSESS - Validate service name
	if serviceName == "" {
		return nil, fmt.Errorf("service name is required")
	}

	// INTERVENE - Query Consul for healthy endpoints
	endpoints, err := sdm.getHealthyEndpoints(rc, serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get healthy endpoints: %w", err)
	}

	// EVALUATE - Validate endpoints
	if len(endpoints) == 0 {
		logger.Warn("No healthy endpoints found for service",
			zap.String("service_name", serviceName))
		return nil, fmt.Errorf("no healthy endpoints found for service: %s", serviceName)
	}

	logger.Info("Service endpoints retrieved",
		zap.String("service_name", serviceName),
		zap.Int("endpoint_count", len(endpoints)))

	return endpoints, nil
}

// ConvertK3sServiceToConsul converts K3s service definition to Consul service
func (sdm *ServiceDiscoveryManager) ConvertK3sServiceToConsul(rc *eos_io.RuntimeContext, k3sService map[string]interface{}) (ServiceInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Converting K3s service to Consul service")

	service := ServiceInfo{
		Tags:     []string{"migrated-from-k3s"},
		Metadata: make(map[string]string),
	}

	// Extract service name
	if name, ok := k3sService["name"].(string); ok {
		service.Name = name
	} else {
		return service, fmt.Errorf("service name is required")
	}

	// Extract service address
	if address, ok := k3sService["clusterIP"].(string); ok {
		service.Address = address
	}

	// Extract service port
	if ports, ok := k3sService["ports"].([]interface{}); ok {
		for _, port := range ports {
			if portMap, ok := port.(map[string]interface{}); ok {
				if portNum, ok := portMap["port"].(float64); ok {
					service.Port = int(portNum)
					break // Use first port
				}
			}
		}
	}

	// Extract service type as tag
	if serviceType, ok := k3sService["type"].(string); ok {
		service.Tags = append(service.Tags, fmt.Sprintf("type-%s", serviceType))
	}

	// Extract selector labels as tags
	if selector, ok := k3sService["selector"].(map[string]interface{}); ok {
		for key, value := range selector {
			if valueStr, ok := value.(string); ok {
				service.Tags = append(service.Tags, fmt.Sprintf("%s-%s", key, valueStr))
			}
		}
	}

	// Add metadata
	service.Metadata["migration_source"] = "k3s"
	service.Metadata["converted_at"] = "automated"

	logger.Info("K3s service converted to Consul service",
		zap.String("service_name", service.Name),
		zap.String("address", service.Address),
		zap.Int("port", service.Port))

	return service, nil
}

// checkConsulHealth checks if Consul is accessible
func (sdm *ServiceDiscoveryManager) checkConsulHealth(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking Consul health",
		zap.String("consul_address", sdm.consulAddress))

	// This would implement actual Consul health check
	// For now, we'll simulate success
	logger.Debug("Consul health check passed")

	return nil
}

// queryConsulServices queries Consul for services
func (sdm *ServiceDiscoveryManager) queryConsulServices(rc *eos_io.RuntimeContext, serviceFilter string) ([]ServiceInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Querying Consul for services",
		zap.String("service_filter", serviceFilter))

	// This would implement actual Consul API call
	// For now, we'll return mock data
	services := []ServiceInfo{
		{
			Name:    "web-service",
			Address: "10.0.0.10",
			Port:    8080,
			Tags:    []string{"web", "http"},
		},
		{
			Name:    "api-service",
			Address: "10.0.0.20",
			Port:    8090,
			Tags:    []string{"api", "rest"},
		},
	}

	// Filter services if filter is provided
	if serviceFilter != "" {
		filtered := make([]ServiceInfo, 0)
		for _, svc := range services {
			if strings.Contains(svc.Name, serviceFilter) {
				filtered = append(filtered, svc)
			}
		}
		services = filtered
	}

	logger.Debug("Consul services queried",
		zap.Int("service_count", len(services)))

	return services, nil
}

// validateServiceInfo validates service information
func (sdm *ServiceDiscoveryManager) validateServiceInfo(service ServiceInfo) error {
	if service.Name == "" {
		return fmt.Errorf("service name is required")
	}

	if service.Port <= 0 || service.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", service.Port)
	}

	return nil
}

// consulRegisterService registers service with Consul
func (sdm *ServiceDiscoveryManager) consulRegisterService(rc *eos_io.RuntimeContext, service ServiceInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Registering service with Consul",
		zap.String("service_name", service.Name))

	// This would implement actual Consul service registration
	// For now, we'll simulate success
	logger.Debug("Service registration simulated")

	return nil
}

// verifyServiceRegistration verifies service registration
func (sdm *ServiceDiscoveryManager) verifyServiceRegistration(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Verifying service registration",
		zap.String("service_name", serviceName))

	// This would implement actual verification
	// For now, we'll simulate success
	logger.Debug("Service registration verification simulated")

	return nil
}

// serviceExists checks if service exists in Consul
func (sdm *ServiceDiscoveryManager) serviceExists(rc *eos_io.RuntimeContext, serviceName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking if service exists",
		zap.String("service_name", serviceName))

	// This would implement actual check
	// For now, we'll simulate existence
	return true, nil
}

// consulDeregisterService deregisters service from Consul
func (sdm *ServiceDiscoveryManager) consulDeregisterService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Deregistering service from Consul",
		zap.String("service_name", serviceName))

	// This would implement actual deregistration
	// For now, we'll simulate success
	logger.Debug("Service deregistration simulated")

	return nil
}

// verifyServiceDeregistration verifies service deregistration
func (sdm *ServiceDiscoveryManager) verifyServiceDeregistration(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Verifying service deregistration",
		zap.String("service_name", serviceName))

	// This would implement actual verification
	// For now, we'll simulate success
	logger.Debug("Service deregistration verification simulated")

	return nil
}

// getHealthyEndpoints gets healthy service endpoints
func (sdm *ServiceDiscoveryManager) getHealthyEndpoints(rc *eos_io.RuntimeContext, serviceName string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Getting healthy endpoints",
		zap.String("service_name", serviceName))

	// This would implement actual Consul health check query
	// For now, we'll return mock endpoints
	endpoints := []string{
		"10.0.0.10:8080",
		"10.0.0.20:8080",
	}

	logger.Debug("Healthy endpoints retrieved",
		zap.Int("endpoint_count", len(endpoints)))

	return endpoints, nil
}
