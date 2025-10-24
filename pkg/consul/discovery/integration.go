// pkg/consul/discovery/integration.go
//
// Service Discovery Integration Examples
//
// Demonstrates how to integrate service discovery into EOS services.
//
// *Last Updated: 2025-01-24*

package discovery

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RegisterEOSService registers an EOS service with Consul
//
// This is the standard pattern for registering EOS services with proper
// health checks and metadata.
//
// Example usage in service installation:
//
//	// After deploying a service like BionicGPT
//	err := discovery.RegisterEOSService(rc, consulClient, &discovery.EOSServiceConfig{
//	    ServiceName: "bionicgpt",
//	    ServicePort: 7860,
//	    HealthCheckURL: "http://localhost:7860/health",
//	    Tags: []string{"ai", "llm", "production"},
//	    Metadata: map[string]string{
//	        "version": "1.0.0",
//	        "environment": "production",
//	    },
//	})
func RegisterEOSService(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	config *EOSServiceConfig) error {

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Registering EOS service with Consul",
		zap.String("service", config.ServiceName),
		zap.Int("port", config.ServicePort))

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return fmt.Errorf("failed to create discovery client: %w", err)
	}

	// Get local address (for now, use localhost - could be enhanced to detect actual IP)
	serviceAddress := config.ServiceAddress
	if serviceAddress == "" {
		serviceAddress = "127.0.0.1"
	}

	// Build service ID
	serviceID := fmt.Sprintf("%s-%s", config.ServiceName, config.NodeName)
	if serviceID == "" {
		serviceID = config.ServiceName
	}

	// Create service registration
	registration := &ServiceRegistration{
		ID:      serviceID,
		Name:    config.ServiceName,
		Address: serviceAddress,
		Port:    config.ServicePort,
		Tags:    config.Tags,
		Meta:    config.Metadata,
	}

	// Add health check if provided
	if config.HealthCheckURL != "" {
		registration.HealthCheck = &HealthCheck{
			ID:                     fmt.Sprintf("%s-health", serviceID),
			Name:                   fmt.Sprintf("%s Health Check", config.ServiceName),
			Type:                   HealthCheckHTTP,
			HTTP:                   config.HealthCheckURL,
			Interval:               config.HealthCheckInterval,
			Timeout:                config.HealthCheckTimeout,
			SuccessBeforePassing:   2, // Require 2 consecutive passes
			FailuresBeforeCritical: 3, // Allow 3 failures before critical
		}

		// Use defaults if not specified
		if registration.HealthCheck.Interval == 0 {
			registration.HealthCheck.Interval = 10 * time.Second
		}
		if registration.HealthCheck.Timeout == 0 {
			registration.HealthCheck.Timeout = 2 * time.Second
		}
	} else if config.HealthCheckTCP != "" {
		// TCP health check as fallback
		registration.HealthCheck = &HealthCheck{
			ID:                     fmt.Sprintf("%s-health", serviceID),
			Name:                   fmt.Sprintf("%s TCP Health Check", config.ServiceName),
			Type:                   HealthCheckTCP,
			TCP:                    config.HealthCheckTCP,
			Interval:               10 * time.Second,
			Timeout:                2 * time.Second,
			SuccessBeforePassing:   2,
			FailuresBeforeCritical: 3,
		}
	}

	// Register with Consul
	if err := client.RegisterService(registration); err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	logger.Info("EOS service registered successfully",
		zap.String("service", config.ServiceName),
		zap.String("service_id", serviceID))

	return nil
}

// EOSServiceConfig contains configuration for registering an EOS service
type EOSServiceConfig struct {
	ServiceName    string            // Service name (e.g., "bionicgpt", "vault")
	ServicePort    int               // Service port
	ServiceAddress string            // Service address (optional, defaults to 127.0.0.1)
	NodeName       string            // Node name (optional, for multi-instance services)
	Tags           []string          // Service tags
	Metadata       map[string]string // Service metadata

	// Health check configuration
	HealthCheckURL      string        // HTTP health check URL (e.g., "http://localhost:7860/health")
	HealthCheckTCP      string        // TCP health check (e.g., "localhost:7860")
	HealthCheckInterval time.Duration // Health check interval (default: 10s)
	HealthCheckTimeout  time.Duration // Health check timeout (default: 2s)
}

// DiscoverEOSServices discovers all EOS-managed services
//
// Returns a map of service names to their addresses.
//
// Example:
//
//	services, err := discovery.DiscoverEOSServices(rc, consulClient)
//	for name, addresses := range services {
//	    fmt.Printf("Service %s has %d instances\n", name, len(addresses))
//	}
func DiscoverEOSServices(rc *eos_io.RuntimeContext, consulClient *consulapi.Client) (map[string][]*ServiceAddress, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Discovering all EOS services")

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return nil, err
	}

	// Get all services
	allServices, err := client.ListAllServices()
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	result := make(map[string][]*ServiceAddress)

	// Common EOS services
	eosServices := []string{
		"vault", "consul", "nomad",
		"bionicgpt", "wazuh", "openwebui",
		"mattermost", "ceph", "postgres",
	}

	for _, serviceName := range eosServices {
		if _, exists := allServices[serviceName]; exists {
			addresses, err := client.FindService(serviceName)
			if err != nil {
				logger.Warn("Failed to discover service",
					zap.String("service", serviceName),
					zap.Error(err))
				continue
			}
			result[serviceName] = addresses
		}
	}

	logger.Info("EOS services discovered",
		zap.Int("service_count", len(result)))

	return result, nil
}

// ConnectToService establishes a connection to a discovered service
//
// This is a convenience function that discovers the service and returns
// a connection endpoint ready to use.
//
// Example:
//
//	endpoint, err := discovery.ConnectToService(rc, consulClient, "vault", "https")
//	vaultClient, err := vaultapi.NewClient(&vaultapi.Config{
//	    Address: endpoint,
//	})
func ConnectToService(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	serviceName, scheme string) (string, error) {

	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Connecting to service",
		zap.String("service", serviceName),
		zap.String("scheme", scheme))

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return "", err
	}

	endpoint, err := client.GetServiceURL(serviceName, scheme)
	if err != nil {
		return "", fmt.Errorf("failed to connect to service %s: %w", serviceName, err)
	}

	logger.Info("Connected to service",
		zap.String("service", serviceName),
		zap.String("endpoint", endpoint))

	return endpoint, nil
}

// UpdateServiceMetadata updates metadata for a registered service
//
// Example:
//
//	err := discovery.UpdateServiceMetadata(rc, consulClient, "bionicgpt",
//	    map[string]string{
//	        "version": "1.1.0",
//	        "last_updated": time.Now().Format(time.RFC3339),
//	    })
func UpdateServiceMetadata(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	serviceName string, metadata map[string]string) error {

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Updating service metadata",
		zap.String("service", serviceName))

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return err
	}

	// Find the service to get its ID
	addresses, err := client.FindService(serviceName)
	if err != nil {
		return fmt.Errorf("failed to find service %s: %w", serviceName, err)
	}

	if len(addresses) == 0 {
		return fmt.Errorf("no instances of service %s found", serviceName)
	}

	// Update metadata via registry
	serviceID := fmt.Sprintf("%s-%s", serviceName, addresses[0].NodeName)
	if err := client.registry.UpdateServiceMetadata(rc.Ctx, serviceID, metadata); err != nil {
		return fmt.Errorf("failed to update metadata: %w", err)
	}

	logger.Info("Service metadata updated successfully",
		zap.String("service", serviceName))

	return nil
}

// MonitorServiceHealth monitors a service's health and calls callback on changes
//
// Example:
//
//	go discovery.MonitorServiceHealth(rc, consulClient, "vault", func(healthy bool) {
//	    if !healthy {
//	        logger.Warn("Vault became unhealthy!")
//	        // Send alert, fail over, etc.
//	    }
//	})
func MonitorServiceHealth(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	serviceName string, callback func(healthy bool)) error {

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting service health monitoring",
		zap.String("service", serviceName))

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return err
	}

	// Watch for service changes
	return client.WatchService(serviceName, func(addresses []*ServiceAddress) {
		// Check if any instances are healthy
		healthy := false
		for _, addr := range addresses {
			if addr.Health == "passing" {
				healthy = true
				break
			}
		}

		callback(healthy)
	})
}
