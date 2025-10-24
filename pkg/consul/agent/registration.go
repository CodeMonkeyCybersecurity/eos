// pkg/consul/agent/registration.go
//
// Service registration helpers for Consul agents.
// Uses pkg/consul/registry for programmatic service registration.
//
// Last Updated: 2025-01-24

package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/registry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RegisterServices registers multiple services with a Consul agent.
//
// This function takes a list of service definitions and registers them
// with the specified Consul agent. Registration is idempotent - existing
// services are updated, not duplicated.
//
// Parameters:
//   - rc: RuntimeContext for logging
//   - agentAddr: Consul agent address (e.g., "http://localhost:8500")
//   - services: List of services to register
//
// Returns:
//   - error: First registration error encountered, or nil if all succeed
//
// Example:
//
//	services := []ServiceDefinition{
//	    {
//	        ID:   "web-01",
//	        Name: "web",
//	        Port: 8080,
//	        Tags: []string{"primary", "v2"},
//	        Checks: []HealthCheck{
//	            {Type: "http", Endpoint: "http://localhost:8080/health", Interval: "10s"},
//	        },
//	    },
//	}
//	err := RegisterServices(rc, "http://localhost:8500", services)
func RegisterServices(rc *eos_io.RuntimeContext, agentAddr string, services []ServiceDefinition) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(services) == 0 {
		logger.Debug("No services to register")
		return nil
	}

	logger.Info("Registering services with Consul",
		zap.String("agent_addr", agentAddr),
		zap.Int("service_count", len(services)))

	// Create service registry client
	reg, err := registry.NewServiceRegistry(rc.Ctx, agentAddr)
	if err != nil {
		return fmt.Errorf("failed to create service registry: %w", err)
	}

	// Register each service
	successCount := 0
	for i, svc := range services {
		logger.Debug("Registering service",
			zap.Int("index", i+1),
			zap.Int("total", len(services)),
			zap.String("service_id", svc.ID),
			zap.String("service_name", svc.Name))

		// Convert to registry format
		registration := convertToRegistryFormat(svc)

		// Register with Consul
		if err := reg.RegisterService(rc.Ctx, registration); err != nil {
			logger.Warn("Failed to register service",
				zap.String("service_id", svc.ID),
				zap.Error(err))
			// Continue with other services (non-fatal)
		} else {
			successCount++
			logger.Info("Service registered successfully",
				zap.String("service_id", svc.ID),
				zap.String("service_name", svc.Name),
				zap.Int("port", svc.Port))
		}
	}

	logger.Info("Service registration complete",
		zap.Int("total", len(services)),
		zap.Int("successful", successCount),
		zap.Int("failed", len(services)-successCount))

	if successCount == 0 && len(services) > 0 {
		return fmt.Errorf("failed to register any services (%d attempted)", len(services))
	}

	return nil
}

// RegisterService registers a single service with a Consul agent.
//
// Convenience function for registering a single service.
// Uses RegisterServices internally.
//
// Parameters:
//   - rc: RuntimeContext
//   - agentAddr: Consul agent address
//   - service: Service to register
//
// Returns:
//   - error: Registration error or nil
func RegisterService(rc *eos_io.RuntimeContext, agentAddr string, service ServiceDefinition) error {
	return RegisterServices(rc, agentAddr, []ServiceDefinition{service})
}

// DeregisterService removes a service registration from Consul.
//
// Parameters:
//   - rc: RuntimeContext
//   - agentAddr: Consul agent address
//   - serviceID: ID of service to deregister
//
// Returns:
//   - error: Deregistration error or nil
func DeregisterService(rc *eos_io.RuntimeContext, agentAddr string, serviceID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deregistering service from Consul",
		zap.String("agent_addr", agentAddr),
		zap.String("service_id", serviceID))

	// Create service registry client
	reg, err := registry.NewServiceRegistry(rc.Ctx, agentAddr)
	if err != nil {
		return fmt.Errorf("failed to create service registry: %w", err)
	}

	// Deregister
	if err := reg.DeregisterService(rc.Ctx, serviceID); err != nil {
		logger.Error("Failed to deregister service",
			zap.String("service_id", serviceID),
			zap.Error(err))
		return fmt.Errorf("failed to deregister service %s: %w", serviceID, err)
	}

	logger.Info("Service deregistered successfully",
		zap.String("service_id", serviceID))

	return nil
}

// convertToRegistryFormat converts agent.ServiceDefinition to registry.ServiceRegistration
func convertToRegistryFormat(svc ServiceDefinition) *registry.ServiceRegistration {
	registration := &registry.ServiceRegistration{
		ID:      svc.ID,
		Name:    svc.Name,
		Address: svc.Address,
		Port:    svc.Port,
		Tags:    svc.Tags,
		Meta:    svc.Meta,
	}

	// Convert health checks
	if len(svc.Checks) > 0 {
		registration.Checks = make([]*registry.HealthCheck, len(svc.Checks))
		for i, check := range svc.Checks {
			registration.Checks[i] = convertHealthCheck(check)
		}
	}

	// Convert weights
	if svc.Weights != nil {
		registration.Weights = &registry.ServiceWeights{
			Passing: svc.Weights.Passing,
			Warning: svc.Weights.Warning,
		}
	}

	return registration
}

// convertHealthCheck converts agent.HealthCheck to registry.HealthCheck
func convertHealthCheck(check HealthCheck) *registry.HealthCheck {
	regCheck := &registry.HealthCheck{
		ID:                     check.ID,
		Name:                   check.Name,
		TLSSkipVerify:          check.TLSSkipVerify,
		SuccessBeforePassing:   check.SuccessBeforePassing,
		FailuresBeforeCritical: check.FailuresBeforeCritical,
	}

	// Parse interval and timeout
	if interval, err := time.ParseDuration(check.Interval); err == nil {
		regCheck.Interval = interval
	}
	if timeout, err := time.ParseDuration(check.Timeout); err == nil {
		regCheck.Timeout = timeout
	}

	// Set type-specific fields
	switch check.Type {
	case "http", "https":
		regCheck.Type = registry.HealthCheckHTTP
		regCheck.HTTP = check.Endpoint
	case "tcp":
		regCheck.Type = registry.HealthCheckTCP
		regCheck.TCP = check.Endpoint
	case "grpc":
		regCheck.Type = registry.HealthCheckGRPC
		regCheck.GRPC = check.Endpoint
	case "script":
		regCheck.Type = registry.HealthCheckScript
		regCheck.Script = check.Endpoint
	case "ttl":
		regCheck.Type = registry.HealthCheckTTL
	default:
		// Default to HTTP if unknown
		regCheck.Type = registry.HealthCheckHTTP
		regCheck.HTTP = check.Endpoint
	}

	return regCheck
}

// ListServices retrieves all services registered with an agent.
//
// Parameters:
//   - ctx: Context for cancellation
//   - agentAddr: Consul agent address
//
// Returns:
//   - []string: List of service IDs
//   - error: Query error or nil
func ListServices(ctx context.Context, agentAddr string) ([]string, error) {
	// Create service registry client
	reg, err := registry.NewServiceRegistry(ctx, agentAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create service registry: %w", err)
	}

	// List all services
	instances, err := reg.ListServices(ctx, &registry.ServiceFilter{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	// Extract service IDs
	serviceIDs := make([]string, 0, len(instances))
	for _, instance := range instances {
		serviceIDs = append(serviceIDs, instance.ID)
	}

	return serviceIDs, nil
}
