// pkg/consul/registry/registry.go
//
// ServiceRegistry provides programmatic service discovery and registration
// using the Consul API. This replaces file-based service registration with
// dynamic SDK-based operations.
//
// Last Updated: 2025-10-23

package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceRegistry provides programmatic service discovery and registration
// ASSESS → INTERVENE → EVALUATE pattern for all operations
type ServiceRegistry interface {
	// Service Registration
	RegisterService(ctx context.Context, service *ServiceRegistration) error
	DeregisterService(ctx context.Context, serviceID string) error
	UpdateService(ctx context.Context, serviceID string, service *ServiceRegistration) error

	// Service Discovery
	DiscoverService(ctx context.Context, serviceName string, opts *DiscoveryOptions) ([]*ServiceInstance, error)
	DiscoverHealthyServices(ctx context.Context, serviceName string) ([]*ServiceInstance, error)
	WatchService(ctx context.Context, serviceName string, callback ServiceWatchCallback) error

	// Health Checks
	RegisterHealthCheck(ctx context.Context, check *HealthCheck) error
	DeregisterHealthCheck(ctx context.Context, checkID string) error
	UpdateHealthCheckStatus(ctx context.Context, checkID string, status HealthStatus, output string) error

	// Service Metadata
	GetServiceMetadata(ctx context.Context, serviceID string) (map[string]string, error)
	UpdateServiceMetadata(ctx context.Context, serviceID string, metadata map[string]string) error

	// Query and Filtering
	ListServices(ctx context.Context, filters *ServiceFilter) ([]*ServiceInstance, error)
	QueryServicesByTag(ctx context.Context, tag string) ([]*ServiceInstance, error)
}

// ServiceRegistration defines a service to register in Consul
type ServiceRegistration struct {
	ID      string            // Unique service ID (e.g., "vault-vhost5")
	Name    string            // Service name (e.g., "vault")
	Address string            // Service IP address
	Port    int               // Service port
	Tags    []string          // Service tags for filtering
	Meta    map[string]string // Service metadata
	Check   *HealthCheck      // Primary health check
	Checks  []*HealthCheck    // Additional health checks
	Weights *ServiceWeights   // Load balancing weights
}

// ServiceInstance represents a discovered service instance
type ServiceInstance struct {
	ID       string
	Name     string
	Address  string
	Port     int
	Tags     []string
	Meta     map[string]string
	Health   HealthStatus
	Checks   []*HealthCheckResult
	Weights  *ServiceWeights
	NodeName string
}

// HealthCheck defines a service health check
type HealthCheck struct {
	ID                     string            // Check ID (e.g., "vault-health")
	Name                   string            // Human-readable name
	Type                   HealthCheckType   // HTTP, TCP, Script, TTL, Docker, gRPC
	HTTP                   string            // HTTP endpoint (for HTTP checks)
	TCP                    string            // TCP address (for TCP checks)
	Script                 string            // Script path (for script checks)
	GRPC                   string            // gRPC endpoint
	Interval               time.Duration     // Check interval
	Timeout                time.Duration     // Check timeout
	TLSSkipVerify          bool                // Skip TLS verification
	SuccessBeforePassing   int                 // Consecutive passes before healthy
	FailuresBeforeCritical int                 // Consecutive fails before critical
	Header                 map[string][]string // HTTP headers
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	CheckID string
	Name    string
	Status  HealthStatus
	Output  string
	Node    string
}

// HealthCheckType defines the type of health check
type HealthCheckType string

const (
	HealthCheckHTTP   HealthCheckType = "http"
	HealthCheckHTTPS  HealthCheckType = "https"
	HealthCheckTCP    HealthCheckType = "tcp"
	HealthCheckScript HealthCheckType = "script"
	HealthCheckTTL    HealthCheckType = "ttl"
	HealthCheckDocker HealthCheckType = "docker"
	HealthCheckGRPC   HealthCheckType = "grpc"
)

// HealthStatus represents the health status of a service or check
type HealthStatus string

const (
	HealthPassing  HealthStatus = "passing"
	HealthWarning  HealthStatus = "warning"
	HealthCritical HealthStatus = "critical"
	HealthUnknown  HealthStatus = "unknown"
)

// ServiceWeights defines load balancing weights
type ServiceWeights struct {
	Passing int // Weight when service is healthy
	Warning int // Weight when service has warnings
}

// DiscoveryOptions controls service discovery behavior
type DiscoveryOptions struct {
	OnlyHealthy bool     // Only return healthy instances
	Tags        []string // Filter by tags
	Datacenter  string   // Specific datacenter
	Near        string   // Node name for proximity sorting
	WaitIndex   uint64   // For blocking queries
	WaitTime    time.Duration
}

// ServiceFilter allows complex service queries
type ServiceFilter struct {
	Name       string            // Service name pattern
	Tags       []string          // Required tags (AND)
	Meta       map[string]string // Required metadata (AND)
	Health     HealthStatus      // Minimum health status
	Datacenter string            // Specific datacenter
}

// ServiceWatchCallback is called when a watched service changes
type ServiceWatchCallback func(instances []*ServiceInstance, err error)

// ConsulServiceRegistry implements ServiceRegistry using Consul API
type ConsulServiceRegistry struct {
	client *api.Client
	agent  *api.Agent
	health *api.Health
	logger otelzap.LoggerWithCtx
}

// NewServiceRegistry creates a new Consul-backed service registry
func NewServiceRegistry(ctx context.Context, consulAddress string) (ServiceRegistry, error) {
	logger := otelzap.Ctx(ctx)

	// ASSESS - Validate connection parameters
	if consulAddress == "" {
		consulAddress = "127.0.0.1:8500" // Default Consul address
	}

	logger.Info("Creating Consul service registry",
		zap.String("consul_address", consulAddress))

	// INTERVENE - Create Consul client
	config := api.DefaultConfig()
	config.Address = consulAddress

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// EVALUATE - Verify connection
	agent := client.Agent()
	if _, err := agent.Self(); err != nil {
		logger.Warn("Failed to verify Consul connection",
			zap.Error(err),
			zap.String("consul_address", consulAddress))
		// Don't fail - allow offline operation
	}

	registry := &ConsulServiceRegistry{
		client: client,
		agent:  agent,
		health: client.Health(),
		logger: logger,
	}

	logger.Info("Consul service registry created successfully",
		zap.String("consul_address", consulAddress))

	return registry, nil
}

// RegisterService registers a service in Consul
func (r *ConsulServiceRegistry) RegisterService(ctx context.Context, service *ServiceRegistration) error {
	r.logger.Info("ASSESS: Registering service",
		zap.String("service_id", service.ID),
		zap.String("service_name", service.Name),
		zap.String("address", service.Address),
		zap.Int("port", service.Port))

	// Validate service registration
	if service.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if service.ID == "" {
		service.ID = service.Name // Default to service name if no ID
	}

	// INTERVENE - Build Consul API registration
	registration := &api.AgentServiceRegistration{
		ID:      service.ID,
		Name:    service.Name,
		Address: service.Address,
		Port:    service.Port,
		Tags:    service.Tags,
		Meta:    service.Meta,
	}

	// Add health check
	if service.Check != nil {
		registration.Check = convertHealthCheck(service.Check)
	}

	// Add multiple checks
	if len(service.Checks) > 0 {
		registration.Checks = make([]*api.AgentServiceCheck, len(service.Checks))
		for i, check := range service.Checks {
			registration.Checks[i] = convertHealthCheck(check)
		}
	}

	// Add weights
	if service.Weights != nil {
		registration.Weights = &api.AgentWeights{
			Passing: service.Weights.Passing,
			Warning: service.Weights.Warning,
		}
	}

	// Register with Consul
	if err := r.agent.ServiceRegister(registration); err != nil {
		r.logger.Error("INTERVENE FAILED: Service registration failed",
			zap.String("service_id", service.ID),
			zap.Error(err))
		return fmt.Errorf("failed to register service %s: %w", service.ID, err)
	}

	// EVALUATE - Verify registration
	services, err := r.agent.Services()
	if err != nil {
		r.logger.Warn("EVALUATE: Failed to verify service registration",
			zap.Error(err))
		// Don't fail - registration likely succeeded
	} else if _, exists := services[service.ID]; !exists {
		r.logger.Error("EVALUATE FAILED: Service not found after registration",
			zap.String("service_id", service.ID))
		return fmt.Errorf("service %s not found after registration", service.ID)
	}

	r.logger.Info("EVALUATE SUCCESS: Service registered successfully",
		zap.String("service_id", service.ID),
		zap.String("service_name", service.Name))

	return nil
}

// DeregisterService removes a service from Consul
func (r *ConsulServiceRegistry) DeregisterService(ctx context.Context, serviceID string) error {
	r.logger.Info("ASSESS: Deregistering service",
		zap.String("service_id", serviceID))

	// ASSESS - Check if service exists
	services, err := r.agent.Services()
	if err != nil {
		r.logger.Warn("ASSESS: Failed to check service existence",
			zap.String("service_id", serviceID),
			zap.Error(err))
		// Continue anyway
	} else if _, exists := services[serviceID]; !exists {
		r.logger.Info("ASSESS: Service not registered, nothing to deregister",
			zap.String("service_id", serviceID))
		return nil // Idempotent - not an error
	}

	// INTERVENE - Deregister service
	if err := r.agent.ServiceDeregister(serviceID); err != nil {
		r.logger.Error("INTERVENE FAILED: Service deregistration failed",
			zap.String("service_id", serviceID),
			zap.Error(err))
		return fmt.Errorf("failed to deregister service %s: %w", serviceID, err)
	}

	// EVALUATE - Verify deregistration
	services, err = r.agent.Services()
	if err != nil {
		r.logger.Warn("EVALUATE: Failed to verify service deregistration",
			zap.Error(err))
		// Don't fail - deregistration likely succeeded
	} else if _, exists := services[serviceID]; exists {
		r.logger.Error("EVALUATE FAILED: Service still exists after deregistration",
			zap.String("service_id", serviceID))
		return fmt.Errorf("service %s still exists after deregistration", serviceID)
	}

	r.logger.Info("EVALUATE SUCCESS: Service deregistered successfully",
		zap.String("service_id", serviceID))

	return nil
}

// UpdateService updates an existing service registration
func (r *ConsulServiceRegistry) UpdateService(ctx context.Context, serviceID string, service *ServiceRegistration) error {
	r.logger.Info("ASSESS: Updating service",
		zap.String("service_id", serviceID))

	// In Consul, update = deregister + register
	// This is the recommended approach per Consul docs

	// First, deregister the old service
	if err := r.DeregisterService(ctx, serviceID); err != nil {
		r.logger.Warn("Failed to deregister service during update",
			zap.String("service_id", serviceID),
			zap.Error(err))
		// Continue - service may not exist
	}

	// Then register with new configuration
	service.ID = serviceID // Ensure ID matches
	return r.RegisterService(ctx, service)
}

// convertHealthCheck converts our HealthCheck to Consul's format
func convertHealthCheck(check *HealthCheck) *api.AgentServiceCheck {
	if check == nil {
		return nil
	}

	consulCheck := &api.AgentServiceCheck{
		CheckID:                        check.ID,
		Name:                           check.Name,
		Interval:                       check.Interval.String(),
		Timeout:                        check.Timeout.String(),
		TLSSkipVerify:                  check.TLSSkipVerify,
		SuccessBeforePassing:           check.SuccessBeforePassing,
		FailuresBeforeCritical:         check.FailuresBeforeCritical,
		Header:                         check.Header,
	}

	// Set check-type-specific fields
	switch check.Type {
	case HealthCheckHTTP, HealthCheckHTTPS:
		consulCheck.HTTP = check.HTTP
	case HealthCheckTCP:
		consulCheck.TCP = check.TCP
	case HealthCheckScript:
		consulCheck.Args = []string{check.Script}
	case HealthCheckGRPC:
		consulCheck.GRPC = check.GRPC
	case HealthCheckTTL:
		// TTL checks don't have interval/timeout
		consulCheck.TTL = check.Interval.String()
		consulCheck.Interval = ""
		consulCheck.Timeout = ""
	}

	return consulCheck
}
