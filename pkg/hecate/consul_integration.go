// pkg/hecate/consul_integration.go
// Consul service discovery integration for Hecate reverse proxy

package hecate

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BackendServiceRegistration contains parameters for registering a backend service
type BackendServiceRegistration struct {
	ID                  string
	Name                string
	LocalAddress        string
	PublicDomain        string
	Port                int
	Tags                []string
	HealthCheckHTTP     string
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
}

// ConsulServiceDiscovery discovers backend services via Consul
type ConsulServiceDiscovery struct {
	client     *api.Client
	datacenter string
	logger     otelzap.LoggerWithCtx
}

// NewConsulServiceDiscovery creates a new Consul service discovery client
func NewConsulServiceDiscovery(rc *eos_io.RuntimeContext, datacenter string) (*ConsulServiceDiscovery, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check Consul connectivity
	logger.Debug("Connecting to Consul for service discovery",
		zap.String("datacenter", datacenter))

	config := api.DefaultConfig()
	// Allow override via environment variable CONSUL_HTTP_ADDR
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Verify connectivity
	_, err = client.Status().Leader()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Consul: %w", err)
	}

	return &ConsulServiceDiscovery{
		client:     client,
		datacenter: datacenter,
		logger:     logger,
	}, nil
}

// DiscoverBackend discovers a backend service by name
func (csd *ConsulServiceDiscovery) DiscoverBackend(ctx context.Context, serviceName string) (*Upstream, error) {
	logger := csd.logger

	// ASSESS - Query Consul for healthy service instances
	logger.Info("Discovering backend service via Consul",
		zap.String("service", serviceName),
		zap.String("datacenter", csd.datacenter))

	services, _, err := csd.client.Health().Service(serviceName, "", true, &api.QueryOptions{
		Datacenter: csd.datacenter,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to query Consul for service %s: %w", serviceName, err)
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("no healthy instances of service %s found in datacenter %s", serviceName, csd.datacenter)
	}

	// INTERVENE - Use first healthy instance
	service := services[0]
	upstream := &Upstream{
		URL:             fmt.Sprintf("http://%s:%d", service.Service.Address, service.Service.Port),
		TLSSkipVerify:   false,
		HealthCheckPath: "/health",
		Timeout:         30 * time.Second,
		MaxIdleConns:    100,
		MaxConnsPerHost: 10,
		KeepAlive:       90 * time.Second,
	}

	// Check service metadata for TLS
	if tls, ok := service.Service.Meta["tls"]; ok && tls == "true" {
		upstream.URL = fmt.Sprintf("https://%s:%d", service.Service.Address, service.Service.Port)
	}

	// Override health check path from metadata
	if healthPath, ok := service.Service.Meta["health_check_path"]; ok {
		upstream.HealthCheckPath = healthPath
	}

	logger.Info("Discovered backend service",
		zap.String("service", serviceName),
		zap.String("url", upstream.URL),
		zap.Int("total_instances", len(services)))

	return upstream, nil
}

// WatchBackend watches for changes to a backend service
func (csd *ConsulServiceDiscovery) WatchBackend(ctx context.Context, serviceName string, onChange func(*Upstream)) error {
	logger := csd.logger

	logger.Info("Starting watch for backend service",
		zap.String("service", serviceName))

	// Use Consul blocking queries for efficient watching
	opts := &api.QueryOptions{
		Datacenter:        csd.datacenter,
		WaitIndex:         0,
		WaitTime:          5 * time.Minute,
		AllowStale:        false,
		RequireConsistent: false,
	}

	for {
		services, meta, err := csd.client.Health().Service(serviceName, "", true, opts)
		if err != nil {
			if ctx.Err() != nil {
				// Context cancelled, exit gracefully
				return nil
			}
			logger.Error("Failed to watch service",
				zap.String("service", serviceName),
				zap.Error(err))
			time.Sleep(10 * time.Second)
			continue
		}

		// Update wait index for next blocking query
		opts.WaitIndex = meta.LastIndex

		// Notify about changes
		if len(services) > 0 {
			service := services[0]
			upstream := &Upstream{
				URL: fmt.Sprintf("http://%s:%d", service.Service.Address, service.Service.Port),
			}
			onChange(upstream)

			logger.Debug("Backend service changed",
				zap.String("service", serviceName),
				zap.String("new_url", upstream.URL))
		}
	}
}

// RegisterBackendService registers a backend service with Consul
// This is idempotent - safe to call multiple times
func (csd *ConsulServiceDiscovery) RegisterBackendService(ctx context.Context, backend BackendServiceRegistration) error {
	logger := csd.logger

	// ASSESS - Check if service already registered
	services, err := csd.client.Agent().Services()
	if err != nil {
		return fmt.Errorf("failed to query existing services: %w", err)
	}

	// Idempotent: Check if already registered
	if existing, exists := services[backend.ID]; exists {
		logger.Info("Service already registered, checking if update needed",
			zap.String("service_id", backend.ID),
			zap.String("service_name", backend.Name))

		// Check if configuration changed
		if existing.Port == backend.Port && existing.Address == backend.LocalAddress {
			logger.Info("Service already registered with correct configuration")
			return nil
		}

		logger.Info("Service configuration changed, updating registration")
	}

	// INTERVENE - Register or update service
	registration := &api.AgentServiceRegistration{
		ID:      backend.ID,
		Name:    backend.Name,
		Address: backend.LocalAddress,
		Port:    backend.Port,
		Tags:    backend.Tags,
		Meta: map[string]string{
			"managed_by":    "eos-hecate",
			"public_domain": backend.PublicDomain,
			"datacenter":    csd.datacenter,
			"environment":   csd.datacenter,
		},
		Check: &api.AgentServiceCheck{
			HTTP:     backend.HealthCheckHTTP,
			Interval: backend.HealthCheckInterval.String(),
			Timeout:  backend.HealthCheckTimeout.String(),
		},
	}

	if err := csd.client.Agent().ServiceRegister(registration); err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	// EVALUATE - Verify registration
	services, err = csd.client.Agent().Services()
	if err != nil {
		return fmt.Errorf("failed to verify service registration: %w", err)
	}

	if _, exists := services[backend.ID]; !exists {
		return fmt.Errorf("service registration verification failed")
	}

	logger.Info("Backend service registered successfully",
		zap.String("service_id", backend.ID),
		zap.String("service_name", backend.Name),
		zap.String("address", backend.LocalAddress),
		zap.Int("port", backend.Port))

	return nil
}

// DeregisterBackendService removes a backend service from Consul
// This is idempotent - safe to call even if service doesn't exist
func (csd *ConsulServiceDiscovery) DeregisterBackendService(serviceID string) error {
	logger := csd.logger

	// ASSESS - Check if service exists
	services, err := csd.client.Agent().Services()
	if err != nil {
		return fmt.Errorf("failed to query existing services: %w", err)
	}

	if _, exists := services[serviceID]; !exists {
		logger.Info("Service already deregistered",
			zap.String("service_id", serviceID))
		return nil
	}

	// INTERVENE - Deregister
	if err := csd.client.Agent().ServiceDeregister(serviceID); err != nil {
		return fmt.Errorf("failed to deregister service: %w", err)
	}

	logger.Info("Backend service deregistered",
		zap.String("service_id", serviceID))

	return nil
}

// GetEnvironmentConfig retrieves environment configuration from Consul K/V
// This stores things like Vault address, Nomad address, etc.
func (csd *ConsulServiceDiscovery) GetEnvironmentConfig(ctx context.Context, key string) (string, error) {
	logger := csd.logger

	kvPath := fmt.Sprintf("eos/config/%s/%s", csd.datacenter, key)
	logger.Debug("Retrieving environment config from Consul K/V",
		zap.String("key", kvPath))

	pair, _, err := csd.client.KV().Get(kvPath, &api.QueryOptions{
		Datacenter: csd.datacenter,
	})

	if err != nil {
		return "", fmt.Errorf("failed to get key %s: %w", kvPath, err)
	}

	if pair == nil {
		return "", fmt.Errorf("key %s not found", kvPath)
	}

	return string(pair.Value), nil
}

// SetEnvironmentConfig stores environment configuration in Consul K/V
// This is idempotent - safe to call multiple times with same value
func (csd *ConsulServiceDiscovery) SetEnvironmentConfig(ctx context.Context, key, value string) error {
	logger := csd.logger

	kvPath := fmt.Sprintf("eos/config/%s/%s", csd.datacenter, key)

	// ASSESS - Check if value already set correctly
	existing, _, err := csd.client.KV().Get(kvPath, &api.QueryOptions{
		Datacenter: csd.datacenter,
	})

	if err == nil && existing != nil && string(existing.Value) == value {
		logger.Debug("Config key already set to correct value",
			zap.String("key", kvPath))
		return nil
	}

	// INTERVENE - Set or update value
	pair := &api.KVPair{
		Key:   kvPath,
		Value: []byte(value),
	}

	_, err = csd.client.KV().Put(pair, &api.WriteOptions{
		Datacenter: csd.datacenter,
	})

	if err != nil {
		return fmt.Errorf("failed to set key %s: %w", kvPath, err)
	}

	logger.Info("Environment config updated",
		zap.String("key", kvPath),
		zap.String("value", value))

	return nil
}
