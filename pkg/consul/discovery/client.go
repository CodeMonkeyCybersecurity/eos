// pkg/consul/discovery/client.go
//
// Service Discovery Client
//
// Provides high-level service discovery capabilities for EOS services.
// Wraps the lower-level registry package with convenience methods and
// integration with EOS RuntimeContext.
//
// *Last Updated: 2025-01-24*

package discovery

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/registry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Client provides service discovery capabilities
type Client struct {
	rc       *eos_io.RuntimeContext
	consul   *consulapi.Client
	registry registry.ServiceRegistry
	logger   otelzap.LoggerWithCtx
}

// NewClient creates a new service discovery client
func NewClient(rc *eos_io.RuntimeContext, consulClient *consulapi.Client) (*Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create registry client (empty string uses default Consul address)
	reg, err := registry.NewServiceRegistry(rc.Ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %w", err)
	}

	return &Client{
		rc:       rc,
		consul:   consulClient,
		registry: reg,
		logger:   logger,
	}, nil
}

// ServiceAddress represents a discovered service address
type ServiceAddress struct {
	Address  string            // IP address or hostname
	Port     int               // Port number
	Tags     []string          // Service tags
	Meta     map[string]string // Service metadata
	Health   registry.HealthStatus
	NodeName string
}

// FindService discovers healthy instances of a service
//
// Example:
//
//	client := discovery.NewClient(rc, consulClient)
//	addresses, err := client.FindService("vault")
//	for _, addr := range addresses {
//	    fmt.Printf("Found vault at %s:%d\n", addr.Address, addr.Port)
//	}
func (c *Client) FindService(serviceName string) ([]*ServiceAddress, error) {
	c.logger.Debug("Finding service",
		zap.String("service", serviceName))

	// Discover healthy instances
	instances, err := c.registry.DiscoverHealthyServices(c.rc.Ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to discover service %s: %w", serviceName, err)
	}

	if len(instances) == 0 {
		return nil, fmt.Errorf("no healthy instances of service %s found", serviceName)
	}

	// Convert to ServiceAddress format
	addresses := make([]*ServiceAddress, len(instances))
	for i, instance := range instances {
		addresses[i] = &ServiceAddress{
			Address:  instance.Address,
			Port:     instance.Port,
			Tags:     instance.Tags,
			Meta:     instance.Meta,
			Health:   instance.Health,
			NodeName: instance.NodeName,
		}
	}

	c.logger.Info("Service discovered",
		zap.String("service", serviceName),
		zap.Int("instances", len(addresses)))

	return addresses, nil
}

// FindServiceWithTag discovers services with a specific tag
//
// Example:
//
//	// Find all Vault instances with "primary" tag
//	addresses, err := client.FindServiceWithTag("vault", "primary")
func (c *Client) FindServiceWithTag(serviceName, tag string) ([]*ServiceAddress, error) {
	c.logger.Debug("Finding service with tag",
		zap.String("service", serviceName),
		zap.String("tag", tag))

	// Discover with tag filter
	instances, err := c.registry.DiscoverService(c.rc.Ctx, serviceName, &registry.DiscoveryOptions{
		OnlyHealthy: true,
		Tags:        []string{tag},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to discover service %s with tag %s: %w", serviceName, tag, err)
	}

	if len(instances) == 0 {
		return nil, fmt.Errorf("no healthy instances of service %s with tag %s found", serviceName, tag)
	}

	addresses := make([]*ServiceAddress, len(instances))
	for i, instance := range instances {
		addresses[i] = &ServiceAddress{
			Address:  instance.Address,
			Port:     instance.Port,
			Tags:     instance.Tags,
			Meta:     instance.Meta,
			Health:   instance.Health,
			NodeName: instance.NodeName,
		}
	}

	return addresses, nil
}

// GetServiceURL returns a complete URL for a service
//
// Example:
//
//	vaultURL, err := client.GetServiceURL("vault", "https")
//	// Returns: "https://10.0.1.5:8200"
func (c *Client) GetServiceURL(serviceName, scheme string) (string, error) {
	addresses, err := c.FindService(serviceName)
	if err != nil {
		return "", err
	}

	// Return first healthy instance
	addr := addresses[0]
	return fmt.Sprintf("%s://%s:%d", scheme, addr.Address, addr.Port), nil
}

// GetServiceEndpoint returns the address:port string for a service
//
// Example:
//
//	consulAddr, err := client.GetServiceEndpoint("consul")
//	// Returns: "10.0.1.5:8500"
func (c *Client) GetServiceEndpoint(serviceName string) (string, error) {
	addresses, err := c.FindService(serviceName)
	if err != nil {
		return "", err
	}

	addr := addresses[0]
	return fmt.Sprintf("%s:%d", addr.Address, addr.Port), nil
}

// WatchService watches a service for changes and calls the callback
//
// The callback receives the updated list of service addresses whenever
// the service configuration changes (instances added/removed, health changes).
//
// Example:
//
//	err := client.WatchService("vault", func(addresses []*ServiceAddress) {
//	    logger.Info("Vault instances changed", zap.Int("count", len(addresses)))
//	    // Update load balancer, connection pool, etc.
//	})
func (c *Client) WatchService(serviceName string, callback func([]*ServiceAddress)) error {
	c.logger.Info("Starting service watch",
		zap.String("service", serviceName))

	// Wrap the callback to convert ServiceInstance to ServiceAddress
	wrappedCallback := func(instances []*registry.ServiceInstance, err error) {
		if err != nil {
			c.logger.Warn("Service watch received error",
				zap.String("service", serviceName),
				zap.Error(err))
			return
		}

		addresses := make([]*ServiceAddress, len(instances))
		for i, instance := range instances {
			addresses[i] = &ServiceAddress{
				Address:  instance.Address,
				Port:     instance.Port,
				Tags:     instance.Tags,
				Meta:     instance.Meta,
				Health:   instance.Health,
				NodeName: instance.NodeName,
			}
		}
		callback(addresses)
	}

	return c.registry.WatchService(c.rc.Ctx, serviceName, wrappedCallback)
}

// RegisterService registers a service with Consul
//
// Example:
//
//	err := client.RegisterService(&discovery.ServiceRegistration{
//	    Name:    "myapp",
//	    Address: "10.0.1.10",
//	    Port:    8080,
//	    Tags:    []string{"v1", "production"},
//	    HealthCheck: &discovery.HealthCheck{
//	        Type:     discovery.HealthCheckHTTP,
//	        HTTP:     "http://10.0.1.10:8080/health",
//	        Interval: 10 * time.Second,
//	        Timeout:  2 * time.Second,
//	    },
//	})
func (c *Client) RegisterService(service *ServiceRegistration) error {
	c.logger.Info("Registering service",
		zap.String("name", service.Name),
		zap.String("address", service.Address),
		zap.Int("port", service.Port))

	// Convert to registry format
	regService := &registry.ServiceRegistration{
		ID:      service.ID,
		Name:    service.Name,
		Address: service.Address,
		Port:    service.Port,
		Tags:    service.Tags,
		Meta:    service.Meta,
	}

	// Convert health check if provided
	if service.HealthCheck != nil {
		regService.Check = &registry.HealthCheck{
			ID:                     service.HealthCheck.ID,
			Name:                   service.HealthCheck.Name,
			Type:                   registry.HealthCheckType(service.HealthCheck.Type),
			HTTP:                   service.HealthCheck.HTTP,
			TCP:                    service.HealthCheck.TCP,
			Interval:               service.HealthCheck.Interval,
			Timeout:                service.HealthCheck.Timeout,
			TLSSkipVerify:          service.HealthCheck.TLSSkipVerify,
			SuccessBeforePassing:   service.HealthCheck.SuccessBeforePassing,
			FailuresBeforeCritical: service.HealthCheck.FailuresBeforeCritical,
		}
	}

	if err := c.registry.RegisterService(c.rc.Ctx, regService); err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	c.logger.Info("Service registered successfully",
		zap.String("name", service.Name))

	return nil
}

// DeregisterService removes a service from Consul
func (c *Client) DeregisterService(serviceID string) error {
	c.logger.Info("Deregistering service",
		zap.String("service_id", serviceID))

	if err := c.registry.DeregisterService(c.rc.Ctx, serviceID); err != nil {
		return fmt.Errorf("failed to deregister service: %w", err)
	}

	c.logger.Info("Service deregistered successfully",
		zap.String("service_id", serviceID))

	return nil
}

// ResolveServiceDNS resolves a service via Consul DNS
//
// Consul provides DNS interface at <service>.service.consul
// This method performs standard DNS lookup via Consul DNS server.
//
// Example:
//
//	ips, err := client.ResolveServiceDNS("vault")
//	// Queries: vault.service.consul
func (c *Client) ResolveServiceDNS(serviceName string) ([]net.IP, error) {
	dnsName := fmt.Sprintf("%s.service.consul", serviceName)

	c.logger.Debug("Resolving service via DNS",
		zap.String("service", serviceName),
		zap.String("dns_name", dnsName))

	// Use custom resolver pointing to Consul
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Consul DNS runs on port 8600
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "127.0.0.1:8600")
		},
	}

	ips, err := resolver.LookupIP(c.rc.Ctx, "ip", dnsName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", dnsName, err)
	}

	c.logger.Debug("DNS resolution successful",
		zap.String("service", serviceName),
		zap.Int("ip_count", len(ips)))

	return ips, nil
}

// ResolveServiceSRV resolves service via SRV records
//
// Returns both IP addresses and port numbers from SRV records.
//
// Example:
//
//	addresses, err := client.ResolveServiceSRV("vault")
func (c *Client) ResolveServiceSRV(serviceName string) ([]*ServiceAddress, error) {
	dnsName := fmt.Sprintf("%s.service.consul", serviceName)

	c.logger.Debug("Resolving service via SRV",
		zap.String("service", serviceName),
		zap.String("dns_name", dnsName))

	// Custom resolver for Consul DNS
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "127.0.0.1:8600")
		},
	}

	// Lookup SRV records
	_, srvRecords, err := resolver.LookupSRV(c.rc.Ctx, "", "", dnsName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SRV for %s: %w", dnsName, err)
	}

	// Convert to ServiceAddress
	addresses := make([]*ServiceAddress, len(srvRecords))
	for i, srv := range srvRecords {
		// Resolve the target hostname to IP
		ips, err := resolver.LookupIP(c.rc.Ctx, "ip", srv.Target)
		if err != nil {
			c.logger.Warn("Failed to resolve SRV target",
				zap.String("target", srv.Target),
				zap.Error(err))
			continue
		}

		if len(ips) > 0 {
			addresses[i] = &ServiceAddress{
				Address: ips[0].String(),
				Port:    int(srv.Port),
			}
		}
	}

	c.logger.Debug("SRV resolution successful",
		zap.String("service", serviceName),
		zap.Int("record_count", len(addresses)))

	return addresses, nil
}

// ListAllServices lists all services registered in Consul
func (c *Client) ListAllServices() (map[string][]string, error) {
	c.logger.Debug("Listing all services")

	services, _, err := c.consul.Catalog().Services(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	c.logger.Info("Services listed",
		zap.Int("service_count", len(services)))

	return services, nil
}

// ServiceRegistration defines a service to register
type ServiceRegistration struct {
	ID          string
	Name        string
	Address     string
	Port        int
	Tags        []string
	Meta        map[string]string
	HealthCheck *HealthCheck
}

// HealthCheck defines a health check for a service
type HealthCheck struct {
	ID                     string
	Name                   string
	Type                   HealthCheckType
	HTTP                   string
	TCP                    string
	Interval               time.Duration
	Timeout                time.Duration
	TLSSkipVerify          bool
	SuccessBeforePassing   int
	FailuresBeforeCritical int
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
