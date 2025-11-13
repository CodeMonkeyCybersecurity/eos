// pkg/consul/discovery/helpers.go
//
// Service Discovery Helpers
//
// Convenience functions for common service discovery patterns in EOS.
//
// *Last Updated: 2025-01-24*

package discovery

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetVaultAddress discovers the Vault service and returns its HTTPS URL
//
// Example:
//
//	vaultAddr, err := discovery.GetVaultAddress(rc, consulClient)
//	// Returns: "https://10.0.1.5:8200"
func GetVaultAddress(rc *eos_io.RuntimeContext, consulClient *consulapi.Client) (string, error) {
	client, err := NewClient(rc, consulClient)
	if err != nil {
		return "", err
	}

	return client.GetServiceURL("vault", "https")
}

// GetConsulAddress discovers the Consul service and returns its HTTP URL
//
// Example:
//
//	consulAddr, err := discovery.GetConsulAddress(rc, consulClient)
//	// Returns: "http://10.0.1.5:8500"
func GetConsulAddress(rc *eos_io.RuntimeContext, consulClient *consulapi.Client) (string, error) {
	client, err := NewClient(rc, consulClient)
	if err != nil {
		return "", err
	}

	return client.GetServiceURL("consul", "http")
}

// GetNomadAddress discovers the Nomad service and returns its HTTP URL
func GetNomadAddress(rc *eos_io.RuntimeContext, consulClient *consulapi.Client) (string, error) {
	client, err := NewClient(rc, consulClient)
	if err != nil {
		return "", err
	}

	return client.GetServiceURL("nomad", "http")
}

// GetPostgresAddress discovers PostgreSQL and returns connection string components
//
// Returns: host, port, error
//
// Example:
//
//	host, port, err := discovery.GetPostgresAddress(rc, consulClient)
//	connStr := fmt.Sprintf("postgres://user:pass@%s:%d/dbname", host, port)
func GetPostgresAddress(rc *eos_io.RuntimeContext, consulClient *consulapi.Client) (string, int, error) {
	client, err := NewClient(rc, consulClient)
	if err != nil {
		return "", 0, err
	}

	addresses, err := client.FindService("postgres")
	if err != nil {
		return "", 0, err
	}

	addr := addresses[0]
	return addr.Address, addr.Port, nil
}

// GetServicesByTag finds all services with a specific tag
//
// Example:
//
//	// Find all services tagged "production"
//	services, err := discovery.GetServicesByTag(rc, consulClient, "production")
func GetServicesByTag(rc *eos_io.RuntimeContext, consulClient *consulapi.Client, tag string) (map[string][]*ServiceAddress, error) {
	client, err := NewClient(rc, consulClient)
	if err != nil {
		return nil, err
	}

	// Get all services
	allServices, err := client.ListAllServices()
	if err != nil {
		return nil, err
	}

	// Filter services with the tag
	result := make(map[string][]*ServiceAddress)
	for serviceName, tags := range allServices {
		if containsTag(tags, tag) {
			addresses, err := client.FindService(serviceName)
			if err != nil {
				continue // Skip services that can't be discovered
			}
			result[serviceName] = addresses
		}
	}

	return result, nil
}

// BuildConnectionString builds a database connection string for discovered services
//
// Example:
//
//	connStr, err := discovery.BuildConnectionString(rc, consulClient,
//	    "postgres", "myuser", "mypass", "mydb")
//	// Returns: "postgres://myuser:mypass@10.0.1.5:5432/mydb"
func BuildConnectionString(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	serviceName, username, password, database string) (string, error) {

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return "", err
	}

	addresses, err := client.FindService(serviceName)
	if err != nil {
		return "", err
	}

	addr := addresses[0]

	// Build connection string based on service type
	switch {
	case strings.Contains(serviceName, "postgres"):
		return fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
			username, password, addr.Address, addr.Port, database), nil
	case strings.Contains(serviceName, "mysql"):
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			username, password, addr.Address, addr.Port, database), nil
	case strings.Contains(serviceName, "redis"):
		if password != "" {
			return fmt.Sprintf("redis://:%s@%s:%d",
				password, addr.Address, addr.Port), nil
		}
		return fmt.Sprintf("redis://%s:%d", addr.Address, addr.Port), nil
	default:
		return fmt.Sprintf("%s:%d", addr.Address, addr.Port), nil
	}
}

// WaitForService waits for a service to become available
//
// Polls until the service is discovered or timeout is reached.
//
// Example:
//
//	err := discovery.WaitForService(rc, consulClient, "vault", 30*time.Second)
func WaitForService(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	serviceName string, timeout time.Duration) error {

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return err
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Waiting for service to become available",
		zap.String("service", serviceName),
		zap.Duration("timeout", timeout))

	start := time.Now()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rc.Ctx.Done():
			return fmt.Errorf("context canceled while waiting for service %s", serviceName)

		case <-ticker.C:
			if time.Since(start) > timeout {
				return fmt.Errorf("timeout waiting for service %s after %v", serviceName, timeout)
			}

			_, err := client.FindService(serviceName)
			if err == nil {
				logger.Info("Service became available",
					zap.String("service", serviceName),
					zap.Duration("elapsed", time.Since(start)))
				return nil
			}

			logger.Debug("Service not yet available, retrying",
				zap.String("service", serviceName),
				zap.Error(err))
		}
	}
}

// GetServiceMetadata retrieves metadata for a service instance
//
// Example:
//
//	meta, err := discovery.GetServiceMetadata(rc, consulClient, "vault")
//	version := meta["version"]
func GetServiceMetadata(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	serviceName string) (map[string]string, error) {

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return nil, err
	}

	addresses, err := client.FindService(serviceName)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no instances of service %s found", serviceName)
	}

	return addresses[0].Meta, nil
}

// LoadBalanceServices returns a load-balanced service address
//
// Uses round-robin selection across healthy instances.
//
// Example:
//
//	addr, err := discovery.LoadBalanceServices(rc, consulClient, "api")
func LoadBalanceServices(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	serviceName string) (*ServiceAddress, error) {

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return nil, err
	}

	addresses, err := client.FindService(serviceName)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no healthy instances of service %s found", serviceName)
	}

	// Simple round-robin: use current time to select instance
	idx := int(time.Now().UnixNano()) % len(addresses)
	return addresses[idx], nil
}

// GetPrimaryInstance returns the primary instance of a service
//
// Looks for a service tagged with "primary" or returns the first instance.
//
// Example:
//
//	primary, err := discovery.GetPrimaryInstance(rc, consulClient, "postgres")
func GetPrimaryInstance(rc *eos_io.RuntimeContext, consulClient *consulapi.Client,
	serviceName string) (*ServiceAddress, error) {

	client, err := NewClient(rc, consulClient)
	if err != nil {
		return nil, err
	}

	// Try to find primary-tagged instance
	primaryAddresses, err := client.FindServiceWithTag(serviceName, "primary")
	if err == nil && len(primaryAddresses) > 0 {
		return primaryAddresses[0], nil
	}

	// Fallback to first available instance
	addresses, err := client.FindService(serviceName)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no instances of service %s found", serviceName)
	}

	return addresses[0], nil
}

// containsTag checks if a tag is in the list
func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
