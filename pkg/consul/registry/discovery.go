// pkg/consul/registry/discovery.go
//
// Service discovery implementation using Consul Health API
//
// Last Updated: 2025-10-23

package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/consul/api"
	"go.uber.org/zap"
)

// DiscoverService discovers all instances of a service
func (r *ConsulServiceRegistry) DiscoverService(ctx context.Context, serviceName string, opts *DiscoveryOptions) ([]*ServiceInstance, error) {
	r.logger.Info("ASSESS: Discovering service",
		zap.String("service_name", serviceName))

	if opts == nil {
		opts = &DiscoveryOptions{}
	}

	// INTERVENE - Query Consul for service instances
	queryOpts := &api.QueryOptions{
		Datacenter: opts.Datacenter,
		Near:       opts.Near,
		WaitIndex:  opts.WaitIndex,
		WaitTime:   opts.WaitTime,
	}

	// Use Health API for service discovery (includes health status)
	entries, meta, err := r.health.Service(serviceName, "", !opts.OnlyHealthy, queryOpts)
	if err != nil {
		r.logger.Error("INTERVENE FAILED: Service discovery failed",
			zap.String("service_name", serviceName),
			zap.Error(err))
		return nil, fmt.Errorf("failed to discover service %s: %w", serviceName, err)
	}

	r.logger.Debug("Service discovery query completed",
		zap.String("service_name", serviceName),
		zap.Int("instance_count", len(entries)),
		zap.Uint64("last_index", meta.LastIndex))

	// EVALUATE - Convert to our ServiceInstance format
	instances := make([]*ServiceInstance, 0, len(entries))
	for _, entry := range entries {
		// Check tag filter
		if len(opts.Tags) > 0 && !hasAllTags(entry.Service.Tags, opts.Tags) {
			continue
		}

		instance := convertServiceEntry(entry)
		instances = append(instances, instance)
	}

	r.logger.Info("EVALUATE SUCCESS: Service discovery completed",
		zap.String("service_name", serviceName),
		zap.Int("total_instances", len(entries)),
		zap.Int("filtered_instances", len(instances)))

	return instances, nil
}

// DiscoverHealthyServices discovers only healthy instances of a service
func (r *ConsulServiceRegistry) DiscoverHealthyServices(ctx context.Context, serviceName string) ([]*ServiceInstance, error) {
	return r.DiscoverService(ctx, serviceName, &DiscoveryOptions{
		OnlyHealthy: true,
	})
}

// WatchService watches for changes to a service
func (r *ConsulServiceRegistry) WatchService(ctx context.Context, serviceName string, callback ServiceWatchCallback) error {
	r.logger.Info("Starting service watch",
		zap.String("service_name", serviceName))

	go func() {
		var waitIndex uint64
		for {
			select {
			case <-ctx.Done():
				r.logger.Info("Service watch cancelled",
					zap.String("service_name", serviceName))
				return
			default:
				// Use blocking query with wait index
				opts := &DiscoveryOptions{
					WaitIndex: waitIndex,
					WaitTime:  5 * time.Minute,
				}

				instances, err := r.DiscoverService(ctx, serviceName, opts)

				// Update wait index for next iteration
				if err == nil && len(instances) > 0 {
					// Consul returns the new index in the response
					// For simplicity, we'll just increment
					waitIndex++
				}

				// Call callback
				callback(instances, err)

				// If error, back off before retry
				if err != nil {
					time.Sleep(10 * time.Second)
				}
			}
		}
	}()

	return nil
}

// ListServices lists all services matching the filter
func (r *ConsulServiceRegistry) ListServices(ctx context.Context, filter *ServiceFilter) ([]*ServiceInstance, error) {
	r.logger.Info("ASSESS: Listing services",
		zap.Any("filter", filter))

	if filter == nil {
		filter = &ServiceFilter{}
	}

	// INTERVENE - Get all services
	queryOpts := &api.QueryOptions{
		Datacenter: filter.Datacenter,
	}

	services, _, err := r.client.Catalog().Services(queryOpts)
	if err != nil {
		r.logger.Error("INTERVENE FAILED: Failed to list services",
			zap.Error(err))
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	// EVALUATE - Discover and filter each service
	var allInstances []*ServiceInstance

	for serviceName, tags := range services {
		// Apply name filter
		if filter.Name != "" && serviceName != filter.Name {
			continue
		}

		// Apply tag filter
		if len(filter.Tags) > 0 && !hasAllTags(tags, filter.Tags) {
			continue
		}

		// Discover instances of this service
		instances, err := r.DiscoverService(ctx, serviceName, &DiscoveryOptions{
			Datacenter: filter.Datacenter,
		})
		if err != nil {
			r.logger.Warn("Failed to discover service instances",
				zap.String("service_name", serviceName),
				zap.Error(err))
			continue
		}

		// Apply health filter
		for _, instance := range instances {
			if filter.Health != "" && instance.Health != filter.Health {
				continue
			}

			// Apply metadata filter
			if !hasAllMetadata(instance.Meta, filter.Meta) {
				continue
			}

			allInstances = append(allInstances, instance)
		}
	}

	r.logger.Info("EVALUATE SUCCESS: Services listed",
		zap.Int("service_count", len(services)),
		zap.Int("instance_count", len(allInstances)))

	return allInstances, nil
}

// QueryServicesByTag queries services that have a specific tag
func (r *ConsulServiceRegistry) QueryServicesByTag(ctx context.Context, tag string) ([]*ServiceInstance, error) {
	return r.ListServices(ctx, &ServiceFilter{
		Tags: []string{tag},
	})
}

// GetServiceMetadata retrieves metadata for a specific service
func (r *ConsulServiceRegistry) GetServiceMetadata(ctx context.Context, serviceID string) (map[string]string, error) {
	services, err := r.agent.Services()
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %w", err)
	}

	service, exists := services[serviceID]
	if !exists {
		return nil, fmt.Errorf("service %s not found", serviceID)
	}

	return service.Meta, nil
}

// UpdateServiceMetadata updates metadata for a specific service
func (r *ConsulServiceRegistry) UpdateServiceMetadata(ctx context.Context, serviceID string, metadata map[string]string) error {
	// Get current service
	services, err := r.agent.Services()
	if err != nil {
		return fmt.Errorf("failed to get services: %w", err)
	}

	currentService, exists := services[serviceID]
	if !exists {
		return fmt.Errorf("service %s not found", serviceID)
	}

	// Create updated registration
	updated := &ServiceRegistration{
		ID:      currentService.ID,
		Name:    currentService.Service,
		Address: currentService.Address,
		Port:    currentService.Port,
		Tags:    currentService.Tags,
		Meta:    metadata, // Updated metadata
	}

	// Re-register service with updated metadata
	return r.UpdateService(ctx, serviceID, updated)
}

// Helper functions

func convertServiceEntry(entry *api.ServiceEntry) *ServiceInstance {
	instance := &ServiceInstance{
		ID:       entry.Service.ID,
		Name:     entry.Service.Service,
		Address:  entry.Service.Address,
		Port:     entry.Service.Port,
		Tags:     entry.Service.Tags,
		Meta:     entry.Service.Meta,
		NodeName: entry.Node.Node,
		Health:   aggregateHealth(entry.Checks),
		Checks:   make([]*HealthCheckResult, len(entry.Checks)),
	}

	// Convert health checks
	for i, check := range entry.Checks {
		instance.Checks[i] = &HealthCheckResult{
			CheckID: check.CheckID,
			Name:    check.Name,
			Status:  HealthStatus(check.Status),
			Output:  check.Output,
			Node:    check.Node,
		}
	}

	// Add weights if present
	if entry.Service.Weights.Passing > 0 || entry.Service.Weights.Warning > 0 {
		instance.Weights = &ServiceWeights{
			Passing: entry.Service.Weights.Passing,
			Warning: entry.Service.Weights.Warning,
		}
	}

	return instance
}

func aggregateHealth(checks api.HealthChecks) HealthStatus {
	// Aggregate health status using Consul's logic:
	// - If any check is critical, overall is critical
	// - If any check is warning, overall is warning
	// - If all checks are passing, overall is passing

	hasCritical := false
	hasWarning := false

	for _, check := range checks {
		switch check.Status {
		case "critical":
			hasCritical = true
		case "warning":
			hasWarning = true
		}
	}

	if hasCritical {
		return HealthCritical
	}
	if hasWarning {
		return HealthWarning
	}
	if len(checks) > 0 {
		return HealthPassing
	}
	return HealthUnknown
}

func hasAllTags(available, required []string) bool {
	tagMap := make(map[string]bool)
	for _, tag := range available {
		tagMap[tag] = true
	}

	for _, req := range required {
		if !tagMap[req] {
			return false
		}
	}
	return true
}

func hasAllMetadata(available, required map[string]string) bool {
	if len(required) == 0 {
		return true // No requirements
	}

	for key, value := range required {
		if available[key] != value {
			return false
		}
	}
	return true
}
