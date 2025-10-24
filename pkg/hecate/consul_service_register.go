// pkg/hecate/consul_service_register.go
//
// Consul service registration for Hecate reverse proxy framework.
//
// This package handles automatic registration of Hecate services (Caddy, Authentik, etc.)
// with Consul for seamless service discovery.
//
// Last Updated: 2025-01-24

package hecate

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/agent"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RegisterHecateServices registers all Hecate services with Consul.
//
// This function:
//  1. Defines service registrations for Hecate components
//  2. Registers each service with Consul agent
//  3. Sets up health checks
//  4. Adds service metadata
//
// Services registered:
//   - Caddy (reverse proxy) on port 80/443
//   - Authentik (SSO) on port 9000
//   - Redis (Authentik backend) on port 6379
//   - PostgreSQL (Authentik database) on port 5432
//
// All failures are non-fatal warnings. Hecate functions normally even if
// Consul registration fails.
//
// Parameters:
//   - rc: RuntimeContext for logging
//   - hecateDir: Path to Hecate installation (default: /opt/hecate)
//
// Returns:
//   - error: Always nil (failures are logged as warnings)
//
// Example:
//
//	err := RegisterHecateServices(rc, "/opt/hecate")
//	// Services registered with Consul for service discovery
func RegisterHecateServices(rc *eos_io.RuntimeContext, hecateDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Registering Hecate services with Consul",
		zap.String("hecate_dir", hecateDir))

	// ASSESS - Define Hecate service registrations
	services := []agent.ServiceDefinition{
		{
			ID:      "hecate-caddy",
			Name:    "caddy",
			Port:    80,
			Address: "localhost",
			Tags:    []string{"reverse-proxy", "hecate", "http"},
			Meta: map[string]string{
				"framework": "hecate",
				"version":   "latest",
				"role":      "reverse-proxy",
			},
			Checks: []agent.HealthCheck{
				{
					ID:       "caddy-health",
					Name:     "Caddy HTTP Health",
					Type:     "http",
					Endpoint: "http://localhost:80/health",
					Interval: "10s",
					Timeout:  "2s",
				},
			},
		},
		{
			ID:      "hecate-caddy-https",
			Name:    "caddy-https",
			Port:    443,
			Address: "localhost",
			Tags:    []string{"reverse-proxy", "hecate", "https", "tls"},
			Meta: map[string]string{
				"framework": "hecate",
				"version":   "latest",
				"role":      "reverse-proxy",
				"protocol":  "https",
			},
			Checks: []agent.HealthCheck{
				{
					ID:       "caddy-https-health",
					Name:     "Caddy HTTPS Health",
					Type:     "tcp",
					Endpoint: "localhost:443",
					Interval: "10s",
					Timeout:  "2s",
				},
			},
		},
		{
			ID:      "hecate-authentik",
			Name:    "authentik",
			Port:    9000,
			Address: "localhost",
			Tags:    []string{"sso", "hecate", "authentication", "oidc"},
			Meta: map[string]string{
				"framework": "hecate",
				"version":   "latest",
				"role":      "sso-provider",
				"protocol":  "oidc",
			},
			Checks: []agent.HealthCheck{
				{
					ID:       "authentik-health",
					Name:     "Authentik Health",
					Type:     "http",
					Endpoint: "http://localhost:9000/-/health/ready/",
					Interval: "10s",
					Timeout:  "5s",
				},
			},
		},
		{
			ID:      "hecate-redis",
			Name:    "redis",
			Port:    6379,
			Address: "localhost",
			Tags:    []string{"cache", "hecate", "authentik-backend"},
			Meta: map[string]string{
				"framework": "hecate",
				"version":   "latest",
				"role":      "cache",
				"backend":   "authentik",
			},
			Checks: []agent.HealthCheck{
				{
					ID:       "redis-health",
					Name:     "Redis TCP Health",
					Type:     "tcp",
					Endpoint: "localhost:6379",
					Interval: "10s",
					Timeout:  "2s",
				},
			},
		},
		{
			ID:      "hecate-postgresql",
			Name:    "postgresql",
			Port:    5432,
			Address: "localhost",
			Tags:    []string{"database", "hecate", "authentik-backend"},
			Meta: map[string]string{
				"framework": "hecate",
				"version":   "latest",
				"role":      "database",
				"backend":   "authentik",
			},
			Checks: []agent.HealthCheck{
				{
					ID:       "postgresql-health",
					Name:     "PostgreSQL TCP Health",
					Type:     "tcp",
					Endpoint: "localhost:5432",
					Interval: "10s",
					Timeout:  "2s",
				},
			},
		},
	}

	// INTERVENE - Register with Consul
	consulAddr := "http://localhost:8500"
	if err := agent.RegisterServices(rc, consulAddr, services); err != nil {
		logger.Warn("Failed to register Hecate services with Consul (non-fatal)",
			zap.Error(err),
			zap.String("impact", "Services will not appear in Consul catalog"),
			zap.String("remediation", "Hecate will function normally - service discovery unavailable"))
		return nil // Non-fatal
	}

	// EVALUATE - Log success
	logger.Info("Hecate services registered with Consul successfully",
		zap.Int("service_count", len(services)),
		zap.String("consul_addr", consulAddr),
		zap.String("service_discovery", "enabled"))

	return nil
}

// DeregisterHecateServices removes Hecate service registrations from Consul.
//
// This should be called when Hecate is being uninstalled or stopped.
//
// Parameters:
//   - rc: RuntimeContext
//   - hecateDir: Path to Hecate installation
//
// Returns:
//   - error: Always nil (failures are logged as warnings)
func DeregisterHecateServices(rc *eos_io.RuntimeContext, hecateDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deregistering Hecate services from Consul",
		zap.String("hecate_dir", hecateDir))

	serviceIDs := []string{
		"hecate-caddy",
		"hecate-caddy-https",
		"hecate-authentik",
		"hecate-redis",
		"hecate-postgresql",
	}

	consulAddr := "http://localhost:8500"

	failureCount := 0
	for _, serviceID := range serviceIDs {
		if err := agent.DeregisterService(rc, consulAddr, serviceID); err != nil {
			logger.Warn("Failed to deregister service (non-fatal)",
				zap.String("service_id", serviceID),
				zap.Error(err))
			failureCount++
		}
	}

	if failureCount > 0 {
		logger.Warn("Some Hecate services failed to deregister",
			zap.Int("failed_count", failureCount),
			zap.Int("total_count", len(serviceIDs)))
	} else {
		logger.Info("All Hecate services deregistered successfully",
			zap.Int("service_count", len(serviceIDs)))
	}

	return nil
}

// GenerateHecateConsulServiceDefinitions returns service definitions for Hecate.
//
// This is a helper function for testing and manual registration.
//
// Returns:
//   - []agent.ServiceDefinition: List of Hecate service definitions
func GenerateHecateConsulServiceDefinitions() []agent.ServiceDefinition {
	return []agent.ServiceDefinition{
		{
			ID:      "hecate-caddy",
			Name:    "caddy",
			Port:    80,
			Address: "localhost",
			Tags:    []string{"reverse-proxy", "hecate", "http"},
			Meta: map[string]string{
				"framework": "hecate",
				"role":      "reverse-proxy",
			},
		},
		{
			ID:      "hecate-authentik",
			Name:    "authentik",
			Port:    9000,
			Address: "localhost",
			Tags:    []string{"sso", "hecate", "authentication"},
			Meta: map[string]string{
				"framework": "hecate",
				"role":      "sso-provider",
			},
		},
	}
}
