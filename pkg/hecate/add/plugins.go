// pkg/hecate/add/plugins.go - Service-specific integration plugin system

package add

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// IntegrationResources tracks resources created during service integration
// Used for rollback on failure
type IntegrationResources struct {
	ProxyProviderPK int      // Authentik proxy provider PK (for cleanup)
	ApplicationPK   string   // Authentik application PK (for cleanup)
	ApplicationSlug string   // Authentik application slug (for cleanup)
	UserPK          string   // Created user PK (for cleanup)
	GroupPKs        []string // Created group PKs (for cleanup)
	PolicyPK        string   // Created policy PK
	PolicyBindingPK string   // Created policy binding PK
}

// ServiceIntegrator defines the interface for service-specific integrations
// Services can implement this interface to provide custom validation,
// authentication setup, and health checks
type ServiceIntegrator interface {
	// IsConfigured checks if the service integration is already configured
	// Returns true if SSO/auth is already set up for this specific DNS, false otherwise
	// Used for idempotency - avoids re-configuring already-configured services
	// P1 #4: Plugin-based idempotency check instead of hardcoded service checks
	IsConfigured(rc *eos_io.RuntimeContext, opts *ServiceOptions) (bool, error)

	// ValidateService checks if the backend service is running correctly
	// This is called before adding the route to verify the upstream is healthy
	ValidateService(rc *eos_io.RuntimeContext, opts *ServiceOptions) error

	// ConfigureAuthentication sets up OAuth2/SSO if needed
	// For BionicGPT, this configures Authentik Proxy Provider and application
	ConfigureAuthentication(rc *eos_io.RuntimeContext, opts *ServiceOptions) error

	// HealthCheck verifies service-specific health endpoints
	// Called after route is added to verify end-to-end functionality
	HealthCheck(rc *eos_io.RuntimeContext, opts *ServiceOptions) error

	// Rollback cleans up resources created during integration
	// Called when integration fails to restore system to previous state
	Rollback(rc *eos_io.RuntimeContext) error
}

// IntegratorConstructor is a function that creates a new integrator instance
// This pattern ensures each invocation gets a fresh instance with isolated state
type IntegratorConstructor func() ServiceIntegrator

// serviceIntegratorConstructors is the global registry of service integrator constructors
// Services register constructors in their init() functions
// RATIONALE: Constructor pattern prevents resource leaks from shared state
// SECURITY: Each invocation gets isolated resources for proper rollback
var serviceIntegratorConstructors = map[string]IntegratorConstructor{}

// RegisterServiceIntegrator registers a service-specific integrator constructor
// This should be called from the init() function of service plugin files
// CRITICAL: Pass a constructor function, NOT a concrete instance
// Example: RegisterServiceIntegrator("wazuh", func() ServiceIntegrator { return &WazuhIntegrator{...} })
func RegisterServiceIntegrator(serviceName string, constructor IntegratorConstructor) {
	serviceIntegratorConstructors[serviceName] = constructor
}

// GetServiceIntegrator retrieves a NEW integrator instance for the service
// Returns a fresh integrator instance and true if found, nil and false if not registered
// IMPORTANT: Each call creates a new instance to prevent state sharing between invocations
func GetServiceIntegrator(serviceName string) (ServiceIntegrator, bool) {
	constructor, exists := serviceIntegratorConstructors[serviceName]
	if !exists {
		return nil, false
	}
	return constructor(), true // Call constructor to create fresh instance
}

// HasServiceIntegrator checks if a service has a registered integrator
func HasServiceIntegrator(serviceName string) bool {
	_, exists := serviceIntegratorConstructors[serviceName]
	return exists
}
