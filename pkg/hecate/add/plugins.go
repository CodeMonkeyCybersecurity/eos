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
}

// ServiceIntegrator defines the interface for service-specific integrations
// Services can implement this interface to provide custom validation,
// authentication setup, and health checks
type ServiceIntegrator interface {
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

// serviceIntegrators is the global registry of service-specific integrators
// Services register themselves in their init() functions
var serviceIntegrators = map[string]ServiceIntegrator{}

// RegisterServiceIntegrator registers a service-specific integrator
// This should be called from the init() function of service plugin files
func RegisterServiceIntegrator(serviceName string, integrator ServiceIntegrator) {
	serviceIntegrators[serviceName] = integrator
}

// GetServiceIntegrator retrieves a registered service integrator
// Returns the integrator and true if found, nil and false if not registered
func GetServiceIntegrator(serviceName string) (ServiceIntegrator, bool) {
	integrator, exists := serviceIntegrators[serviceName]
	return integrator, exists
}

// HasServiceIntegrator checks if a service has a registered integrator
func HasServiceIntegrator(serviceName string) bool {
	_, exists := serviceIntegrators[serviceName]
	return exists
}
