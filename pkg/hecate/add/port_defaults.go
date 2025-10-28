// pkg/hecate/add/port_defaults.go

package add

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// serviceDefaultPorts maps service names to their default ports
// RATIONALE: User experience - allow specifying IP without port for known services
// SECURITY: Port numbers come from centralized pkg/shared/ports.go constants
var serviceDefaultPorts = map[string]int{
	"bionicgpt": shared.PortBionicGPT, // 8513 - BionicGPT multi-tenant LLM platform
	"openwebui": shared.PortOpenWebUI, // 8501 - Open WebUI
	"authentik": shared.PortAuthentik, // 9000 - Authentik identity provider
	// Add more services as needed - refer to pkg/shared/ports.go for port constants
}

// EnsureBackendHasPort appends the default port for known services if port is missing
// This improves UX by allowing users to specify just IP/hostname for known services
//
// Examples:
//
//	EnsureBackendHasPort("bionicgpt", "100.71.196.79")      → "100.71.196.79:8513"
//	EnsureBackendHasPort("bionicgpt", "100.71.196.79:7703") → "100.71.196.79:7703" (user override)
//	EnsureBackendHasPort("custom", "192.168.1.1")           → "192.168.1.1" (unknown service, no change)
func EnsureBackendHasPort(service, backend string) string {
	// Check if backend already has port (contains colon)
	if strings.Contains(backend, ":") {
		return backend // User explicitly specified port - respect it
	}

	// Check if service has a known default port
	if defaultPort, exists := serviceDefaultPorts[service]; exists {
		return fmt.Sprintf("%s:%d", backend, defaultPort)
	}

	// Unknown service - return as-is (validation will require explicit port)
	return backend
}
