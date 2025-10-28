// pkg/hecate/add/port_defaults.go

package add

import (
	"fmt"
	"net"
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
// Correctly handles IPv4, IPv6, and hostnames
//
// Examples:
//
//	EnsureBackendHasPort("bionicgpt", "100.71.196.79")      → "100.71.196.79:8513"
//	EnsureBackendHasPort("bionicgpt", "100.71.196.79:7703") → "100.71.196.79:7703" (user override)
//	EnsureBackendHasPort("bionicgpt", "::1")                → "[::1]:8513" (IPv6)
//	EnsureBackendHasPort("bionicgpt", "[::1]:7703")         → "[::1]:7703" (IPv6 with port)
//	EnsureBackendHasPort("bionicgpt", "2001:db8::1")        → "[2001:db8::1]:8513" (IPv6)
//	EnsureBackendHasPort("custom", "192.168.1.1")           → "192.168.1.1" (unknown service, no change)
func EnsureBackendHasPort(service, backend string) string {
	// Try to split host:port using net.SplitHostPort
	// This correctly handles IPv6 brackets: [::1]:8080
	_, _, err := net.SplitHostPort(backend)
	if err == nil {
		// Already has port - user explicitly specified it
		return backend
	}

	// No port present - check if we should add default
	defaultPort, hasDefault := serviceDefaultPorts[service]
	if !hasDefault {
		// Unknown service - return as-is (validation will catch missing port)
		return backend
	}

	// Check if backend is IPv6 address (contains colons but no port)
	// IPv6 format: 2001:db8::1 or ::1
	if strings.Contains(backend, ":") {
		// This is IPv6 without port - add brackets and port
		return fmt.Sprintf("[%s]:%d", backend, defaultPort)
	}

	// IPv4 or hostname without port - add port directly
	return fmt.Sprintf("%s:%d", backend, defaultPort)
}
