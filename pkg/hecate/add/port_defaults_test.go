// pkg/hecate/add/port_defaults_test.go

package add

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

func TestEnsureBackendHasPort(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		backend  string
		expected string
	}{
		// IPv4 tests
		{
			name:     "IPv4 without port - bionicgpt",
			service:  "bionicgpt",
			backend:  "100.71.196.79",
			expected: "100.71.196.79:8513",
		},
		{
			name:     "IPv4 with port - bionicgpt (user override)",
			service:  "bionicgpt",
			backend:  "100.71.196.79:7703",
			expected: "100.71.196.79:7703",
		},
		{
			name:     "IPv4 without port - unknown service",
			service:  "custom",
			backend:  "192.168.1.1",
			expected: "192.168.1.1", // No change for unknown services
		},

		// IPv6 tests
		{
			name:     "IPv6 loopback without port",
			service:  "bionicgpt",
			backend:  "::1",
			expected: "[::1]:8513",
		},
		{
			name:     "IPv6 loopback with port (brackets)",
			service:  "bionicgpt",
			backend:  "[::1]:7703",
			expected: "[::1]:7703",
		},
		{
			name:     "IPv6 full address without port",
			service:  "bionicgpt",
			backend:  "2001:db8::1",
			expected: "[2001:db8::1]:8513",
		},
		{
			name:     "IPv6 full address with port (brackets)",
			service:  "bionicgpt",
			backend:  "[2001:db8::1]:7703",
			expected: "[2001:db8::1]:7703",
		},
		{
			name:     "IPv6 link-local without port",
			service:  "openwebui",
			backend:  "fe80::1",
			expected: "[fe80::1]:8501",
		},

		// Hostname tests
		{
			name:     "Hostname without port",
			service:  "authentik",
			backend:  "auth.example.com",
			expected: "auth.example.com:9000",
		},
		{
			name:     "Hostname with port (user override)",
			service:  "authentik",
			backend:  "auth.example.com:443",
			expected: "auth.example.com:443",
		},
		{
			name:     "Localhost without port",
			service:  "bionicgpt",
			backend:  "localhost",
			expected: "localhost:8513",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EnsureBackendHasPort(tt.service, tt.backend)
			if result != tt.expected {
				t.Errorf("EnsureBackendHasPort(%q, %q) = %q, want %q",
					tt.service, tt.backend, result, tt.expected)
			}
		})
	}
}

func TestServiceDefaultPorts(t *testing.T) {
	// Verify that serviceDefaultPorts map matches shared constants
	tests := []struct {
		service      string
		expectedPort int
	}{
		{"bionicgpt", shared.PortBionicGPT},
		{"openwebui", shared.PortOpenWebUI},
		{"authentik", shared.PortAuthentik},
	}

	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			port, exists := serviceDefaultPorts[tt.service]
			if !exists {
				t.Errorf("Service %q not found in serviceDefaultPorts", tt.service)
			}
			if port != tt.expectedPort {
				t.Errorf("serviceDefaultPorts[%q] = %d, want %d",
					tt.service, port, tt.expectedPort)
			}
		})
	}
}
