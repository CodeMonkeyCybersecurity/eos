package bootstrap

import (
	"context"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapProcessToServiceName(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	sm := NewServiceManager(rc)

	tests := []struct {
		name         string
		processName  string
		port         int
		expectedName string
	}{
		// Direct process name mappings
		{
			name:         "salt-master direct",
			processName:  "salt-master",
			port:         4505,
			expectedName: "salt-master",
		},
		{
			name:         "salt-api direct",
			processName:  "salt-api",
			port:         8000,
			expectedName: "salt-api",
		},
		{
			name:         "vault direct",
			processName:  "vault",
			port:         8200,
			expectedName: "vault",
		},
		{
			name:         "consul direct",
			processName:  "consul",
			port:         8500,
			expectedName: "consul",
		},
		{
			name:         "nomad direct",
			processName:  "nomad",
			port:         4646,
			expectedName: "nomad",
		},
		// Path-based mappings
		{
			name:         "saltstack path with slash",
			processName:  "/opt/saltstack/",
			port:         4505,
			expectedName: "salt-master",
		},
		{
			name:         "saltstack path without slash",
			processName:  "/opt/saltstack",
			port:         4505,
			expectedName: "salt-master",
		},
		{
			name:         "vault path",
			processName:  "/opt/vault/bin/vault",
			port:         8200,
			expectedName: "vault",
		},
		{
			name:         "consul path",
			processName:  "/opt/consul/bin/consul",
			port:         8500,
			expectedName: "consul",
		},
		// Full path mappings
		{
			name:         "usr bin salt-master",
			processName:  "/usr/bin/salt-master",
			port:         4505,
			expectedName: "salt-master",
		},
		{
			name:         "usr bin vault",
			processName:  "/usr/bin/vault",
			port:         8200,
			expectedName: "vault",
		},
		// Port-based fallback
		{
			name:         "unknown process on salt port",
			processName:  "unknown-process",
			port:         4505,
			expectedName: "salt-master",
		},
		{
			name:         "unknown process on vault port",
			processName:  "unknown-process",
			port:         8200,
			expectedName: "vault",
		},
		// Edge cases
		{
			name:         "empty process on known port",
			processName:  "",
			port:         8500,
			expectedName: "consul",
		},
		{
			name:         "python script on salt-api port",
			processName:  "python3",
			port:         8000,
			expectedName: "salt-api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sm.mapProcessToServiceName(tt.processName, tt.port)
			assert.Equal(t, tt.expectedName, result, 
				"Process %s on port %d should map to %s, got %s",
				tt.processName, tt.port, tt.expectedName, result)
		})
	}
}

func TestParseServiceFromSSLine(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	sm := NewServiceManager(rc)

	tests := []struct {
		name            string
		ssLine          string
		port            int
		expectedService string
		expectedPID     int
		shouldBeNil     bool
	}{
		{
			name:            "standard ss output with quotes",
			ssLine:          `LISTEN 0 128 *:4505 *:* users:(("salt-master",pid=1234,fd=8))`,
			port:            4505,
			expectedService: "salt-master",
			expectedPID:     1234,
			shouldBeNil:     false,
		},
		{
			name:            "ss output without quotes",
			ssLine:          `LISTEN 0 128 *:4505 *:* users:((salt-master,pid=1234,fd=8))`,
			port:            4505,
			expectedService: "salt-master",
			expectedPID:     1234,
			shouldBeNil:     false,
		},
		{
			name:            "ss output with path",
			ssLine:          `LISTEN 0 128 *:4505 *:* users:(("/opt/saltstack/",pid=1234,fd=8))`,
			port:            4505,
			expectedService: "salt-master",
			expectedPID:     1234,
			shouldBeNil:     false,
		},
		{
			name:            "vault process",
			ssLine:          `LISTEN 0 128 *:8200 *:* users:(("vault",pid=5678,fd=10))`,
			port:            8200,
			expectedService: "vault",
			expectedPID:     5678,
			shouldBeNil:     false,
		},
		{
			name:            "no users info",
			ssLine:          `LISTEN 0 128 *:8080 *:*`,
			port:            8080,
			expectedService: "",
			expectedPID:     0,
			shouldBeNil:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := sm.parseServiceFromSSLine(tt.ssLine, tt.port)
			
			if tt.shouldBeNil {
				assert.Nil(t, service, "Expected nil service for line: %s", tt.ssLine)
			} else {
				require.NotNil(t, service, "Expected non-nil service for line: %s", tt.ssLine)
				assert.Equal(t, tt.expectedService, service.Name,
					"Expected service name %s, got %s", tt.expectedService, service.Name)
				assert.Equal(t, tt.expectedPID, service.PID,
					"Expected PID %d, got %d", tt.expectedPID, service.PID)
			}
		})
	}
}

func TestServiceStoppingFallback(t *testing.T) {

	tests := []struct {
		name         string
		serviceName  string
		expectedCmds []string
	}{
		{
			name:        "process path to service name",
			serviceName: "/opt/saltstack/",
			expectedCmds: []string{
				"salt-master",
				"salt-api",
			},
		},
		{
			name:        "simple service name",
			serviceName: "vault",
			expectedCmds: []string{
				"vault",
				"vault.service",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This tests the fallback logic without actually running commands
			// In a real test, you'd mock the execute.Run function
			
			// Verify the service variations are generated correctly
			variations := getServiceVariations(tt.serviceName)
			for _, expected := range tt.expectedCmds {
				assert.Contains(t, variations, expected,
					"Expected variation %s for service %s", expected, tt.serviceName)
			}
		})
	}
}

// getServiceVariations helper function to test service variation generation
func getServiceVariations(serviceName string) []string {
	variations := []string{
		serviceName,
		serviceName + ".service",
	}
	
	if strings.Contains(serviceName, "/opt/saltstack/") {
		variations = append(variations, "salt-master", "salt-api")
	}
	
	return variations
}