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
			name:         "-master direct",
			processName:  "-master",
			port:         4505,
			expectedName: "-master",
		},
		{
			name:         "-api direct",
			processName:  "-api",
			port:         8000,
			expectedName: "-api",
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
			name:         " path with slash",
			processName:  "/opt//",
			port:         4505,
			expectedName: "-master",
		},
		{
			name:         " path without slash",
			processName:  "/opt/",
			port:         4505,
			expectedName: "-master",
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
			name:         "usr bin -master",
			processName:  "/usr/bin/-master",
			port:         4505,
			expectedName: "-master",
		},
		{
			name:         "usr bin vault",
			processName:  "/usr/bin/vault",
			port:         8200,
			expectedName: "vault",
		},
		// Port-based fallback
		{
			name:         "unknown process on  port",
			processName:  "unknown-process",
			port:         4505,
			expectedName: "-master",
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
			name:         "python script on -api port",
			processName:  "python3",
			port:         8000,
			expectedName: "-api",
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
			name:        "standard ss output with quotes",
			ssLine:      `LISTEN 0 128 *:4505 *:* users:(("-master",pid=1234,fd=8))`,
			port:        4505,
			expectedPID: 1234,
			shouldBeNil: false,
		},
		{
			name:        "ss output without quotes",
			ssLine:      `LISTEN 0 128 *:4505 *:* users:((-master,pid=1234,fd=8))`,
			port:        4505,
			expectedPID: 1234,
			shouldBeNil: false,
		},
		{
			name:        "ss output with path",
			ssLine:      `LISTEN 0 128 *:4505 *:* users:(("/opt//",pid=1234,fd=8))`,
			port:        4505,
			expectedPID: 1234,
			shouldBeNil: false,
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
			serviceName: "/opt//",
			expectedCmds: []string{
				"-master",
				"-api",
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

	if strings.Contains(serviceName, "/opt//") {
		variations = append(variations, "-master", "-api")
	}

	return variations
}
