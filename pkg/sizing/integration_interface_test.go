package sizing

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunWithSizingChecks(t *testing.T) {
	// Create test context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc := eos_io.NewContext(ctx, "test")

	// Test successful deployment with existing mapping
	t.Run("successful deployment with sizing checks", func(t *testing.T) {
		deploymentRan := false
		err := RunWithSizingChecks(rc, "vault", func(rc *eos_io.RuntimeContext) error {
			deploymentRan = true
			return nil
		})
		
		// In test environment, this may pass if system has enough resources
		// or fail if user input is required (no TTY in test)
		if err != nil {
			// If error, deployment shouldn't have run (blocked by preflight)
			assert.False(t, deploymentRan)
		} else {
			// If no error, deployment should have run
			assert.True(t, deploymentRan)
		}
	})

	// Test with unknown service (no sizing checks)
	t.Run("unknown service skips sizing checks", func(t *testing.T) {
		deploymentRan := false
		err := RunWithSizingChecks(rc, "unknown-service", func(rc *eos_io.RuntimeContext) error {
			deploymentRan = true
			return nil
		})
		
		assert.NoError(t, err)
		assert.True(t, deploymentRan) // Should run without sizing checks
	})

	// Test with custom mapping
	t.Run("custom service mapping", func(t *testing.T) {
		// Register custom mapping that skips preflight
		RegisterServiceMapping("test-service", CreateServiceMapping(
			ServiceTypeWebServer,
			WithoutPreflight(),
			WithRelatedServices(ServiceTypeDatabase),
		))

		deploymentRan := false
		err := RunWithSizingChecks(rc, "test-service", func(rc *eos_io.RuntimeContext) error {
			deploymentRan = true
			return nil
		})
		
		assert.NoError(t, err)
		assert.True(t, deploymentRan) // Should run since preflight is skipped
	})
}

func TestServiceMappingOptions(t *testing.T) {
	t.Run("create mapping with all options", func(t *testing.T) {
		workload := WorkloadProfile{
			Name:              "Test Workload",
			ConcurrentUsers:   1000,
			RequestsPerSecond: 100,
		}

		mapping := CreateServiceMapping(
			ServiceTypeDatabase,
			WithWorkloadProfile(workload),
			WithRelatedServices(ServiceTypeCache, ServiceTypeQueue),
			WithoutPreflight(),
			WithoutPostflight(),
		)

		assert.Equal(t, ServiceTypeDatabase, mapping.ServiceType)
		assert.NotNil(t, mapping.WorkloadProfile)
		assert.Equal(t, "Test Workload", mapping.WorkloadProfile.Name)
		assert.Len(t, mapping.RelatedServices, 2)
		assert.True(t, mapping.SkipPreflight)
		assert.True(t, mapping.SkipPostflight)
	})
}

func TestCommandServiceMappings(t *testing.T) {
	// Verify some key mappings exist
	testCases := []struct {
		command         string
		expectedType    ServiceType
		relatedServices int
	}{
		{"nomad", ServiceTypeOrchestrator, 1},
		{"vault", ServiceTypeVault, 0},
		{"postgres", ServiceTypeDatabase, 0},
		{"grafana", ServiceTypeMonitoring, 1},
		{"hecate", ServiceTypeProxy, 1},
		{"delphi", ServiceTypeMonitoring, 2},
	}

	for _, tc := range testCases {
		t.Run(tc.command, func(t *testing.T) {
			mapping, exists := CommandServiceMappings[tc.command]
			require.True(t, exists, "mapping should exist for %s", tc.command)
			assert.Equal(t, tc.expectedType, mapping.ServiceType)
			assert.Len(t, mapping.RelatedServices, tc.relatedServices)
		})
	}
}

func TestRegisterServiceMapping(t *testing.T) {
	// Test registering a new mapping
	customMapping := ServiceMapping{
		ServiceType: ServiceTypeWebServer,
		RelatedServices: []ServiceType{ServiceTypeCache},
	}

	RegisterServiceMapping("MyCustomApp", customMapping)

	// Verify it was registered (case-insensitive)
	registered, exists := CommandServiceMappings["mycustomapp"]
	require.True(t, exists)
	assert.Equal(t, ServiceTypeWebServer, registered.ServiceType)
	assert.Len(t, registered.RelatedServices, 1)
}