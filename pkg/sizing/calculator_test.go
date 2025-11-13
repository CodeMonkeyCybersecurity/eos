package sizing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testContext creates a test runtime context
func testContext(t *testing.T) *eos_io.RuntimeContext {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return eos_io.NewContext(ctx, "test")
}

// getServiceDef is a helper to get a pointer to a service definition
func getServiceDef(serviceType ServiceType) *ServiceDefinition {
	def := ServiceDefinitions[serviceType]
	return &def
}

func TestNewCalculator(t *testing.T) {
	t.Parallel()
	config := EnvironmentConfigs["development"]
	workload := DefaultWorkloadProfiles["small"]

	calc := NewCalculator(config, workload)

	assert.NotNil(t, calc)
	assert.Equal(t, config, calc.config)
	assert.Equal(t, workload, calc.workloadProfile)
	assert.Empty(t, calc.services)
	assert.NotNil(t, calc.customServices)
}

func TestAddService(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		serviceType ServiceType
		wantErr     bool
	}{
		{
			name:        "valid service type",
			serviceType: ServiceTypeWebServer,
			wantErr:     false,
		},
		{
			name:        "another valid service type",
			serviceType: ServiceTypeDatabase,
			wantErr:     false,
		},
		{
			name:        "invalid service type",
			serviceType: ServiceType("invalid"),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			calc := NewCalculator(EnvironmentConfigs["development"], DefaultWorkloadProfiles["small"])

			err := calc.AddService(tt.serviceType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, calc.services, tt.serviceType)
			}
		})
	}
}

func TestAddCustomService(t *testing.T) {
	t.Parallel()
	calc := NewCalculator(EnvironmentConfigs["development"], DefaultWorkloadProfiles["small"])

	customService := ServiceDefinition{
		Name: "Custom Service",
		Type: ServiceType("custom"),
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 1},
			Memory: MemoryRequirements{GB: 2},
			Disk:   DiskRequirements{GB: 10, Type: "ssd"},
		},
		ScalingFactor:    0.001,
		LoadFactor:       1.0,
		RedundancyFactor: 1,
	}

	calc.AddCustomService(customService)

	// Should be able to add the custom service now
	err := calc.AddService(ServiceType("custom"))
	assert.NoError(t, err)
}

func TestCalculateSmallWorkload(t *testing.T) {
	t.Parallel()
	rc := testContext(t)

	calc := NewCalculator(EnvironmentConfigs["development"], DefaultWorkloadProfiles["small"])

	// Add a basic web stack
	require.NoError(t, calc.AddService(ServiceTypeWebServer))
	require.NoError(t, calc.AddService(ServiceTypeDatabase))
	require.NoError(t, calc.AddService(ServiceTypeCache))

	result, err := calc.Calculate(rc)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Check that we have results for all services
	assert.Len(t, result.Services, 3)
	assert.Contains(t, result.Services, string(ServiceTypeWebServer))
	assert.Contains(t, result.Services, string(ServiceTypeDatabase))
	assert.Contains(t, result.Services, string(ServiceTypeCache))

	// Check that totals are calculated
	assert.Greater(t, result.TotalCPUCores, 0.0)
	assert.Greater(t, result.TotalMemoryGB, 0.0)
	assert.Greater(t, result.TotalDiskGB, 0.0)

	// Check node recommendations
	assert.Greater(t, result.NodeCount, 0)
	assert.Greater(t, result.NodeSpecs.CPUCores, 0)
	assert.Greater(t, result.NodeSpecs.MemoryGB, 0)
	assert.Greater(t, result.NodeSpecs.DiskGB, 0)
}

func TestCalculateLargeWorkload(t *testing.T) {
	t.Parallel()
	rc := testContext(t)

	calc := NewCalculator(EnvironmentConfigs["production"], DefaultWorkloadProfiles["large"])

	// Add a comprehensive stack
	services := []ServiceType{
		ServiceTypeWebServer,
		ServiceTypeDatabase,
		ServiceTypeCache,
		ServiceTypeQueue,
		ServiceTypeWorker,
		ServiceTypeProxy,
		ServiceTypeMonitoring,
		ServiceTypeLogging,
	}

	for _, service := range services {
		require.NoError(t, calc.AddService(service))
	}

	result, err := calc.Calculate(rc)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Production should have at least 3 nodes
	assert.GreaterOrEqual(t, result.NodeCount, 3)

	// Large workload should require significant resources
	assert.Greater(t, result.TotalCPUCores, 50.0)
	assert.Greater(t, result.TotalMemoryGB, 100.0)
}

func TestCalculateScalingMultiplier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		service  *ServiceDefinition
		workload WorkloadProfile
		minValue float64
	}{
		{
			name:     "web server scaling",
			service:  getServiceDef(ServiceTypeWebServer),
			workload: DefaultWorkloadProfiles["medium"],
			minValue: 1.0, // Should scale with concurrent users
		},
		{
			name:     "database scaling",
			service:  getServiceDef(ServiceTypeDatabase),
			workload: DefaultWorkloadProfiles["large"],
			minValue: 2.0, // Should scale with requests per second
		},
		{
			name:     "cache scaling",
			service:  getServiceDef(ServiceTypeCache),
			workload: DefaultWorkloadProfiles["medium"],
			minValue: 1.0, // Should scale with concurrent users and read ratio
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			calc := NewCalculator(EnvironmentConfigs["development"], tt.workload)
			multiplier := calc.calculateScalingMultiplier(tt.service)
			assert.GreaterOrEqual(t, multiplier, tt.minValue)
		})
	}
}

func TestCalculateDiskGrowth(t *testing.T) {
	t.Parallel()
	calc := NewCalculator(EnvironmentConfigs["development"], DefaultWorkloadProfiles["medium"])

	tests := []struct {
		name         string
		service      *ServiceDefinition
		expectGrowth bool
	}{
		{
			name:         "database should have disk growth",
			service:      getServiceDef(ServiceTypeDatabase),
			expectGrowth: true,
		},
		{
			name:         "storage should have disk growth",
			service:      getServiceDef(ServiceTypeStorage),
			expectGrowth: true,
		},
		{
			name:         "logging should have disk growth with compression",
			service:      getServiceDef(ServiceTypeLogging),
			expectGrowth: true,
		},
		{
			name:         "web server should not have disk growth",
			service:      getServiceDef(ServiceTypeWebServer),
			expectGrowth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			growth := calc.calculateDiskGrowth(tt.service)
			if tt.expectGrowth {
				assert.Greater(t, growth, 0.0)
			} else {
				assert.Equal(t, 0.0, growth)
			}
		})
	}
}

func TestDeterminePlacementStrategy(t *testing.T) {
	t.Parallel()
	calc := NewCalculator(EnvironmentConfigs["development"], DefaultWorkloadProfiles["small"])

	tests := []struct {
		name     string
		service  *ServiceDefinition
		expected string
	}{
		{
			name:     "database with redundancy",
			service:  getServiceDef(ServiceTypeDatabase),
			expected: "anti-affinity",
		},
		{
			name:     "cache placement",
			service:  getServiceDef(ServiceTypeCache),
			expected: "anti-affinity",
		},
		{
			name:     "proxy placement",
			service:  getServiceDef(ServiceTypeProxy),
			expected: "edge",
		},
		{
			name:     "monitoring placement",
			service:  getServiceDef(ServiceTypeMonitoring),
			expected: "dedicated",
		},
		{
			name:     "worker placement",
			service:  getServiceDef(ServiceTypeWorker),
			expected: "balanced",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			strategy := calc.determinePlacementStrategy(tt.service)
			assert.Equal(t, tt.expected, strategy)
		})
	}
}

func TestRoundToStandardSize(t *testing.T) {
	t.Parallel()
	calc := NewCalculator(EnvironmentConfigs["development"], DefaultWorkloadProfiles["small"])

	tests := []struct {
		name     string
		value    int
		sizes    []int
		expected int
	}{
		{
			name:     "round up to nearest",
			value:    3,
			sizes:    []int{2, 4, 8, 16},
			expected: 4,
		},
		{
			name:     "exact match",
			value:    8,
			sizes:    []int{2, 4, 8, 16},
			expected: 8,
		},
		{
			name:     "exceeds all sizes",
			value:    20,
			sizes:    []int{2, 4, 8, 16},
			expected: 16,
		},
		{
			name:     "below minimum",
			value:    1,
			sizes:    []int{2, 4, 8, 16},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := calc.roundToStandardSize(tt.value, tt.sizes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEstimateCosts(t *testing.T) {
	t.Parallel()
	rc := testContext(t)

	// Test with Hetzner provider
	config := EnvironmentConfigs["development"]
	config.Provider = "hetzner"

	calc := NewCalculator(config, DefaultWorkloadProfiles["small"])
	require.NoError(t, calc.AddService(ServiceTypeWebServer))
	require.NoError(t, calc.AddService(ServiceTypeDatabase))

	result, err := calc.Calculate(rc)
	require.NoError(t, err)

	// Should have cost estimates
	assert.Greater(t, result.EstimatedCost.Monthly, 0.0)
	assert.Equal(t, result.EstimatedCost.Yearly, result.EstimatedCost.Monthly*12)
	assert.Equal(t, "USD", result.EstimatedCost.Currency)
	assert.NotEmpty(t, result.EstimatedCost.Breakdown)
	assert.Contains(t, result.EstimatedCost.Breakdown, "compute")
	assert.Contains(t, result.EstimatedCost.Breakdown, "memory")
	assert.Contains(t, result.EstimatedCost.Breakdown, "storage")
}

func TestGenerateWarningsAndRecommendations(t *testing.T) {
	t.Parallel()
	rc := testContext(t)

	// Create a scenario that will generate warnings
	config := EnvironmentConfigs["production"]
	calc := NewCalculator(config, DefaultWorkloadProfiles["large"])

	// Add services but not monitoring (should generate recommendation)
	require.NoError(t, calc.AddService(ServiceTypeWebServer))
	require.NoError(t, calc.AddService(ServiceTypeDatabase))

	result, err := calc.Calculate(rc)
	require.NoError(t, err)

	// Should have recommendation about monitoring
	assert.NotEmpty(t, result.Recommendations)
	hasMonitoringRec := false
	for _, rec := range result.Recommendations {
		if strings.Contains(rec, "monitoring") {
			hasMonitoringRec = true
			break
		}
	}
	assert.True(t, hasMonitoringRec, "Should recommend adding monitoring for production")
}
