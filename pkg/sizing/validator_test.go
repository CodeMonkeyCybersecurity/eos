package sizing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewValidator(t *testing.T) {
	result := &SizingResult{
		TotalCPUCores: 16,
		TotalMemoryGB: 32,
		TotalDiskGB:   500,
		NodeCount:     2,
		NodeSpecs: NodeSpecification{
			CPUCores:    8,
			MemoryGB:    16,
			DiskGB:      250,
			DiskType:    "ssd",
			NetworkGbps: 1,
		},
	}

	validator := NewValidator(result)
	assert.NotNil(t, validator)
	assert.Equal(t, result, validator.requirements)
}

func TestValidateNodeCapacity(t *testing.T) {
	rc := testContext(t)

	result := &SizingResult{
		NodeSpecs: NodeSpecification{
			CPUCores:    8,
			MemoryGB:    16,
			DiskGB:      200,
			DiskType:    "ssd",
			NetworkGbps: 1,
		},
	}

	validator := NewValidator(result)

	tests := []struct {
		name          string
		node          NodeSpecification
		expectErrors  bool
		errorCount    int
	}{
		{
			name: "node meets requirements",
			node: NodeSpecification{
				CPUCores:    8,
				MemoryGB:    16,
				DiskGB:      200,
				DiskType:    "ssd",
				NetworkGbps: 1,
			},
			expectErrors: false,
		},
		{
			name: "node exceeds requirements",
			node: NodeSpecification{
				CPUCores:    16,
				MemoryGB:    32,
				DiskGB:      500,
				DiskType:    "nvme",
				NetworkGbps: 10,
			},
			expectErrors: false,
		},
		{
			name: "insufficient CPU",
			node: NodeSpecification{
				CPUCores:    4,
				MemoryGB:    16,
				DiskGB:      200,
				DiskType:    "ssd",
				NetworkGbps: 1,
			},
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "insufficient everything",
			node: NodeSpecification{
				CPUCores:    4,
				MemoryGB:    8,
				DiskGB:      100,
				DiskType:    "hdd",
				NetworkGbps: 0,
			},
			expectErrors: true,
			errorCount:   5,
		},
		{
			name: "incompatible disk type",
			node: NodeSpecification{
				CPUCores:    8,
				MemoryGB:    16,
				DiskGB:      200,
				DiskType:    "hdd", // Required is SSD
				NetworkGbps: 1,
			},
			expectErrors: true,
			errorCount:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors, err := validator.ValidateNodeCapacity(rc, tt.node)
			require.NoError(t, err)

			if tt.expectErrors {
				assert.NotEmpty(t, errors)
				assert.Len(t, errors, tt.errorCount)
			} else {
				assert.Empty(t, errors)
			}
		})
	}
}

func TestValidateServicePlacement(t *testing.T) {
	rc := testContext(t)

	result := &SizingResult{
		Services: map[string]ServiceRequirements{
			string(ServiceTypeWebServer): {
				PerInstance: ResourceRequirements{
					CPU:    CPURequirements{Cores: 2},
					Memory: MemoryRequirements{GB: 4},
					Disk:   DiskRequirements{GB: 50},
				},
			},
			string(ServiceTypeDatabase): {
				PerInstance: ResourceRequirements{
					CPU:    CPURequirements{Cores: 4},
					Memory: MemoryRequirements{GB: 16},
					Disk:   DiskRequirements{GB: 100, IOPS: 10000},
					Network: NetworkRequirements{BandwidthMbps: 100},
				},
			},
		},
	}

	validator := NewValidator(result)

	tests := []struct {
		name         string
		serviceType  ServiceType
		nodeResources ResourceRequirements
		wantErr      bool
		errContains  string
	}{
		{
			name:        "sufficient resources for web server",
			serviceType: ServiceTypeWebServer,
			nodeResources: ResourceRequirements{
				CPU:    CPURequirements{Cores: 4},
				Memory: MemoryRequirements{GB: 8},
				Disk:   DiskRequirements{GB: 100},
			},
			wantErr: false,
		},
		{
			name:        "insufficient CPU",
			serviceType: ServiceTypeWebServer,
			nodeResources: ResourceRequirements{
				CPU:    CPURequirements{Cores: 1},
				Memory: MemoryRequirements{GB: 8},
				Disk:   DiskRequirements{GB: 100},
			},
			wantErr:     true,
			errContains: "insufficient CPU",
		},
		{
			name:        "insufficient memory",
			serviceType: ServiceTypeDatabase,
			nodeResources: ResourceRequirements{
				CPU:    CPURequirements{Cores: 8},
				Memory: MemoryRequirements{GB: 8},
				Disk:   DiskRequirements{GB: 200},
			},
			wantErr:     true,
			errContains: "insufficient memory",
		},
		{
			name:        "insufficient network",
			serviceType: ServiceTypeDatabase,
			nodeResources: ResourceRequirements{
				CPU:     CPURequirements{Cores: 8},
				Memory:  MemoryRequirements{GB: 32},
				Disk:    DiskRequirements{GB: 200},
				Network: NetworkRequirements{BandwidthMbps: 50},
			},
			wantErr:     true,
			errContains: "insufficient network bandwidth",
		},
		{
			name:        "unknown service",
			serviceType: ServiceType("unknown"),
			nodeResources: ResourceRequirements{
				CPU:    CPURequirements{Cores: 8},
				Memory: MemoryRequirements{GB: 32},
				Disk:   DiskRequirements{GB: 200},
			},
			wantErr:     true,
			errContains: "no sizing requirements found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateServicePlacement(rc, tt.serviceType, tt.nodeResources)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateClusterCapacity(t *testing.T) {
	rc := testContext(t)

	result := &SizingResult{
		TotalCPUCores:      32,
		TotalMemoryGB:      64,
		TotalDiskGB:        1000,
		TotalBandwidthMbps: 2000,
		NodeCount:          3,
	}

	validator := NewValidator(result)

	tests := []struct {
		name    string
		nodes   []NodeSpecification
		wantErr bool
	}{
		{
			name: "cluster meets requirements",
			nodes: []NodeSpecification{
				{CPUCores: 16, MemoryGB: 32, DiskGB: 500, NetworkGbps: 1},
				{CPUCores: 16, MemoryGB: 32, DiskGB: 500, NetworkGbps: 1},
				{CPUCores: 8, MemoryGB: 16, DiskGB: 250, NetworkGbps: 1},
			},
			wantErr: false,
		},
		{
			name: "insufficient total resources",
			nodes: []NodeSpecification{
				{CPUCores: 8, MemoryGB: 16, DiskGB: 250, NetworkGbps: 1},
				{CPUCores: 8, MemoryGB: 16, DiskGB: 250, NetworkGbps: 1},
			},
			wantErr: true,
		},
		{
			name:    "no nodes",
			nodes:   []NodeSpecification{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateClusterCapacity(rc, tt.nodes)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateServiceDistribution(t *testing.T) {
	rc := testContext(t)

	result := &SizingResult{
		Services: map[string]ServiceRequirements{
			string(ServiceTypeWebServer): {
				Service: ServiceDefinition{
					Name:             "Web Server",
					RedundancyFactor: 2,
				},
				InstanceCount:     2,
				PlacementStrategy: "anti-affinity",
			},
			string(ServiceTypeDatabase): {
				Service: ServiceDefinition{
					Name:             "Database",
					RedundancyFactor: 3,
				},
				InstanceCount:     3,
				PlacementStrategy: "anti-affinity",
			},
		},
	}

	validator := NewValidator(result)

	tests := []struct {
		name       string
		placements map[string][]string
		wantErr    bool
	}{
		{
			name: "correct distribution",
			placements: map[string][]string{
				string(ServiceTypeWebServer): {"node1", "node2"},
				string(ServiceTypeDatabase):  {"node1", "node2", "node3"},
			},
			wantErr: false,
		},
		{
			name: "anti-affinity violation",
			placements: map[string][]string{
				string(ServiceTypeWebServer): {"node1", "node1"}, // Same node twice
				string(ServiceTypeDatabase):  {"node1", "node2", "node3"},
			},
			wantErr: true,
		},
		{
			name: "fewer instances than recommended",
			placements: map[string][]string{
				string(ServiceTypeWebServer): {"node1"}, // Only 1 instance, need 2
				string(ServiceTypeDatabase):  {"node1", "node2", "node3"},
			},
			wantErr: false, // This generates a warning, not an error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateServiceDistribution(rc, tt.placements)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsDiskTypeCompatible(t *testing.T) {
	validator := NewValidator(&SizingResult{})

	tests := []struct {
		name     string
		actual   string
		required string
		expected bool
	}{
		{
			name:     "exact match ssd",
			actual:   "ssd",
			required: "ssd",
			expected: true,
		},
		{
			name:     "nvme exceeds ssd",
			actual:   "nvme",
			required: "ssd",
			expected: true,
		},
		{
			name:     "nvme exceeds hdd",
			actual:   "nvme",
			required: "hdd",
			expected: true,
		},
		{
			name:     "ssd exceeds hdd",
			actual:   "ssd",
			required: "hdd",
			expected: true,
		},
		{
			name:     "hdd insufficient for ssd",
			actual:   "hdd",
			required: "ssd",
			expected: false,
		},
		{
			name:     "hdd insufficient for nvme",
			actual:   "hdd",
			required: "nvme",
			expected: false,
		},
		{
			name:     "case insensitive",
			actual:   "SSD",
			required: "ssd",
			expected: true,
		},
		{
			name:     "unknown type",
			actual:   "unknown",
			required: "ssd",
			expected: true, // Assume compatible if unknown
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isDiskTypeCompatible(tt.actual, tt.required)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateReport(t *testing.T) {
	rc := testContext(t)

	result := &SizingResult{
		TotalCPUCores:      32,
		TotalMemoryGB:      64,
		TotalDiskGB:        1000,
		TotalBandwidthMbps: 2000,
		NodeCount:          3,
		NodeSpecs: NodeSpecification{
			CPUCores:       16,
			MemoryGB:       32,
			DiskGB:         500,
			DiskType:       "ssd",
			NetworkGbps:    10,
			Provider:       "hetzner",
			CPUUtilization: 75.5,
			MemUtilization: 82.3,
		},
		Services: map[string]ServiceRequirements{
			string(ServiceTypeWebServer): {
				Service: ServiceDefinition{
					Name: "Web Server",
					Type: ServiceTypeWebServer,
				},
				InstanceCount: 2,
				PerInstance: ResourceRequirements{
					CPU:    CPURequirements{Cores: 2},
					Memory: MemoryRequirements{GB: 4},
					Disk:   DiskRequirements{GB: 50},
				},
				PlacementStrategy: "balanced",
			},
		},
		Warnings: []string{
			"High memory utilization (82.3%) - consider larger nodes",
		},
		Recommendations: []string{
			"Consider SSD storage for database workloads",
		},
		EstimatedCost: CostEstimate{
			Monthly:  1500.00,
			Yearly:   18000.00,
			Currency: "USD",
			Breakdown: map[string]float64{
				"compute": 800.00,
				"memory":  400.00,
				"storage": 300.00,
			},
		},
	}

	validator := NewValidator(result)
	report := validator.GenerateReport(rc)

	// Check that report contains expected sections
	assert.Contains(t, report, "Infrastructure Sizing Requirements")
	assert.Contains(t, report, "Environment: hetzner")
	assert.Contains(t, report, "Total CPU Cores: 32.0")
	assert.Contains(t, report, "Total Memory: 64.0 GB")
	assert.Contains(t, report, "Recommended Nodes: 3")

	// Check node specifications
	assert.Contains(t, report, "Recommended Node Specifications")
	assert.Contains(t, report, "CPU Cores: 16")
	assert.Contains(t, report, "Memory: 32 GB")
	assert.Contains(t, report, "Disk: 500 GB (ssd)")

	// Check service requirements
	assert.Contains(t, report, "Service Requirements")
	assert.Contains(t, report, "Web Server")
	assert.Contains(t, report, "Instances: 2")

	// Check warnings and recommendations
	assert.Contains(t, report, "Warnings:")
	assert.Contains(t, report, "High memory utilization")
	assert.Contains(t, report, "Recommendations:")
	assert.Contains(t, report, "Consider SSD storage")

	// Check cost estimate
	assert.Contains(t, report, "Estimated Cost:")
	assert.Contains(t, report, "Monthly: $1500.00 USD")
	assert.Contains(t, report, "Yearly: $18000.00 USD")
	assert.Contains(t, report, "compute: $800.00")
}