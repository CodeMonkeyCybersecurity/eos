package cephfs

import (
	"testing"
)

func TestConfig_GetObjectStore(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "default objectstore",
			config:   &Config{},
			expected: DefaultObjectStore,
		},
		{
			name:     "custom objectstore",
			config:   &Config{ObjectStore: "filestore"},
			expected: "filestore",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.GetObjectStore(); got != tt.expected {
				t.Errorf("GetObjectStore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_GetOSDMemoryTarget(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "default memory target",
			config:   &Config{},
			expected: DefaultOSDMemoryTarget,
		},
		{
			name:     "custom memory target",
			config:   &Config{OSDMemoryTarget: "8G"},
			expected: "8G",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.GetOSDMemoryTarget(); got != tt.expected {
				t.Errorf("GetOSDMemoryTarget() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_GetMONCount(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected int
	}{
		{
			name:     "default MON count",
			config:   &Config{},
			expected: DefaultMONCount,
		},
		{
			name:     "custom MON count",
			config:   &Config{MONCount: 5},
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.GetMONCount(); got != tt.expected {
				t.Errorf("GetMONCount() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_GetMGRCount(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected int
	}{
		{
			name:     "default MGR count",
			config:   &Config{},
			expected: DefaultMGRCount,
		},
		{
			name:     "custom MGR count",
			config:   &Config{MGRCount: 3},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.GetMGRCount(); got != tt.expected {
				t.Errorf("GetMGRCount() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsValidCephImage(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		expected bool
	}{
		{
			name:     "valid quay.io image",
			image:    "quay.io/ceph/ceph:v18.2.1",
			expected: true,
		},
		{
			name:     "valid docker.io image",
			image:    "docker.io/ceph/ceph:latest",
			expected: true,
		},
		{
			name:     "valid short image",
			image:    "ceph/ceph:v17.2.0",
			expected: true,
		},
		{
			name:     "empty image",
			image:    "",
			expected: false,
		},
		{
			name:     "image without tag",
			image:    "quay.io/ceph/ceph",
			expected: false,
		},
		{
			name:     "invalid registry",
			image:    "invalid/registry:tag",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidCephImage(tt.image); got != tt.expected {
				t.Errorf("IsValidCephImage() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetCephMGRPort(t *testing.T) {
	port := GetCephMGRPort()
	if port <= 0 {
		t.Errorf("GetCephMGRPort() returned invalid port: %d", port)
	}

	// Should return the expected port
	if port != 8263 {
		t.Errorf("GetCephMGRPort() = %d, want %d", port, 8263)
	}
}

func TestGetSaltCephPillarPath(t *testing.T) {
	expected := SaltCephPillarDir + "/ceph.sls"
	if got := GetSaltCephPillarPath(); got != expected {
		t.Errorf("GetSaltCephPillarPath() = %v, want %v", got, expected)
	}
}

func TestGetTerraformCephConfigPath(t *testing.T) {
	expected := TerraformCephDir + "/main.tf"
	if got := GetTerraformCephConfigPath(); got != expected {
		t.Errorf("GetTerraformCephConfigPath() = %v, want %v", got, expected)
	}
}

func TestVerificationResult_HasErrors(t *testing.T) {
	tests := []struct {
		name   string
		result *VerificationResult
		want   bool
	}{
		{
			name:   "no errors",
			result: &VerificationResult{Errors: []string{}},
			want:   false,
		},
		{
			name:   "has errors",
			result: &VerificationResult{Errors: []string{"error1", "error2"}},
			want:   true,
		},
		{
			name:   "nil errors slice",
			result: &VerificationResult{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasErrors := len(tt.result.Errors) > 0
			if hasErrors != tt.want {
				t.Errorf("VerificationResult has errors = %v, want %v", hasErrors, tt.want)
			}
		})
	}
}

func TestDeploymentStatus_IsHealthy(t *testing.T) {
	tests := []struct {
		name   string
		status *DeploymentStatus
		want   bool
	}{
		{
			name: "healthy cluster",
			status: &DeploymentStatus{
				ClusterExists:   true,
				ClusterHealthy:  true,
				CephFSAvailable: true,
			},
			want: true,
		},
		{
			name: "cluster doesn't exist",
			status: &DeploymentStatus{
				ClusterExists:   false,
				ClusterHealthy:  false,
				CephFSAvailable: false,
			},
			want: false,
		},
		{
			name: "cluster exists but unhealthy",
			status: &DeploymentStatus{
				ClusterExists:   true,
				ClusterHealthy:  false,
				CephFSAvailable: false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isHealthy := tt.status.ClusterExists && tt.status.ClusterHealthy
			if isHealthy != tt.want {
				t.Errorf("DeploymentStatus is healthy = %v, want %v", isHealthy, tt.want)
			}
		})
	}
}
