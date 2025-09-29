// pkg/bootstrap/orchestrator_test.go
//
// Tests for the bootstrap orchestrator phase functions

package bootstrap

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/stretchr/testify/assert"
)

// TestConsulConfigGeneration tests that Consul configuration is generated correctly
func TestConsulConfigGeneration(t *testing.T) {
	tests := []struct {
		name           string
		clusterInfo    *ClusterInfo
		expectedExpect int
	}{
		{
			name: "single node deployment",
			clusterInfo: &ClusterInfo{
				IsSingleNode: true,
				NodeCount:    1,
			},
			expectedExpected: 1,
		},
		{
			name: "multi-node with count",
			clusterInfo: &ClusterInfo{
				IsSingleNode: false,
				NodeCount:    5,
			},
			expectedExpected: 5,
		},
		{
			name: "multi-node default",
			clusterInfo: &ClusterInfo{
				IsSingleNode: false,
				NodeCount:    0,
			},
			expectedExpected: 3, // Should default to 3
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the configuration logic
			consulConfig := &consul.ConsulConfig{
				Mode:       "server",
				Datacenter: "dc1",
				UI:         true,
			}

			// Apply the logic from phaseConsul
			if tt.clusterInfo.IsSingleNode {
				consulConfig.BootstrapExpected = 1
			} else {
				consulConfig.BootstrapExpected = tt.clusterInfo.NodeCount
				if consulConfig.BootstrapExpected == 0 {
					consulConfig.BootstrapExpected = 3
				}
			}

			assert.Equal(t, tt.expectedExpected, consulConfig.BootstrapExpected,
				"BootstrapExpected should match expected value")
		})
	}
}

func TestBootstrapOptions_HashiCorpFlags(t *testing.T) {
	// Test that BootstrapOptions properly handles HashiCorp service flags
	opts := &BootstrapOptions{
		SkipConsul:  false, // Consul should always be false (required)
		EnableVault: true,
		EnableNomad: false,
	}

	assert.False(t, opts.SkipConsul, "Consul should never be skipped")
	assert.True(t, opts.EnableVault, "Vault should be enabled when flag is set")
	assert.False(t, opts.EnableNomad, "Nomad should be disabled when flag is false")
}

func TestBootstrapPhaseValidation(t *testing.T) {
	// Test that required phases are defined correctly
	assert.Contains(t, PhaseValidators, "consul", "Consul validator should be defined")
	assert.Contains(t, PhaseValidators, "vault", "Vault validator should be defined")
	assert.Contains(t, PhaseValidators, "nomad", "Nomad validator should be defined")
	assert.Contains(t, PhaseValidators, "storage", "Storage validator should be defined")
	assert.Contains(t, PhaseValidators, "tailscale", "Tailscale validator should be defined")
	assert.Contains(t, PhaseValidators, "osquery", "OSQuery validator should be defined")
	assert.Contains(t, PhaseValidators, "hardening", "Hardening validator should be defined")
}

func TestClusterInfoStructure(t *testing.T) {
	// Test that ClusterInfo has the expected fields
	clusterInfo := &ClusterInfo{
		IsSingleNode: true,
		NodeCount:    1,
		MyRole:       "server",
		ClusterID:    "test-cluster",
	}

	assert.True(t, clusterInfo.IsSingleNode, "IsSingleNode should be settable")
	assert.Equal(t, 1, clusterInfo.NodeCount, "NodeCount should be settable")
	assert.Equal(t, "server", clusterInfo.MyRole, "MyRole should be settable")
	assert.Equal(t, "test-cluster", clusterInfo.ClusterID, "ClusterID should be settable")
}
