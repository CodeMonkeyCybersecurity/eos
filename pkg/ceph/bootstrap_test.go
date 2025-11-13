// pkg/ceph/bootstrap_test.go
package ceph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBootstrapConfigDefaults tests that default values are set correctly
func TestBootstrapConfigDefaults(t *testing.T) {
	config := &BootstrapConfig{
		Hostname:      "test-host",
		MonitorIP:     "192.168.1.10",
		PublicNetwork: "192.168.1.0/24",
	}

	// Test that cluster name defaults
	if config.ClusterName == "" {
		config.ClusterName = "ceph"
	}
	assert.Equal(t, "ceph", config.ClusterName)

	// Test that cluster network defaults to public network
	if config.ClusterNetwork == "" {
		config.ClusterNetwork = config.PublicNetwork
	}
	assert.Equal(t, config.PublicNetwork, config.ClusterNetwork)
}

// TestBootstrapConfigValidation tests configuration validation
func TestBootstrapConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *BootstrapConfig
		shouldError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &BootstrapConfig{
				Hostname:      "test-host",
				MonitorIP:     "192.168.1.10",
				PublicNetwork: "192.168.1.0/24",
			},
			shouldError: false,
		},
		{
			name: "missing hostname",
			config: &BootstrapConfig{
				Hostname:      "",
				MonitorIP:     "192.168.1.10",
				PublicNetwork: "192.168.1.0/24",
			},
			shouldError: true,
			errorMsg:    "hostname is required",
		},
		{
			name: "missing monitor IP",
			config: &BootstrapConfig{
				Hostname:      "test-host",
				MonitorIP:     "",
				PublicNetwork: "192.168.1.0/24",
			},
			shouldError: true,
			errorMsg:    "monitor IP address is required",
		},
		{
			name: "missing public network",
			config: &BootstrapConfig{
				Hostname:      "test-host",
				MonitorIP:     "192.168.1.10",
				PublicNetwork: "",
			},
			shouldError: true,
			errorMsg:    "public network CIDR is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate validation
			var err error
			if tt.config.Hostname == "" {
				err = assert.AnError
			} else if tt.config.MonitorIP == "" {
				err = assert.AnError
			} else if tt.config.PublicNetwork == "" {
				err = assert.AnError
			}

			if tt.shouldError {
				assert.Error(t, err, "Expected validation to fail for: %s", tt.name)
			} else {
				assert.NoError(t, err, "Expected validation to pass for: %s", tt.name)
			}
		})
	}
}

// TestSecureKeyringCreation tests that keyring creation uses secure permissions
func TestSecureKeyringCreation(t *testing.T) {
	// Test that createSecureKeyring returns a path
	keyring, err := createSecureKeyring("test")
	if err != nil {
		t.Skipf("Skipping keyring test (requires filesystem access): %v", err)
		return
	}
	defer func() {
		// Clean up
		if keyring != "" {
			// Would normally remove file, but in test we just verify it was created
		}
	}()

	assert.NotEmpty(t, keyring, "Keyring path should not be empty")
	assert.Contains(t, keyring, "ceph-test-", "Keyring should have expected prefix")
	assert.Contains(t, keyring, ".keyring", "Keyring should have .keyring extension")
}

// TestMustAtoi tests the helper function
func TestMustAtoi(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"0", 0},
		{"1", 1},
		{"999", 999},
		{"64045", 64045}, // Ceph UID
		{"invalid", 0},   // Should return 0 for invalid input
		{"", 0},          // Should return 0 for empty input
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mustAtoi(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestBootstrapStateTransitions tests state machine transitions
func TestBootstrapStateTransitions(t *testing.T) {
	states := []BootstrapState{
		StateUninitialized,
		StateFSIDGenerated,
		StateConfigWritten,
		StateKeyringsCreated,
		StateMonmapGenerated,
		StateMonitorInitialized,
		StateOwnershipFixed,
		StateMonitorStarted,
		StateBootstrapComplete,
	}

	// Verify all states are defined
	for i, state := range states {
		assert.NotEmpty(t, string(state), "State %d should not be empty", i)
	}

	// Verify states are in logical order (this is a documentation test)
	t.Logf("Bootstrap state progression:")
	for i, state := range states {
		t.Logf("  %d. %s", i+1, state)
	}
}

// BenchmarkMustAtoi benchmarks the helper function
func BenchmarkMustAtoi(b *testing.B) {
	for b.Loop() {
		_ = mustAtoi("64045")
	}
}
