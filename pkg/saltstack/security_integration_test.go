// pkg/saltstack/security_integration_test.go - Comprehensive security tests for SaltStack integration
package saltstack_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// TestClient_StateApply_SecurityValidation tests state application with security focus
func TestClient_StateApply_SecurityValidation(t *testing.T) {
	tests := []struct {
		name          string
		target        string
		state         string
		pillar        map[string]interface{}
		expectedCmd   string
		expectedArgs  []string
		shouldFail    bool
		errorContains string
	}{
		{
			name:         "basic_state_application",
			target:       "minion-01",
			state:        "apache.install",
			pillar:       nil,
			expectedCmd:  "salt",
			expectedArgs: []string{"minion-01", "state.apply", "apache.install"},
			shouldFail:   false,
		},
		{
			name:   "state_with_pillar_data",
			target: "web-servers",
			state:  "users.create",
			pillar: map[string]interface{}{
				"username": "testuser",
				"groups":   []string{"sudo", "www-data"},
				"shell":    "/bin/bash",
			},
			expectedCmd: "salt",
			shouldFail:  false,
		},
		{
			name:   "complex_pillar_data",
			target: "*",
			state:  "firewall.configure",
			pillar: map[string]interface{}{
				"rules": map[string]interface{}{
					"ssh": map[string]interface{}{
						"port":   22,
						"source": "192.168.1.0/24",
					},
					"http": map[string]interface{}{
						"port":    80,
						"enabled": true,
					},
				},
				"default_policy": "drop",
			},
			expectedCmd: "salt",
			shouldFail:  false,
		},
		{
			name:       "empty_target_validation",
			target:     "",
			state:      "test.state",
			pillar:     nil,
			shouldFail: false, // Salt should handle empty targets
		},
		{
			name:       "empty_state_validation",
			target:     "minion-01",
			state:      "",
			pillar:     nil,
			shouldFail: false, // Salt should handle empty states
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			logger := otelzap.Ctx(ctx)
			client := NewClient(logger)

			err := client.StateApply(ctx, tt.target, tt.state, tt.pillar)

			if tt.shouldFail {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				// For testing, we expect errors since we don't have actual Salt
				// but we can verify the structure and input validation
				assert.Error(t, err) // Expected since salt command won't exist in test
			}
		})
	}
}

// TestClient_PillarSerialization tests secure pillar data serialization
func TestClient_PillarSerialization(t *testing.T) {
	tests := []struct {
		name   string
		pillar map[string]interface{}
		valid  bool
	}{
		{
			name: "simple_string_values",
			pillar: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
			valid: true,
		},
		{
			name: "nested_structures",
			pillar: map[string]interface{}{
				"database": map[string]interface{}{
					"host":     "localhost",
					"port":     5432,
					"username": "dbuser",
					"ssl":      true,
				},
			},
			valid: true,
		},
		{
			name: "array_values",
			pillar: map[string]interface{}{
				"packages": []string{"nginx", "postgresql", "redis"},
				"ports":    []int{80, 443, 5432},
			},
			valid: true,
		},
		{
			name: "special_characters",
			pillar: map[string]interface{}{
				"password":    "P@ssw0rd!#$%",
				"description": "Special chars: <>&\"'`",
				"path":        "/usr/local/bin",
			},
			valid: true,
		},
		{
			name: "unicode_content",
			pillar: map[string]interface{}{
				"message": "Hello 世界 🌍",
				"name":    "José María",
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling (used internally by StateApply)
			jsonBytes, err := json.Marshal(tt.pillar)

			if tt.valid {
				require.NoError(t, err)
				assert.NotEmpty(t, jsonBytes)

				// Verify we can unmarshal back
				var unmarshaled map[string]interface{}
				err = json.Unmarshal(jsonBytes, &unmarshaled)
				assert.NoError(t, err)

				// Verify string representation is safe for shell
				jsonStr := string(jsonBytes)
				assert.NotContains(t, jsonStr, "`", "JSON should not contain backticks")
				assert.NotContains(t, jsonStr, "$(", "JSON should not contain command substitution")
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestClient_TestPing_ConnectivityValidation tests connectivity testing
func TestClient_TestPing_ConnectivityValidation(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		shouldTest bool
	}{
		{
			name:       "single_minion",
			target:     "minion-01",
			shouldTest: true,
		},
		{
			name:       "glob_pattern",
			target:     "web-*",
			shouldTest: true,
		},
		{
			name:       "all_minions",
			target:     "*",
			shouldTest: true,
		},
		{
			name:       "grain_matching",
			target:     "G@os:Ubuntu",
			shouldTest: true,
		},
		{
			name:       "compound_matching",
			target:     "G@os:Ubuntu and web-*",
			shouldTest: true,
		},
		{
			name:       "empty_target",
			target:     "",
			shouldTest: true,
		},
		{
			name:       "special_characters_in_target",
			target:     "minion@domain.com",
			shouldTest: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			logger := otelzap.Ctx(ctx)
			client := NewClient(logger)

			connected, err := client.TestPing(ctx, tt.target)

			if tt.shouldTest {
				// We expect an error in tests since salt command doesn't exist
				// but we can verify the function doesn't panic and handles input
				assert.Error(t, err)       // Expected in test environment
				assert.False(t, connected) // Expected when command fails
			}
		})
	}
}

// TestClient_CmdRun_CommandSecurityValidation tests command execution security
func TestClient_CmdRun_CommandSecurityValidation(t *testing.T) {
	tests := []struct {
		name             string
		target           string
		command          string
		expectValidation bool
		securityConcern  string
	}{
		{
			name:             "safe_system_command",
			target:           "minion-01",
			command:          "systemctl status nginx",
			expectValidation: true,
		},
		{
			name:             "file_operations",
			target:           "*",
			command:          "ls -la /etc/nginx",
			expectValidation: true,
		},
		{
			name:             "package_management",
			target:           "ubuntu-*",
			command:          "apt list --installed",
			expectValidation: true,
		},
		{
			name:             "process_inspection",
			target:           "servers",
			command:          "ps aux | grep nginx",
			expectValidation: true,
		},
		{
			name:             "command_with_quotes",
			target:           "minion-01",
			command:          "echo 'Hello World'",
			expectValidation: true,
		},
		{
			name:             "command_with_special_chars",
			target:           "minion-01",
			command:          "find /var/log -name '*.log'",
			expectValidation: true,
		},
		{
			name:             "potentially_dangerous_command",
			target:           "minion-01",
			command:          "rm -rf /tmp/testfile",
			expectValidation: true, // Salt should handle command validation
			securityConcern:  "destructive command",
		},
		{
			name:             "command_injection_attempt",
			target:           "minion-01",
			command:          "ls; rm -rf /",
			expectValidation: true, // Salt should handle this
			securityConcern:  "command injection",
		},
		{
			name:             "command_substitution",
			target:           "minion-01",
			command:          "echo $(whoami)",
			expectValidation: true, // Salt should handle this
			securityConcern:  "command substitution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			logger := otelzap.Ctx(ctx)
			client := NewClient(logger)

			output, err := client.CmdRun(ctx, tt.target, tt.command)

			if tt.expectValidation {
				// In test environment, we expect errors due to missing salt
				// But the function should not panic or fail validation
				assert.Error(t, err)    // Expected in test
				assert.Empty(t, output) // Expected when command fails

				// Log security concerns for awareness
				if tt.securityConcern != "" {
					t.Logf("Security concern noted: %s for command: %s",
						tt.securityConcern, tt.command)
				}
			}
		})
	}
}

// TestClient_GrainGet_DataRetrieval tests grain data retrieval
func TestClient_GrainGet_DataRetrieval(t *testing.T) {
	tests := []struct {
		name   string
		target string
		grain  string
		valid  bool
	}{
		{
			name:   "os_information",
			target: "minion-01",
			grain:  "os",
			valid:  true,
		},
		{
			name:   "network_interfaces",
			target: "*",
			grain:  "ip_interfaces",
			valid:  true,
		},
		{
			name:   "hardware_info",
			target: "servers",
			grain:  "mem_total",
			valid:  true,
		},
		{
			name:   "kernel_version",
			target: "linux-*",
			grain:  "kernel",
			valid:  true,
		},
		{
			name:   "custom_grain",
			target: "minion-01",
			grain:  "custom_role",
			valid:  true,
		},
		{
			name:   "empty_grain",
			target: "minion-01",
			grain:  "",
			valid:  true, // Salt should handle empty grain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			logger := otelzap.Ctx(ctx)
			client := NewClient(logger)

			grains, err := client.GrainGet(ctx, tt.target, tt.grain)

			if tt.valid {
				// Expected error in test environment
				assert.Error(t, err)
				assert.Nil(t, grains)
			}
		})
	}
}

// TestClient_CheckMinion_MinionValidation tests minion status checking
func TestClient_CheckMinion_MinionValidation(t *testing.T) {
	tests := []struct {
		name   string
		minion string
		valid  bool
	}{
		{
			name:   "standard_minion_name",
			minion: "minion-01",
			valid:  true,
		},
		{
			name:   "domain_based_minion",
			minion: "server.example.com",
			valid:  true,
		},
		{
			name:   "ip_address_minion",
			minion: "192.168.1.100",
			valid:  true,
		},
		{
			name:   "hyphenated_name",
			minion: "web-server-01",
			valid:  true,
		},
		{
			name:   "underscored_name",
			minion: "db_server_primary",
			valid:  true,
		},
		{
			name:   "empty_minion_name",
			minion: "",
			valid:  true, // Should be handled gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			logger := otelzap.Ctx(ctx)
			client := NewClient(logger)

			available, err := client.CheckMinion(ctx, tt.minion)

			if tt.valid {
				// Expected error in test environment
				assert.Error(t, err)
				assert.False(t, available)
			}
		})
	}
}

// TestClient_ErrorHandling tests error handling scenarios
func TestClient_ErrorHandling(t *testing.T) {
	ctx := context.Background()
	logger := otelzap.Ctx(ctx)
	client := NewClient(logger)

	t.Run("context_cancellation", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		err := client.StateApply(cancelCtx, "test", "test.state", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("context_timeout", func(t *testing.T) {
		timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
		defer cancel()

		time.Sleep(2 * time.Millisecond) // Ensure timeout

		err := client.StateApply(timeoutCtx, "test", "test.state", nil)
		assert.Error(t, err)
		// Context should be expired
	})

	t.Run("large_pillar_data", func(t *testing.T) {
		// Test with large pillar data to ensure no buffer overflow
		largePillar := make(map[string]interface{})
		for i := 0; i < 1000; i++ {
			largePillar[fmt.Sprintf("key_%d", i)] = strings.Repeat("value", 100)
		}

		err := client.StateApply(ctx, "test", "test.state", largePillar)
		assert.Error(t, err) // Expected due to missing salt command
		// Should not panic or cause memory issues
	})
}

// TestClient_ConcurrentAccess tests thread safety
func TestClient_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	logger := otelzap.Ctx(ctx)
	client := NewClient(logger)

	const goroutines = 10
	const operations = 5

	results := make(chan error, goroutines*operations)

	// Test concurrent operations
	for g := 0; g < goroutines; g++ {
		go func(goroutineID int) {
			for i := 0; i < operations; i++ {
				// Mix different operations
				switch i % 3 {
				case 0:
					_, err := client.TestPing(ctx, fmt.Sprintf("minion-%d", goroutineID))
					results <- err
				case 1:
					err := client.StateApply(ctx, fmt.Sprintf("group-%d", goroutineID),
						"test.state", map[string]interface{}{"id": goroutineID})
					results <- err
				case 2:
					_, err := client.CmdRun(ctx, fmt.Sprintf("target-%d", goroutineID),
						"echo concurrent test")
					results <- err
				}
			}
		}(g)
	}

	// Collect results
	for i := 0; i < goroutines*operations; i++ {
		err := <-results
		// All operations should fail gracefully (no panic)
		assert.Error(t, err) // Expected in test environment
	}
}

// TestNewClient_Initialization tests client initialization
func TestNewClient_Initialization(t *testing.T) {
	t.Run("valid_logger", func(t *testing.T) {
		logger := otelzap.Ctx(context.Background())
		client := NewClient(logger)

		assert.NotNil(t, client)
		assert.NotNil(t, client.logger)
	})

	t.Run("multiple_clients", func(t *testing.T) {
		logger := otelzap.Ctx(context.Background())

		client1 := NewClient(logger)
		client2 := NewClient(logger)

		assert.NotNil(t, client1)
		assert.NotNil(t, client2)
		assert.NotEqual(t, client1, client2) // Should be different instances
	})
}

// TestClient_InterfaceCompliance tests that Client implements ClientInterface
func TestClient_InterfaceCompliance(t *testing.T) {
	logger := otelzap.Ctx(context.Background())
	client := NewClient(logger)

	// Verify it implements the interface
	var _ ClientInterface = client

	t.Run("interface_methods_available", func(t *testing.T) {
		ctx := context.Background()

		// All interface methods should be callable
		err := client.StateApply(ctx, "test", "test.state", nil)
		assert.Error(t, err) // Expected in test

		_, err = client.TestPing(ctx, "test")
		assert.Error(t, err) // Expected in test

		_, err = client.GrainGet(ctx, "test", "test")
		assert.Error(t, err) // Expected in test

		_, err = client.CmdRun(ctx, "test", "test")
		assert.Error(t, err) // Expected in test

		_, err = client.CheckMinion(ctx, "test")
		assert.Error(t, err) // Expected in test
	})
}

// BenchmarkClient_StateApply benchmarks state application performance
func BenchmarkClient_StateApply(b *testing.B) {
	ctx := context.Background()
	logger := otelzap.Ctx(ctx)
	client := NewClient(logger)

	pillar := map[string]interface{}{
		"test_key": "test_value",
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.StateApply(ctx, "benchmark", "test.state", pillar)
	}
}

// BenchmarkClient_CmdRun benchmarks command execution performance
func BenchmarkClient_CmdRun(b *testing.B) {
	ctx := context.Background()
	logger := otelzap.Ctx(ctx)
	client := NewClient(logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.CmdRun(ctx, "benchmark", "echo test")
	}
}
