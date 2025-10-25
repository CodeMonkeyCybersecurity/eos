// pkg/consul/acl/reset_test.go
//
// Integration tests for ACL bootstrap reset functionality.
//
// Last Updated: 2025-10-25

package acl

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetConsulDataDir_UserProvidedPath tests Layer 1: user-provided path
func TestGetConsulDataDir_UserProvidedPath(t *testing.T) {
	// Create valid Consul data directory
	tmpDir := t.TempDir()
	raftDir := filepath.Join(tmpDir, "raft")
	err := os.MkdirAll(raftDir, 0755)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create Consul client (will not be used since user path provided)
	consulConfig := consulapi.DefaultConfig()
	consulClient, err := consulapi.NewClient(consulConfig)
	require.NoError(t, err)

	// Create reset config with user-provided path
	resetConfig := &ResetConfig{
		DataDir: tmpDir, // User explicitly provides path
	}

	// Call getConsulDataDir
	dataDir, err := getConsulDataDir(rc, consulClient, resetConfig)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, tmpDir, dataDir)
}

// TestGetConsulDataDir_UserProvidedInvalidPath tests Layer 1: invalid user path
func TestGetConsulDataDir_UserProvidedInvalidPath(t *testing.T) {
	// Create directory WITHOUT raft/ subdirectory (invalid)
	tmpDir := t.TempDir()

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create Consul client
	consulConfig := consulapi.DefaultConfig()
	consulClient, err := consulapi.NewClient(consulConfig)
	require.NoError(t, err)

	// Create reset config with invalid path
	resetConfig := &ResetConfig{
		DataDir: tmpDir, // No raft/ subdirectory
	}

	// Call getConsulDataDir
	dataDir, err := getConsulDataDir(rc, consulClient, resetConfig)

	// Should fail with validation error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "specified data directory is not valid")
	assert.Empty(t, dataDir)
}

// TestGetConsulDataDir_FallbackToWellKnownPaths tests Layer 5: well-known paths
func TestGetConsulDataDir_FallbackToWellKnownPaths(t *testing.T) {
	// This test requires setting up a well-known path
	// Skip if /opt/consul or /var/lib/consul don't exist
	wellKnownPaths := []string{
		"/opt/consul",
		"/var/lib/consul",
	}

	var validPath string
	for _, path := range wellKnownPaths {
		raftPath := filepath.Join(path, "raft")
		if _, err := os.Stat(raftPath); err == nil {
			validPath = path
			break
		}
	}

	if validPath == "" {
		t.Skip("No well-known Consul data directories found on system")
	}

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create Consul client (API will likely fail)
	consulConfig := consulapi.DefaultConfig()
	consulClient, err := consulapi.NewClient(consulConfig)
	require.NoError(t, err)

	// Create reset config WITHOUT user-provided path
	resetConfig := &ResetConfig{
		DataDir: "", // No user override
	}

	// Call getConsulDataDir
	// This should fall through to well-known paths
	dataDir, err := getConsulDataDir(rc, consulClient, resetConfig)

	// If a well-known path exists, should succeed
	if err == nil {
		assert.Equal(t, validPath, dataDir)
	} else {
		// If all layers fail, error should be actionable
		assert.Contains(t, err.Error(), "Cannot determine Consul data directory")
	}
}

// TestGetConsulDataDir_AllLayersFail tests Layer 6: all fallbacks exhausted
func TestGetConsulDataDir_AllLayersFail(t *testing.T) {
	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create Consul client (API will fail - no Consul running)
	consulConfig := consulapi.DefaultConfig()
	consulClient, err := consulapi.NewClient(consulConfig)
	require.NoError(t, err)

	// Create reset config WITHOUT user-provided path
	resetConfig := &ResetConfig{
		DataDir: "", // No user override
	}

	// Temporarily set CONSUL_CONFIG_DIR to non-existent path to force config parsing failure
	originalEnv := os.Getenv("CONSUL_CONFIG_DIR")
	os.Setenv("CONSUL_CONFIG_DIR", "/nonexistent")
	defer os.Setenv("CONSUL_CONFIG_DIR", originalEnv)

	// Call getConsulDataDir on system without Consul installation
	// All layers should fail
	dataDir, err := getConsulDataDir(rc, consulClient, resetConfig)

	// Should return actionable error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Cannot determine Consul data directory")
	assert.Contains(t, err.Error(), "Specify data directory manually")
	assert.Contains(t, err.Error(), "eos update consul --bootstrap-token --data-dir")
	assert.Empty(t, dataDir)
}

// TestExtractResetIndex tests reset index extraction from error messages
func TestExtractResetIndex(t *testing.T) {
	tests := []struct {
		name          string
		errorMessage  string
		expectedIndex int
		expectError   bool
	}{
		{
			name:          "standard error format",
			errorMessage:  "Permission denied: ACL bootstrap no longer allowed (reset index: 3117)",
			expectedIndex: 3117,
			expectError:   false,
		},
		{
			name:          "alternative format",
			errorMessage:  "ACL bootstrap no longer allowed (reset index: 1)",
			expectedIndex: 1,
			expectError:   false,
		},
		{
			name:          "reset index with spaces",
			errorMessage:  "ACL bootstrap disabled (reset index:    42)",
			expectedIndex: 42,
			expectError:   false,
		},
		{
			name:         "no reset index in message",
			errorMessage: "ACL bootstrap is disabled",
			expectError:  true,
		},
		{
			name:         "empty message",
			errorMessage: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, err := extractResetIndex(tt.errorMessage)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedIndex, index)
			}
		})
	}
}

// TestCreateDataDirNotFoundError tests error message generation
func TestCreateDataDirNotFoundError(t *testing.T) {
	// Create sample errors
	errors := []error{
		assert.AnError,
		assert.AnError,
	}

	// Generate error
	err := createDataDirNotFoundError(errors)

	// Verify error message contains key elements
	assert.Error(t, err)
	errMsg := err.Error()

	// Should contain explanation
	assert.Contains(t, errMsg, "Cannot determine Consul data directory")

	// Should contain attempted methods
	assert.Contains(t, errMsg, "Attempted detection methods")

	// Should contain solutions
	assert.Contains(t, errMsg, "Solutions to try")
	assert.Contains(t, errMsg, "eos update consul --bootstrap-token --data-dir")

	// Should contain troubleshooting commands
	assert.Contains(t, errMsg, "grep data_dir")
	assert.Contains(t, errMsg, "ps aux | grep consul")
	assert.Contains(t, errMsg, "systemctl cat consul")
}

// TestCreateDataDirValidationError tests validation error message
func TestCreateDataDirValidationError(t *testing.T) {
	// Generate validation error
	err := createDataDirValidationError("/invalid/path", assert.AnError)

	// Verify error message
	assert.Error(t, err)
	errMsg := err.Error()

	// Should contain path
	assert.Contains(t, errMsg, "/invalid/path")

	// Should contain validation error
	assert.Contains(t, errMsg, "not valid")

	// Should contain requirements
	assert.Contains(t, errMsg, "Exist and be a directory")
	assert.Contains(t, errMsg, "raft/ subdirectory")

	// Should contain troubleshooting steps
	assert.Contains(t, errMsg, "grep data_dir")
}

// TestCreateAPIAccessError tests API access error formatting
func TestCreateAPIAccessError(t *testing.T) {
	// Generate API access error
	apiErr := assert.AnError
	err := createAPIAccessError(apiErr)

	// Verify error message
	assert.Error(t, err)
	errMsg := err.Error()

	// Should explain this is expected
	assert.Contains(t, errMsg, "expected when ACLs locked down")
	assert.Contains(t, errMsg, "normal during ACL bootstrap token recovery")
	assert.Contains(t, errMsg, "Continuing with alternative detection methods")
}

// Note: Full integration tests with real Consul instances are beyond the scope
// of unit tests and should be run in a separate integration test suite with
// actual Consul servers running.
