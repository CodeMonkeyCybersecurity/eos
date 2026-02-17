// Platform compatibility tests for CephFS
// Verifies that stubs work correctly on unsupported platforms
// and that build tags are properly applied
package cephfs

import (
	"runtime"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlatformStubBehavior verifies that platform stubs return appropriate errors
func TestPlatformStubBehavior(t *testing.T) {
	rc := testutil.TestContext(t)

	// Test NewCephClient stub behavior
	t.Run("NewCephClient_returns_platform_error_on_unsupported_platform", func(t *testing.T) {
		config := &ClientConfig{
			ClusterName: "ceph",
			User:        "admin",
			MonHosts:    []string{"10.0.0.1"},
		}

		client, err := NewCephClient(rc, config)

		if runtime.GOOS == "darwin" {
			// On macOS, should return error
			require.Error(t, err)
			assert.Nil(t, client)
			assert.Contains(t, err.Error(), "not available on macOS",
				"Error should mention macOS limitation")
			assert.Contains(t, err.Error(), "deploy to Linux",
				"Error should suggest deployment to Linux")
		} else {
			// On Linux, might succeed or fail based on Ceph availability
			// but should not return platform-specific error
			if err != nil {
				assert.NotContains(t, err.Error(), "not available on macOS",
					"Linux should not return macOS-specific error")
			}
		}
	})

	// Test Install stub behavior
	t.Run("Install_returns_platform_error_on_unsupported_platform", func(t *testing.T) {
		config := &Config{
			Name:           "test-volume",
			AdminHost:      "10.0.0.1",
			PublicNetwork:  "10.0.0.0/24",
			ClusterNetwork: "10.1.0.0/24",
		}

		err := Install(rc, config)

		if runtime.GOOS == "darwin" {
			// On macOS, should return error
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not available on macOS",
				"Error should mention macOS limitation")
			assert.Contains(t, err.Error(), "deploy to Ubuntu Linux",
				"Error should suggest deployment to Ubuntu Linux")
		} else {
			// On Linux, might succeed or fail based on Ceph availability
			// but should not return platform-specific error
			if err != nil {
				assert.NotContains(t, err.Error(), "not available on macOS",
					"Linux should not return macOS-specific error")
			}
		}
	})

	// Test CreateVolume stub behavior
	t.Run("CreateVolume_returns_platform_error_on_unsupported_platform", func(t *testing.T) {
		config := &Config{
			Name:            "test-volume",
			ReplicationSize: 3,
			PGNum:           128,
		}

		err := CreateVolume(rc, config)

		if runtime.GOOS == "darwin" {
			// On macOS, should return error
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not available on macOS",
				"Error should mention macOS limitation")
		} else {
			// On Linux, might succeed or fail based on Ceph availability
			// but should not return platform-specific error
			if err != nil {
				assert.NotContains(t, err.Error(), "not available on macOS",
					"Linux should not return macOS-specific error")
			}
		}
	})

	// Test CreateMountPoint stub behavior
	t.Run("CreateMountPoint_returns_platform_error_on_unsupported_platform", func(t *testing.T) {
		config := &Config{
			Name:       "test-volume",
			MountPoint: "/mnt/cephfs",
		}

		err := CreateMountPoint(rc, config)

		if runtime.GOOS == "darwin" {
			// On macOS, should return error
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not available on macOS",
				"Error should mention macOS limitation")
		}
	})

}

// TestValidateConfig_CrossPlatform verifies validation works on all platforms
func TestValidateConfig_CrossPlatform(t *testing.T) {
	// This test should pass on ALL platforms (including macOS)
	// because ValidateConfig is available everywhere for testing

	tests := []struct {
		name      string
		config    *Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid_config",
			config: &Config{
				Name:            "test-volume",
				ReplicationSize: 3,
				PGNum:           128,
			},
			expectErr: false,
		},
		{
			name: "missing_name",
			config: &Config{
				ReplicationSize: 3,
				PGNum:           128,
			},
			expectErr: true,
			errMsg:    "name is required",
		},
		{
			name: "invalid_replication_negative",
			config: &Config{
				Name:            "test",
				ReplicationSize: -1,
				PGNum:           128,
			},
			expectErr: true,
			errMsg:    "replication size",
		},
		{
			name: "invalid_replication_too_large",
			config: &Config{
				Name:            "test",
				ReplicationSize: 11,
				PGNum:           128,
			},
			expectErr: true,
			errMsg:    "replication size",
		},
		{
			name: "invalid_pg_num_negative",
			config: &Config{
				Name:            "test",
				ReplicationSize: 3,
				PGNum:           -1,
			},
			expectErr: true,
			errMsg:    "PG number",
		},
		{
			name: "invalid_pg_num_too_large",
			config: &Config{
				Name:            "test",
				ReplicationSize: 3,
				PGNum:           40000,
			},
			expectErr: true,
			errMsg:    "PG number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, strings.ToLower(err.Error()),
						strings.ToLower(tt.errMsg))
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestBuildMountArgs_CrossPlatform verifies mount args building
func TestBuildMountArgs_CrossPlatform(t *testing.T) {
	config := &Config{
		Name:         "test-volume",
		MountPoint:   "/mnt/cephfs",
		MonitorHosts: []string{"10.0.0.1", "10.0.0.2"},
	}

	args := BuildMountArgs(config)

	if runtime.GOOS == "darwin" {
		// On macOS, should return empty slice since mounting is not supported
		assert.Empty(t, args, "BuildMountArgs should return empty slice on macOS")
	} else {
		// On Linux, should return actual mount arguments
		// (might be empty if not implemented, but shouldn't fail)
		t.Logf("Mount args on Linux: %v", args)
	}
}

// TestShouldPersistMount_CrossPlatform verifies mount persistence logic
func TestShouldPersistMount_CrossPlatform(t *testing.T) {
	config := &Config{
		Name:         "test-volume",
		MountPoint:   "/mnt/cephfs",
		MountOptions: []string{"_netdev"},
	}

	shouldPersist := ShouldPersistMount(config)

	if runtime.GOOS == "darwin" {
		// On macOS, should always return false since mounting is not supported
		assert.False(t, shouldPersist,
			"ShouldPersistMount should return false on macOS")
	} else {
		// On Linux, should respect the config
		t.Logf("Should persist mount on Linux: %v", shouldPersist)
	}
}

// TestPlatformDetection verifies build tag correctness
func TestPlatformDetection(t *testing.T) {
	t.Run("runtime_GOOS_matches_build_tags", func(t *testing.T) {
		// This test verifies that the compiled code matches the runtime platform
		// If build tags are correct:
		// - On macOS (darwin): stubs should be compiled
		// - On Linux: real implementations should be compiled

		goos := runtime.GOOS
		t.Logf("Running on platform: %s", goos)

		// Try to create a client and verify error message matches platform
		config := &ClientConfig{
			ClusterName: "test",
			User:        "admin",
			MonHosts:    []string{"10.0.0.1"},
		}

		rc := testutil.TestContext(t)
		_, err := NewCephClient(rc, config)

		if goos == "darwin" {
			// On macOS, MUST return platform error
			require.Error(t, err, "macOS should return error from stub")
			assert.Contains(t, err.Error(), "macOS",
				"macOS error should mention the platform")
		}
		// On Linux, might succeed or fail for other reasons
	})
}

// TestStubDocumentation verifies stub functions have clear error messages
func TestStubDocumentation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("This test only runs on macOS to verify stub error messages")
	}

	rc := testutil.TestContext(t)

	// All stub errors should:
	// 1. Mention the platform limitation (macOS)
	// 2. Suggest deploying to Linux
	// 3. Be user-friendly (not technical jargon)

	t.Run("error_messages_are_user_friendly", func(t *testing.T) {
		config := &Config{
			Name:           "test",
			AdminHost:      "10.0.0.1",
			PublicNetwork:  "10.0.0.0/24",
			ClusterNetwork: "10.1.0.0/24",
		}

		err := Install(rc, config)
		require.Error(t, err)

		errMsg := err.Error()

		// Should mention limitation
		assert.True(t,
			strings.Contains(errMsg, "not available") ||
				strings.Contains(errMsg, "not supported"),
			"Error should mention feature is not available")

		// Should mention macOS
		assert.Contains(t, strings.ToLower(errMsg), "macos",
			"Error should mention macOS")

		// Should suggest solution
		assert.Contains(t, strings.ToLower(errMsg), "linux",
			"Error should suggest deploying to Linux")
	})
}
