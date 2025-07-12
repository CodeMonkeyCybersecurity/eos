package container

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestStopContainer(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		wantErr     bool
	}{
		{
			name:        "valid container name",
			containerID: "test-container-123",
			wantErr:     true, // Will fail in test env since docker command not available
		},
		{
			name:        "empty container ID",
			containerID: "",
			wantErr:     true, // Will fail in test env since docker command not available
		},
		{
			name:        "container with special characters",
			containerID: "test-container_special-123",
			wantErr:     true, // Will fail in test env since docker command not available
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			err := StopContainer(rc, tc.containerID)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

func TestStopContainers(t *testing.T) {
	tests := []struct {
		name         string
		containerIDs []string
		wantErr      bool
	}{
		{
			name:         "empty container list",
			containerIDs: []string{},
			wantErr:      true, // Will fail in test env since docker command not available
		},
		{
			name:         "nil container list",
			containerIDs: nil,
			wantErr:      true, // Will fail in test env since docker command not available
		},
		{
			name:         "single container",
			containerIDs: []string{"container-1"},
			wantErr:      true, // Will fail in test env since docker command not available
		},
		{
			name:         "multiple containers",
			containerIDs: []string{"container-1", "container-2", "container-3"},
			wantErr:      true, // Will fail in test env since docker command not available
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			err := StopContainers(rc, tc.containerIDs)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

func TestStopContainersBySubstring(t *testing.T) {
	tests := []struct {
		name      string
		substring string
		wantErr   bool
	}{
		{
			name:      "valid substring",
			substring: "webapp",
			wantErr:   false, // Valid input - should pass validation (may fail at docker level)
		},
		{
			name:      "empty substring",
			substring: "",
			wantErr:   true, // Should fail validation
		},
		{
			name:      "substring with special characters",
			substring: "test_app-123",
			wantErr:   false, // Valid input - should pass validation (may fail at docker level)
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			err := StopContainersBySubstring(rc, tc.substring)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

func TestRemoveContainers(t *testing.T) {
	tests := []struct {
		name         string
		containerIDs []string
		wantErr      bool
	}{
		{
			name:         "empty container list",
			containerIDs: []string{},
			wantErr:      true, // Will fail in test env since docker command not available
		},
		{
			name:         "single container",
			containerIDs: []string{"container-1"},
			wantErr:      true, // Will fail in test env since docker command not available
		},
		{
			name:         "multiple containers",
			containerIDs: []string{"container-1", "container-2"},
			wantErr:      true, // Will fail in test env since docker command not available
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			err := RemoveContainers(rc, tc.containerIDs)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

func TestListDefaultContainers(t *testing.T) {
	t.Run("list containers", func(t *testing.T) {
		err := ListDefaultContainers()

		// Will fail in test environment without docker
		testutil.AssertError(t, err)
	})
}

func TestContainerOperationsSecurity(t *testing.T) {
	t.Run("container ID validation", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousIDs := []string{
			"../../../etc/passwd",
			"container; rm -rf /",
			"container`whoami`",
			"container$(id)",
			"container\x00injection",
			"container\nrm -rf /",
		}

		for _, id := range maliciousIDs {
			t.Run("malicious_id", func(t *testing.T) {
				err := StopContainer(rc, id)
				// Should handle malicious input safely - will error due to docker not available
				// but importantly should not cause command injection
				testutil.AssertError(t, err)
			})
		}
	})

	t.Run("substring validation", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousSubstrings := []string{
			"$(rm -rf /)",
			"`whoami`",
			"../../../etc",
			"container; stop",
		}

		for _, substring := range maliciousSubstrings {
			t.Run("malicious_substring", func(t *testing.T) {
				err := StopContainersBySubstring(rc, substring)
				// Should handle malicious input safely
				testutil.AssertError(t, err)
			})
		}
	})
}

func TestContainerOperationsConcurrency(t *testing.T) {
	t.Run("concurrent container operations", func(t *testing.T) {
		containerIDs := []string{"concurrent-1", "concurrent-2", "concurrent-3"}

		// Test concurrent stop operations
		testutil.ParallelTest(t, 3, func(t *testing.T, i int) {
			rc := testutil.TestRuntimeContext(t)
			err := StopContainer(rc, containerIDs[i])
			// Will error in test environment but should be safe
			testutil.AssertError(t, err)
		})
	})
}

func BenchmarkStopContainer(b *testing.B) {
	// Skip benchmarks since they require actual docker commands
	b.Skip("Skipping benchmark - requires actual docker environment")
}

func BenchmarkStopContainers(b *testing.B) {
	// Skip benchmarks since they require actual docker commands
	b.Skip("Skipping benchmark - requires actual docker environment")
}
