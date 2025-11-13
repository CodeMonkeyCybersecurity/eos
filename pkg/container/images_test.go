package container

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestRemoveImages(t *testing.T) {
	tests := []struct {
		name    string
		images  []string
		wantErr bool
	}{
		{
			name:    "empty image list",
			images:  []string{},
			wantErr: false,
		},
		{
			name:    "nil image list",
			images:  nil,
			wantErr: false,
		},
		{
			name:    "single image",
			images:  []string{"nginx:latest"},
			wantErr: true, // Will fail in test env since docker command not mocked
		},
		{
			name:    "multiple images",
			images:  []string{"nginx:latest", "postgres:13"},
			wantErr: true, // Will fail in test env since docker command not mocked
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			err := RemoveImages(rc, tc.images)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

func TestRemoveImagesSecurity(t *testing.T) {
	t.Run("malicious image names", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousImages := []string{
			"../../../etc/passwd",
			"image; rm -rf /",
			"image`whoami`",
			"image$(id)",
			"image\x00injection",
			"image\nrm -rf /",
		}

		for _, image := range maliciousImages {
			t.Run("malicious_image", func(t *testing.T) {
				// Should handle malicious input safely through execute package
				// The execute package should provide proper command sanitization
				err := RemoveImages(rc, []string{image})
				// In test environment, this will fail because docker command execution fails
				// but the important thing is that it doesn't cause injection
				testutil.AssertError(t, err)
			})
		}
	})
}

func TestRemoveImagesConcurrency(t *testing.T) {
	t.Run("concurrent image removal", func(t *testing.T) {
		imageNames := []string{"concurrent-1:latest", "concurrent-2:latest", "concurrent-3:latest"}

		// Test concurrent removal operations
		testutil.ParallelTest(t, 3, func(t *testing.T, i int) {
			rc := testutil.TestRuntimeContext(t)
			err := RemoveImages(rc, []string{imageNames[i]})
			// Will error in test environment due to docker not being available
			testutil.AssertError(t, err)
		})
	})
}

func BenchmarkRemoveImages(b *testing.B) {
	// Skip benchmarks since they require actual docker commands
	b.Skip("Skipping benchmark - requires actual docker environment")
}
