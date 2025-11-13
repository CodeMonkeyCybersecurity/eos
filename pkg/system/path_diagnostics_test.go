// pkg/system/path_diagnostics_test.go
package system

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathDiagnostics_FindDuplicates(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name:     "no duplicates",
			path:     "/usr/bin:/usr/local/bin:/home/user/bin",
			expected: []string{},
		},
		{
			name:     "with duplicates",
			path:     "/usr/bin:/usr/local/bin:/usr/bin:/home/user/bin",
			expected: []string{"/usr/bin"},
		},
		{
			name:     "multiple duplicates",
			path:     "/usr/bin:/usr/local/bin:/usr/bin:/usr/local/bin:/home/user/bin",
			expected: []string{"/usr/bin", "/usr/local/bin"},
		},
		{
			name:     "empty path",
			path:     "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := &PathDiagnostics{}
			info := &PathInfo{CurrentPath: tt.path}

			pd.findDuplicates(info)

			assert.Equal(t, tt.expected, info.DuplicateEntries)
		})
	}
}

func TestPathDiagnostics_AnalyzePath(t *testing.T) {
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")

	pd := NewPathDiagnostics(rc)
	require.NotNil(t, pd)

	info, err := pd.AnalyzePath()
	require.NoError(t, err)
	require.NotNil(t, info)

	// Basic checks
	assert.NotEmpty(t, info.CurrentPath)
	assert.NotNil(t, info.PathSources)
	assert.NotNil(t, info.ConfigFiles)
}

func TestPathDiagnostics_GenerateReport(t *testing.T) {
	pd := &PathDiagnostics{}
	info := &PathInfo{
		CurrentPath:      "/usr/bin:/usr/local/bin",
		LoginShellPath:   "/usr/bin:/usr/local/bin:/home/user/bin",
		PathSources:      map[string][]string{"/etc/profile": {"Line 1: export PATH=$PATH:/usr/local/bin"}},
		DuplicateEntries: []string{},
		SnapStatus:       "active",
		ConfigFiles:      map[string]string{"/etc/environment": "PATH=/usr/bin:/usr/local/bin"},
	}

	report := pd.GenerateReport(info)

	assert.Contains(t, report, "PATH Diagnostics Report")
	assert.Contains(t, report, "Current PATH:")
	assert.Contains(t, report, "Snap daemon status: active")
	assert.Contains(t, report, "PATH modifications found in:")
}

// Fuzz test example
func FuzzPathParsing(f *testing.F) {
	f.Add("/usr/bin:/usr/local/bin")
	f.Add("")
	f.Add(":::::")
	f.Add("/usr/bin")

	f.Fuzz(func(t *testing.T, path string) {
		pd := &PathDiagnostics{}
		info := &PathInfo{CurrentPath: path}

		// Should not panic
		pd.findDuplicates(info)

		// Result should be valid
		assert.NotNil(t, info.DuplicateEntries)
	})
}
