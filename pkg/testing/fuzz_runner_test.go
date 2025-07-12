// pkg/testing/fuzz_runner_test.go
package testing

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFuzzRunner_DiscoverFuzzTests(t *testing.T) {
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")

	runner, err := NewFuzzRunner(rc)
	require.NoError(t, err)
	require.NotNil(t, runner)

	tests, err := runner.DiscoverFuzzTests()
	require.NoError(t, err)

	// Should discover multiple test packages
	assert.Greater(t, len(tests), 0)

	// Check that we have tests for expected packages
	packages := make(map[string]bool)
	for _, test := range tests {
		packages[test.Package] = true
	}

	expectedPackages := []string{
		"./pkg/crypto",
		"./pkg/interaction",
		"./pkg/parse",
	}

	for _, pkg := range expectedPackages {
		assert.True(t, packages[pkg], "Expected package %s not found", pkg)
	}
}

func TestFuzzRunner_CountCrashes(t *testing.T) {
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")

	runner, err := NewFuzzRunner(rc)
	require.NoError(t, err)

	tests := []struct {
		name     string
		output   string
		expected int
	}{
		{
			name:     "no crashes",
			output:   "test completed successfully",
			expected: 0,
		},
		{
			name:     "single crash",
			output:   "test failed with crash",
			expected: 1,
		},
		{
			name:     "multiple crashes",
			output:   "crash detected\nanother crash found\ncrash in function",
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runner.countCrashes(tt.output)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFuzzReport_Summary(t *testing.T) {
	report := &FuzzReport{
		StartTime: time.Now().Add(-time.Minute),
		EndTime:   time.Now(),
		Duration:  time.Minute,
		Tests: []FuzzResult{
			{
				Test:    FuzzTest{Name: "test1"},
				Success: true,
			},
			{
				Test:    FuzzTest{Name: "test2"},
				Success: false,
				Crashes: 1,
			},
		},
	}

	summary := report.Summary()

	assert.Contains(t, summary, "Total Tests: 2")
	assert.Contains(t, summary, "Passed: 1")
	assert.Contains(t, summary, "Failed: 1")
	assert.Contains(t, summary, "Total Crashes: 1")
	assert.Contains(t, summary, "test2")
}

func TestFuzzRunner_SetParallelism(t *testing.T) {
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")

	runner, err := NewFuzzRunner(rc)
	require.NoError(t, err)

	// Test setting valid parallelism
	runner.SetParallelism(8)
	assert.Equal(t, 8, runner.parallel)

	// Test setting invalid parallelism (should be ignored)
	runner.SetParallelism(0)
	assert.Equal(t, 8, runner.parallel) // Should remain unchanged

	runner.SetParallelism(-1)
	assert.Equal(t, 8, runner.parallel) // Should remain unchanged
}

// Fuzz test for crash counting
func FuzzCountCrashes(f *testing.F) {
	f.Add("no crashes here")
	f.Add("crash detected")
	f.Add("crash\ncrash\ncrash")
	f.Add("")

	f.Fuzz(func(t *testing.T, output string) {
		ctx := context.Background()
		rc := eos_io.NewContext(ctx, "test")

		runner, err := NewFuzzRunner(rc)
		require.NoError(t, err)

		// Should not panic
		result := runner.countCrashes(output)

		// Result should be non-negative
		assert.GreaterOrEqual(t, result, 0)
	})
}
