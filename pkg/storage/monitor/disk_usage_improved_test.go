package monitor

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockCommandRunner for testing
type MockCommandRunner struct {
	mock.Mock
}

func (m *MockCommandRunner) RunCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	arguments := m.Called(ctx, name, args)
	return arguments.Get(0).([]byte), arguments.Error(1)
}

// TestSystemDiskChecker_CheckDiskUsage demonstrates table-driven tests
func TestSystemDiskChecker_CheckDiskUsage(t *testing.T) {
	tests := []struct {
		name        string
		paths       []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty paths defaults to root",
			paths:       []string{},
			expectError: false,
		},
		{
			name:        "single valid path",
			paths:       []string{"/tmp"},
			expectError: false,
		},
		{
			name:        "multiple paths",
			paths:       []string{"/tmp", "/var"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewSystemDiskChecker()
			ctx := context.Background()

			result, err := checker.CheckDiskUsage(ctx, tt.paths)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)

				expectedPaths := tt.paths
				if len(expectedPaths) == 0 {
					expectedPaths = []string{"/"}
				}
				assert.Len(t, result, len(expectedPaths))
			}
		})
	}
}

// TestSystemDiskChecker_MonitorDiskUsage demonstrates mock usage and error scenarios
func TestSystemDiskChecker_MonitorDiskUsage(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		checker := NewSystemDiskChecker()
		ctx := context.Background()

		result, err := checker.MonitorDiskUsage(ctx, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "monitor config cannot be nil")
		assert.Nil(t, result)
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		checker := NewSystemDiskChecker()
		ctx := context.Background()

		config := &MonitorConfig{
			DiskUsageWarning:  90.0, // Higher than critical
			DiskUsageCritical: 80.0,
		}

		result, err := checker.MonitorDiskUsage(ctx, config)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "warning threshold")
		assert.Nil(t, result)
	})

	t.Run("context cancellation", func(t *testing.T) {
		checker := NewSystemDiskChecker()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		config := &MonitorConfig{
			DiskUsageWarning:  70.0,
			DiskUsageCritical: 80.0,
			MonitorPaths:      []string{"/tmp"},
		}

		result, err := checker.MonitorDiskUsage(ctx, config)

		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
		assert.NotNil(t, result) // Should return partial results
	})
}

// TestSystemDiskChecker_FindLargeDirectories demonstrates mocking external commands
func TestSystemDiskChecker_FindLargeDirectories(t *testing.T) {
	t.Run("successful directory analysis", func(t *testing.T) {
		mockRunner := new(MockCommandRunner)
		checker := &SystemDiskChecker{commandRunner: mockRunner}

		duOutput := `1000000	/tmp/dir1
500000	/tmp/dir2
250000	/tmp/dir3
`
		mockRunner.On("RunCommand", mock.Anything, "du", mock.Anything).
			Return([]byte(duOutput), nil)

		ctx := context.Background()
		result, err := checker.FindLargeDirectories(ctx, "/tmp", 2)

		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, "/tmp/dir1", result[0].Path)
		assert.Equal(t, int64(1000000), result[0].Size)
		assert.Equal(t, "/tmp/dir2", result[1].Path)
		assert.Equal(t, int64(500000), result[1].Size)

		mockRunner.AssertExpectations(t)
	})

	t.Run("command failure", func(t *testing.T) {
		mockRunner := new(MockCommandRunner)
		checker := &SystemDiskChecker{commandRunner: mockRunner}

		mockRunner.On("RunCommand", mock.Anything, "du", mock.Anything).
			Return([]byte{}, errors.New("command failed"))

		ctx := context.Background()
		result, err := checker.FindLargeDirectories(ctx, "/tmp", 5)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to run du command")
		assert.Nil(t, result)

		mockRunner.AssertExpectations(t)
	})

	t.Run("invalid parameters", func(t *testing.T) {
		checker := NewSystemDiskChecker()
		ctx := context.Background()

		result, err := checker.FindLargeDirectories(ctx, "/tmp", 0)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "topN must be positive")
		assert.Nil(t, result)
	})
}

// TestValidateConfig demonstrates comprehensive validation testing
func TestValidateConfig(t *testing.T) {
	checker := NewSystemDiskChecker()

	tests := []struct {
		name        string
		config      *MonitorConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &MonitorConfig{
				DiskUsageWarning:  70.0,
				DiskUsageCritical: 80.0,
			},
			expectError: false,
		},
		{
			name: "negative warning threshold",
			config: &MonitorConfig{
				DiskUsageWarning:  -10.0,
				DiskUsageCritical: 80.0,
			},
			expectError: true,
			errorMsg:    "disk usage warning threshold must be 0-100",
		},
		{
			name: "warning >= critical",
			config: &MonitorConfig{
				DiskUsageWarning:  80.0,
				DiskUsageCritical: 80.0,
			},
			expectError: true,
			errorMsg:    "warning threshold",
		},
		{
			name: "threshold over 100",
			config: &MonitorConfig{
				DiskUsageWarning:  70.0,
				DiskUsageCritical: 150.0,
			},
			expectError: true,
			errorMsg:    "disk usage critical threshold must be 0-100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checker.validateConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGenerateAlertsForUsage demonstrates alert generation logic
func TestGenerateAlertsForUsage(t *testing.T) {
	checker := NewSystemDiskChecker()
	config := &MonitorConfig{
		DiskUsageWarning:  70.0,
		DiskUsageCritical: 80.0,
	}

	tests := []struct {
		name             string
		usage            *DiskUsage
		expectedAlerts   int
		expectedSeverity AlertSeverity
	}{
		{
			name: "usage below warning",
			usage: &DiskUsage{
				Path:              "/test",
				UsedPercent:       50.0,
				InodesUsedPercent: 50.0,
			},
			expectedAlerts: 0,
		},
		{
			name: "usage at warning level",
			usage: &DiskUsage{
				Path:              "/test",
				UsedPercent:       75.0,
				InodesUsedPercent: 50.0,
			},
			expectedAlerts:   1,
			expectedSeverity: AlertSeverityWarning,
		},
		{
			name: "usage at critical level",
			usage: &DiskUsage{
				Path:              "/test",
				UsedPercent:       85.0,
				InodesUsedPercent: 50.0,
			},
			expectedAlerts:   1,
			expectedSeverity: AlertSeverityCritical,
		},
		{
			name: "high inode usage",
			usage: &DiskUsage{
				Path:              "/test",
				UsedPercent:       50.0,
				InodesUsedPercent: 95.0,
			},
			expectedAlerts:   1,
			expectedSeverity: AlertSeverityCritical,
		},
		{
			name: "both disk and inode critical",
			usage: &DiskUsage{
				Path:              "/test",
				UsedPercent:       85.0,
				InodesUsedPercent: 95.0,
			},
			expectedAlerts: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alerts := checker.generateAlertsForUsage(tt.usage, config)

			assert.Len(t, alerts, tt.expectedAlerts)

			if tt.expectedAlerts > 0 && tt.expectedSeverity != "" {
				assert.Equal(t, tt.expectedSeverity, alerts[0].Severity)
				assert.Equal(t, tt.usage.Path, alerts[0].Path)
				assert.NotEmpty(t, alerts[0].Message)
				assert.NotEmpty(t, alerts[0].ID)
			}
		})
	}
}

// TestParseDuOutput demonstrates parsing logic testing
func TestParseDuOutput(t *testing.T) {
	checker := NewSystemDiskChecker()

	tests := []struct {
		name     string
		output   string
		rootPath string
		topN     int
		expected []DirectoryInfo
	}{
		{
			name: "normal output",
			output: `1000000	/tmp/large
500000	/tmp/medium
100000	/tmp/small
50000	/tmp
`,
			rootPath: "/tmp",
			topN:     2,
			expected: []DirectoryInfo{
				{Path: "/tmp/large", Size: 1000000},
				{Path: "/tmp/medium", Size: 500000},
			},
		},
		{
			name:     "empty output",
			output:   "",
			rootPath: "/tmp",
			topN:     5,
			expected: []DirectoryInfo{},
		},
		{
			name: "malformed lines ignored",
			output: `1000000	/tmp/valid
invalid_line
500000	/tmp/another
`,
			rootPath: "/tmp",
			topN:     5,
			expected: []DirectoryInfo{
				{Path: "/tmp/valid", Size: 1000000},
				{Path: "/tmp/another", Size: 500000},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checker.parseDuOutput(tt.output, tt.rootPath, tt.topN)

			require.NoError(t, err)
			assert.Len(t, result, len(tt.expected))

			for i, expected := range tt.expected {
				if i < len(result) {
					assert.Equal(t, expected.Path, result[i].Path)
					assert.Equal(t, expected.Size, result[i].Size)
				}
			}
		})
	}
}

// BenchmarkCheckDiskUsage demonstrates performance testing
func BenchmarkCheckDiskUsage(b *testing.B) {
	checker := NewSystemDiskChecker()
	ctx := context.Background()
	paths := []string{"/tmp"}

	b.ResetTimer()
	for b.Loop() {
		_, err := checker.CheckDiskUsage(ctx, paths)
		if err != nil {
			b.Fatalf("CheckDiskUsage failed: %v", err)
		}
	}
}

// TestConcurrentAccess demonstrates race condition testing
func TestConcurrentAccess(t *testing.T) {
	checker := NewSystemDiskChecker()
	ctx := context.Background()
	paths := []string{"/tmp"}

	// Run multiple goroutines concurrently
	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			_, err := checker.CheckDiskUsage(ctx, paths)
			done <- err
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-done
		assert.NoError(t, err)
	}
}

// TestTimeoutHandling demonstrates timeout testing
func TestTimeoutHandling(t *testing.T) {
	mockRunner := new(MockCommandRunner)
	checker := &SystemDiskChecker{commandRunner: mockRunner}

	// Mock a command that takes too long
	mockRunner.On("RunCommand", mock.Anything, "du", mock.Anything).
		Run(func(args mock.Arguments) {
			ctx := args.Get(0).(context.Context)
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				return
			}
		}).
		Return([]byte{}, context.DeadlineExceeded)

	// Create a context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result, err := checker.FindLargeDirectories(ctx, "/tmp", 5)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to run du command")
	assert.Nil(t, result)

	mockRunner.AssertExpectations(t)
}

// Example test demonstrates how to write example tests
func ExampleSystemDiskChecker_CheckDiskUsage() {
	checker := NewSystemDiskChecker()
	ctx := context.Background()

	usage, err := checker.CheckDiskUsage(ctx, []string{"/tmp"})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	for _, u := range usage {
		fmt.Printf("Path: %s, Usage: %.1f%%\n", u.Path, u.UsedPercent)
	}
	// Output will vary based on actual disk usage
}
