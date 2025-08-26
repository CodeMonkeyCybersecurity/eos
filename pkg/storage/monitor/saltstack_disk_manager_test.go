// pkg/storage_monitor/saltstack_disk_manager_test.go

package monitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockSaltStackClient implements saltstack.ClientInterface for testing
type MockSaltStackClient struct {
	mock.Mock
}

func (m *MockSaltStackClient) StateApply(ctx context.Context, target string, state string, pillar map[string]interface{}) error {
	args := m.Called(ctx, target, state, pillar)
	return args.Error(0)
}

func (m *MockSaltStackClient) TestPing(ctx context.Context, target string) (bool, error) {
	args := m.Called(ctx, target)
	return args.Bool(0), args.Error(1)
}

func (m *MockSaltStackClient) GrainGet(ctx context.Context, target string, grain string) (map[string]interface{}, error) {
	args := m.Called(ctx, target, grain)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockSaltStackClient) CmdRun(ctx context.Context, target string, command string) (string, error) {
	args := m.Called(ctx, target, command)
	return args.String(0), args.Error(1)
}

func (m *MockSaltStackClient) CheckMinion(ctx context.Context, minion string) (bool, error) {
	args := m.Called(ctx, minion)
	return args.Bool(0), args.Error(1)
}

func (m *MockSaltStackClient) IsAPIAvailable(ctx context.Context) bool {
	args := m.Called(ctx)
	return args.Bool(0)
}

func setupTestDiskManager(t *testing.T) (*SaltStackDiskManager, *MockSaltStackClient) {
	mockClient := &MockSaltStackClient{}

	ctx := context.Background()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	manager := NewSaltStackDiskManager(mockClient, rc)
	return manager, mockClient
}

func setupBenchmarkDiskManager(b *testing.B) (*SaltStackDiskManager, *MockSaltStackClient) {
	mockClient := &MockSaltStackClient{}

	ctx := context.Background()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	manager := NewSaltStackDiskManager(mockClient, rc)
	return manager, mockClient
}

func TestNewSaltStackDiskManager(t *testing.T) {
	manager, _ := setupTestDiskManager(t)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.client)
	assert.NotNil(t, manager.logger)
	assert.NotNil(t, manager.rc)
}

func TestGetDiskUsage(t *testing.T) {
	tests := []struct {
		name           string
		target         string
		path           string
		mockResponse   string
		mockError      error
		expectedResult *DiskUsage
		expectedError  string
	}{
		{
			name:   "successful disk usage retrieval",
			target: "test-minion",
			path:   "/var",
			mockResponse: `{
				"total": 1073741824,
				"used": 536870912,
				"available": 536870912,
				"percent": 50.0
			}`,
			expectedResult: &DiskUsage{
				Path:          "/var",
				TotalSize:     1073741824,
				UsedSize:      536870912,
				AvailableSize: 536870912,
				UsedPercent:   50.0,
			},
		},
		{
			name:          "salt command error",
			target:        "test-minion",
			path:          "/var",
			mockError:     fmt.Errorf("salt command failed"),
			expectedError: "failed to get disk usage for /var",
		},
		{
			name:          "invalid JSON response",
			target:        "test-minion",
			path:          "/var",
			mockResponse:  "invalid json",
			expectedError: "failed to parse disk usage result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, mockClient := setupTestDiskManager(t)
			ctx := context.Background()

			expectedCmd := fmt.Sprintf("disk.usage %s", tt.path)
			mockClient.On("CmdRun", ctx, tt.target, expectedCmd).Return(tt.mockResponse, tt.mockError)

			result, err := manager.GetDiskUsage(ctx, tt.target, tt.path)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedResult.Path, result.Path)
				assert.Equal(t, tt.expectedResult.TotalSize, result.TotalSize)
				assert.Equal(t, tt.expectedResult.UsedSize, result.UsedSize)
				assert.Equal(t, tt.expectedResult.AvailableSize, result.AvailableSize)
				assert.Equal(t, tt.expectedResult.UsedPercent, result.UsedPercent)
				assert.WithinDuration(t, time.Now(), result.Timestamp, time.Second)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestGetAllDiskUsage(t *testing.T) {
	manager, mockClient := setupTestDiskManager(t)
	ctx := context.Background()
	target := "test-minion"

	// Mock mount points response
	mountResponse := `{
		"/": {
			"device": "/dev/sda1",
			"fstype": "ext4",
			"opts": ["rw", "relatime"]
		},
		"/var": {
			"device": "/dev/sda2",
			"fstype": "ext4",
			"opts": ["rw", "relatime"]
		}
	}`

	// Mock disk usage responses
	rootUsageResponse := `{
		"total": 2147483648,
		"used": 1073741824,
		"available": 1073741824,
		"percent": 50.0
	}`

	varUsageResponse := `{
		"total": 1073741824,
		"used": 536870912,
		"available": 536870912,
		"percent": 50.0
	}`

	mockClient.On("CmdRun", ctx, target, "mount.active").Return(mountResponse, nil)
	mockClient.On("CmdRun", ctx, target, "disk.usage /").Return(rootUsageResponse, nil)
	mockClient.On("CmdRun", ctx, target, "disk.usage /var").Return(varUsageResponse, nil)

	result, err := manager.GetAllDiskUsage(ctx, target)

	require.NoError(t, err)
	assert.Len(t, result, 2)

	// Verify root filesystem
	rootUsage := findUsageByPath(result, "/")
	require.NotNil(t, rootUsage)
	assert.Equal(t, int64(2147483648), rootUsage.TotalSize)

	// Verify var filesystem
	varUsage := findUsageByPath(result, "/var")
	require.NotNil(t, varUsage)
	assert.Equal(t, int64(1073741824), varUsage.TotalSize)

	mockClient.AssertExpectations(t)
}

func TestCleanupTempFiles(t *testing.T) {
	tests := []struct {
		name           string
		options        CleanupOptions
		mockError      error
		expectedState  string
		expectedResult *DiskCleanupResult
	}{
		{
			name: "successful cleanup",
			options: CleanupOptions{
				TempDirs:     []string{"/tmp", "/var/tmp"},
				MaxAge:       24 * time.Hour,
				MinFreeSpace: 1024 * 1024 * 1024, // 1GB
				DryRun:       false,
			},
			expectedState: "disk.cleanup",
		},
		{
			name: "dry run cleanup",
			options: CleanupOptions{
				TempDirs: []string{"/tmp"},
				DryRun:   true,
			},
			expectedState: "disk.cleanup_dry_run",
		},
		{
			name: "cleanup with error",
			options: CleanupOptions{
				TempDirs: []string{"/tmp"},
			},
			mockError:     fmt.Errorf("cleanup failed"),
			expectedState: "disk.cleanup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, mockClient := setupTestDiskManager(t)
			ctx := context.Background()
			target := "test-minion"

			expectedPillar := map[string]interface{}{
				"cleanup_options": tt.options,
			}

			mockClient.On("StateApply", ctx, target, tt.expectedState, expectedPillar).Return(tt.mockError)

			if tt.mockError == nil {
				// Mock successful result retrieval
				resultResponse := `{
					"freed_bytes": 1048576,
					"files_removed": 100,
					"dirs_removed": 5
				}`
				mockClient.On("CmdRun", ctx, target, "grains.get cleanup_result").Return(resultResponse, nil)
			}

			result, err := manager.CleanupTempFiles(ctx, target, tt.options)

			if tt.mockError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to apply cleanup state")
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Greater(t, result.Duration, time.Duration(0))
				assert.WithinDuration(t, time.Now(), result.Timestamp, time.Second)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestMountDevice(t *testing.T) {
	manager, mockClient := setupTestDiskManager(t)
	ctx := context.Background()
	target := "test-minion"
	device := "/dev/sdb1"
	mountPoint := "/mnt/data"
	fsType := "ext4"
	options := []string{"rw", "relatime"}

	expectedPillar := map[string]interface{}{
		"device":      device,
		"mount_point": mountPoint,
		"fs_type":     fsType,
		"options":     options,
	}

	mockClient.On("StateApply", ctx, target, "disk.mount", expectedPillar).Return(nil)

	err := manager.MountDevice(ctx, target, device, mountPoint, fsType, options)

	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestUnmountDevice(t *testing.T) {
	manager, mockClient := setupTestDiskManager(t)
	ctx := context.Background()
	target := "test-minion"
	mountPoint := "/mnt/data"
	force := true

	expectedPillar := map[string]interface{}{
		"mount_point": mountPoint,
		"force":       force,
	}

	mockClient.On("StateApply", ctx, target, "disk.unmount", expectedPillar).Return(nil)

	err := manager.UnmountDevice(ctx, target, mountPoint, force)

	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestGetSMARTData(t *testing.T) {
	manager, mockClient := setupTestDiskManager(t)
	ctx := context.Background()
	target := "test-minion"
	device := "/dev/sda"

	smartResponse := `{
		"model": "Samsung SSD 970 EVO",
		"serial": "S466NX0M123456",
		"health": "PASSED"
	}`

	expectedCmd := fmt.Sprintf("disk.smart_attributes %s", device)
	mockClient.On("CmdRun", ctx, target, expectedCmd).Return(smartResponse, nil)

	result, err := manager.GetSMARTData(ctx, target, device)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, device, result.Device)
	assert.Equal(t, "Samsung SSD 970 EVO", result.Model)
	assert.Equal(t, "S466NX0M123456", result.SerialNumber)
	assert.Equal(t, "PASSED", result.OverallHealth)
	assert.WithinDuration(t, time.Now(), result.Timestamp, time.Second)

	mockClient.AssertExpectations(t)
}

func TestCheckDiskHealth(t *testing.T) {
	manager, mockClient := setupTestDiskManager(t)
	ctx := context.Background()
	target := "test-minion"

	// Mock block devices response
	blkidResponse := `{
		"/dev/sda": {
			"TYPE": "disk"
		},
		"/dev/sda1": {
			"TYPE": "part"
		},
		"/dev/sdb": {
			"TYPE": "disk"
		}
	}`

	// Mock SMART responses for each device
	smartResponseA := `{
		"model": "Samsung SSD 970 EVO",
		"serial": "S466NX0M123456A",
		"health": "PASSED"
	}`

	smartResponseB := `{
		"model": "WD Blue 1TB",
		"serial": "WD-WCC4N123456B",
		"health": "PASSED"
	}`

	mockClient.On("CmdRun", ctx, target, "disk.blkid").Return(blkidResponse, nil)
	mockClient.On("CmdRun", ctx, target, "disk.smart_attributes /dev/sda").Return(smartResponseA, nil)
	mockClient.On("CmdRun", ctx, target, "disk.smart_attributes /dev/sdb").Return(smartResponseB, nil)

	result, err := manager.CheckDiskHealth(ctx, target)

	require.NoError(t, err)
	assert.Len(t, result, 2)

	// Verify we got SMART data for both devices
	deviceA := findSMARTByDevice(result, "/dev/sda")
	require.NotNil(t, deviceA)
	assert.Equal(t, "Samsung SSD 970 EVO", deviceA.Model)

	deviceB := findSMARTByDevice(result, "/dev/sdb")
	require.NotNil(t, deviceB)
	assert.Equal(t, "WD Blue 1TB", deviceB.Model)

	mockClient.AssertExpectations(t)
}

func TestCreatePartition(t *testing.T) {
	manager, mockClient := setupTestDiskManager(t)
	ctx := context.Background()
	target := "test-minion"
	device := "/dev/sdb"

	partition := PartitionSpec{
		Start:      "1MiB",
		End:        "100%",
		Type:       "primary",
		Filesystem: "ext4",
		Label:      "data",
		Flags:      []string{"boot"},
	}

	expectedPillar := map[string]interface{}{
		"device":    device,
		"partition": partition,
	}

	mockClient.On("StateApply", ctx, target, "disk.create_partition", expectedPillar).Return(nil)

	err := manager.CreatePartition(ctx, target, device, partition)

	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestDeletePartition(t *testing.T) {
	manager, mockClient := setupTestDiskManager(t)
	ctx := context.Background()
	target := "test-minion"
	device := "/dev/sdb"
	partNumber := 1

	expectedPillar := map[string]interface{}{
		"device":           device,
		"partition_number": partNumber,
	}

	mockClient.On("StateApply", ctx, target, "disk.delete_partition", expectedPillar).Return(nil)

	err := manager.DeletePartition(ctx, target, device, partNumber)

	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestExpandFilesystem(t *testing.T) {
	manager, mockClient := setupTestDiskManager(t)
	ctx := context.Background()
	target := "test-minion"
	device := "/dev/sda1"

	expectedPillar := map[string]interface{}{
		"device": device,
	}

	mockClient.On("StateApply", ctx, target, "disk.expand_filesystem", expectedPillar).Return(nil)

	err := manager.ExpandFilesystem(ctx, target, device)

	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

// Benchmark tests for performance validation
func BenchmarkGetDiskUsage(b *testing.B) {
	manager, mockClient := setupBenchmarkDiskManager(b)
	ctx := context.Background()
	target := "test-minion"
	path := "/var"

	response := `{
		"total": 1073741824,
		"used": 536870912,
		"available": 536870912,
		"percent": 50.0
	}`

	mockClient.On("CmdRun", mock.Anything, mock.Anything, mock.Anything).Return(response, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.GetDiskUsage(ctx, target, path)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDiskUsage(b *testing.B) {
	manager, _ := setupBenchmarkDiskManager(b)

	response := `{
		"total": 1073741824,
		"used": 536870912,
		"available": 536870912,
		"percent": 50.0
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.parseDiskUsage(response, "/var")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Table-driven test for parsing functions
func TestParseDiskUsage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		path     string
		expected *DiskUsage
		hasError bool
	}{
		{
			name: "valid JSON",
			input: `{
				"total": 1073741824,
				"used": 536870912,
				"available": 536870912,
				"percent": 50.0
			}`,
			path: "/var",
			expected: &DiskUsage{
				Path:          "/var",
				TotalSize:     1073741824,
				UsedSize:      536870912,
				AvailableSize: 536870912,
				UsedPercent:   50.0,
			},
		},
		{
			name:     "invalid JSON",
			input:    "invalid json",
			path:     "/var",
			hasError: true,
		},
		{
			name:     "empty JSON",
			input:    "{}",
			path:     "/var",
			expected: &DiskUsage{Path: "/var"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, _ := setupTestDiskManager(t)

			result, err := manager.parseDiskUsage(tt.input, tt.path)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expected.Path, result.Path)
				assert.Equal(t, tt.expected.TotalSize, result.TotalSize)
				assert.Equal(t, tt.expected.UsedSize, result.UsedSize)
				assert.Equal(t, tt.expected.AvailableSize, result.AvailableSize)
				assert.Equal(t, tt.expected.UsedPercent, result.UsedPercent)
			}
		})
	}
}

// Helper functions for test assertions
func findUsageByPath(usages []DiskUsage, path string) *DiskUsage {
	for i := range usages {
		if usages[i].Path == path {
			return &usages[i]
		}
	}
	return nil
}

func findSMARTByDevice(smartData []SMARTData, device string) *SMARTData {
	for i := range smartData {
		if smartData[i].Device == device {
			return &smartData[i]
		}
	}
	return nil
}

// Test error scenarios and edge cases
func TestErrorScenarios(t *testing.T) {
	t.Run("context cancellation", func(t *testing.T) {
		manager, mockClient := setupTestDiskManager(t)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		target := "test-minion"
		path := "/var"

		// Set up mock expectation for the call that will happen before context check
		mockClient.On("CmdRun", mock.MatchedBy(func(ctx context.Context) bool {
			return ctx.Err() != nil // Context should be cancelled
		}), target, "disk.usage "+path).Return("", fmt.Errorf("context cancelled"))

		_, err := manager.GetDiskUsage(ctx, target, path)

		// We expect some kind of error due to context cancellation
		assert.Error(t, err)

		mockClient.AssertExpectations(t)
	})

	t.Run("timeout scenario", func(t *testing.T) {
		manager, mockClient := setupTestDiskManager(t)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		target := "test-minion"
		path := "/var"

		// Simulate a slow response that would timeout
		mockClient.On("CmdRun", mock.Anything, target, mock.Anything).
			Return("", context.DeadlineExceeded).
			After(10 * time.Millisecond)

		_, err := manager.GetDiskUsage(ctx, target, path)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get disk usage")

		mockClient.AssertExpectations(t)
	})
}
