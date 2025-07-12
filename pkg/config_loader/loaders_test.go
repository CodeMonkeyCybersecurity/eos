package config_loader

import (
	"os"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadServicesFromFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
		validate    func(t *testing.T, services []system.ServiceConfig)
	}{
		{
			name:        "empty array",
			content:     `[]`,
			expectError: false,
			validate: func(t *testing.T, services []system.ServiceConfig) {
				assert.Len(t, services, 0)
			},
		},
		{
			name:        "single service",
			content:     `[{"name":"nginx","enable":true}]`,
			expectError: false,
			validate: func(t *testing.T, services []system.ServiceConfig) {
				require.Len(t, services, 1)
				assert.Equal(t, "nginx", services[0].Name)
				assert.True(t, services[0].Enable)
			},
		},
		{
			name:        "multiple services",
			content:     `[{"name":"nginx","enable":true},{"name":"apache","enable":false}]`,
			expectError: false,
			validate: func(t *testing.T, services []system.ServiceConfig) {
				require.Len(t, services, 2)
				assert.Equal(t, "nginx", services[0].Name)
				assert.Equal(t, "apache", services[1].Name)
			},
		},
		{
			name:        "invalid JSON",
			content:     `invalid json`,
			expectError: true,
			validate:    nil,
		},
		{
			name:        "wrong JSON structure",
			content:     `{"not":"an array"}`,
			expectError: true,
			validate:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			// Create temporary file
			tmpFile := createTempFile(t, tt.content)
			defer func() { _ = os.Remove(tmpFile) }()

			services, err := LoadServicesFromFile(rc, tmpFile)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, services)
				}
			}
		})
	}
}

func TestLoadCronJobsFromFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
		validate    func(t *testing.T, jobs []system.CronJobConfig)
	}{
		{
			name:        "empty array",
			content:     `[]`,
			expectError: false,
			validate: func(t *testing.T, jobs []system.CronJobConfig) {
				assert.Len(t, jobs, 0)
			},
		},
		{
			name:        "single cron job",
			content:     `[{"name":"test-job","command":"test","user":"root","minute":"0","hour":"*"}]`,
			expectError: false,
			validate: func(t *testing.T, jobs []system.CronJobConfig) {
				require.Len(t, jobs, 1)
				assert.Equal(t, "test-job", jobs[0].Name)
				assert.Equal(t, "test", jobs[0].Command)
				assert.Equal(t, "root", jobs[0].User)
				assert.Equal(t, "0", jobs[0].Minute)
				assert.Equal(t, "*", jobs[0].Hour)
			},
		},
		{
			name:        "invalid JSON",
			content:     `{invalid}`,
			expectError: true,
			validate:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			tmpFile := createTempFile(t, tt.content)
			defer func() { _ = os.Remove(tmpFile) }()

			jobs, err := LoadCronJobsFromFile(rc, tmpFile)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, jobs)
				}
			}
		})
	}
}

func TestLoadUsersFromFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
		validate    func(t *testing.T, users []system.UserConfig)
	}{
		{
			name:        "empty array",
			content:     `[]`,
			expectError: false,
			validate: func(t *testing.T, users []system.UserConfig) {
				assert.Len(t, users, 0)
			},
		},
		{
			name:        "single user",
			content:     `[{"name":"testuser","shell":"/bin/bash","home":"/home/testuser"}]`,
			expectError: false,
			validate: func(t *testing.T, users []system.UserConfig) {
				require.Len(t, users, 1)
				assert.Equal(t, "testuser", users[0].Name)
				assert.Equal(t, "/bin/bash", users[0].Shell)
				assert.Equal(t, "/home/testuser", users[0].Home)
			},
		},
		{
			name:        "invalid JSON",
			content:     `malformed`,
			expectError: true,
			validate:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			tmpFile := createTempFile(t, tt.content)
			defer func() { _ = os.Remove(tmpFile) }()

			users, err := LoadUsersFromFile(rc, tmpFile)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, users)
				}
			}
		})
	}
}

func TestLoadSystemStateFromFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
		validate    func(t *testing.T, state *SystemState)
	}{
		{
			name:        "minimal state",
			content:     `{"services":[],"cron_jobs":[],"users":[],"packages":[],"files":[]}`,
			expectError: false,
			validate: func(t *testing.T, state *SystemState) {
				assert.NotNil(t, state)
				assert.Len(t, state.Services, 0)
				assert.Len(t, state.CronJobs, 0)
				assert.Len(t, state.Users, 0)
			},
		},
		{
			name: "complete state",
			content: `{
				"services": [{"name":"nginx","enable":true}],
				"cron_jobs": [{"name":"test-job","command":"test","user":"root","minute":"0","hour":"*"}],
				"users": [{"name":"test","shell":"/bin/bash","home":"/home/test"}],
				"packages": [],
				"files": [],
				"security": {"firewall":true},
				"metadata": {"version":"1.0"}
			}`,
			expectError: false,
			validate: func(t *testing.T, state *SystemState) {
				assert.NotNil(t, state)
				assert.Len(t, state.Services, 1)
				assert.Len(t, state.CronJobs, 1)
				assert.Len(t, state.Users, 1)
				assert.NotNil(t, state.Security)
				assert.NotNil(t, state.Metadata)
			},
		},
		{
			name:        "invalid JSON",
			content:     `{broken json}`,
			expectError: true,
			validate:    nil,
		},
		{
			name:        "empty object",
			content:     `{}`,
			expectError: false,
			validate: func(t *testing.T, state *SystemState) {
				assert.NotNil(t, state)
				// All fields should be zero values
				assert.Len(t, state.Services, 0)
				assert.Len(t, state.CronJobs, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			tmpFile := createTempFile(t, tt.content)
			defer func() { _ = os.Remove(tmpFile) }()

			state, err := LoadSystemStateFromFile(rc, tmpFile)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, state)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, state)
				}
			}
		})
	}
}

func TestFileNotFound(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	nonExistentFile := "/tmp/non_existent_file_12345.json"
	
	t.Run("LoadServicesFromFile", func(t *testing.T) {
		_, err := LoadServicesFromFile(rc, nonExistentFile)
		assert.Error(t, err)
	})
	
	t.Run("LoadCronJobsFromFile", func(t *testing.T) {
		_, err := LoadCronJobsFromFile(rc, nonExistentFile)
		assert.Error(t, err)
	})
	
	t.Run("LoadUsersFromFile", func(t *testing.T) {
		_, err := LoadUsersFromFile(rc, nonExistentFile)
		assert.Error(t, err)
	})
	
	t.Run("LoadSystemStateFromFile", func(t *testing.T) {
		_, err := LoadSystemStateFromFile(rc, nonExistentFile)
		assert.Error(t, err)
	})
}

func TestSystemStateStruct(t *testing.T) {
	t.Run("empty state", func(t *testing.T) {
		state := &SystemState{}
		assert.NotNil(t, state)
		assert.Len(t, state.Services, 0)
		assert.Len(t, state.CronJobs, 0)
		assert.Len(t, state.Users, 0)
	})

	t.Run("state with data", func(t *testing.T) {
		state := &SystemState{
			Services: []system.ServiceConfig{{Name: "test", Enable: true}},
			Metadata: map[string]interface{}{"version": "1.0"},
			Security: map[string]interface{}{"enabled": true},
		}
		assert.Len(t, state.Services, 1)
		assert.Equal(t, "test", state.Services[0].Name)
		assert.Equal(t, "1.0", state.Metadata["version"])
		assert.Equal(t, true, state.Security["enabled"])
	})
}

func TestStateApplicationResult(t *testing.T) {
	result := &StateApplicationResult{
		ServicesChanged: 5,
		CronJobsChanged: 2,
		UsersChanged:    1,
		PackagesChanged: 10,
		FilesChanged:    3,
		Errors:          []string{"error1", "error2"},
	}

	assert.Equal(t, 5, result.ServicesChanged)
	assert.Equal(t, 2, result.CronJobsChanged)
	assert.Equal(t, 1, result.UsersChanged)
	assert.Equal(t, 10, result.PackagesChanged)
	assert.Equal(t, 3, result.FilesChanged)
	assert.Len(t, result.Errors, 2)
}

// Helper function to create temporary files for testing
func createTempFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp("", "config_test_*.json")
	require.NoError(t, err)
	
	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)
	
	_ = tmpFile.Close()
	require.NoError(t, err)
	
	return tmpFile.Name()
}