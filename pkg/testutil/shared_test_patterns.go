package testutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/installation"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/serviceutil"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shared test patterns and utilities for consistent testing across the codebase

// TestableComponent interface for components that can be tested
type TestableComponent interface {
	// SetupTest prepares the component for testing
	SetupTest(t *testing.T) error
	// TeardownTest cleans up after testing
	TeardownTest(t *testing.T) error
}

// ServiceTestCase represents a standardized service test case
type ServiceTestCase struct {
	Name           string
	ServiceName    string
	ShouldBeActive bool
	ShouldBeEnabled bool
	SetupFunc      func(t *testing.T) error
	CleanupFunc    func(t *testing.T) error
}

// InstallationTestCase represents a standardized installation test case
type InstallationTestCase struct {
	Name         string
	Config       interface{}
	ExpectError  bool
	ValidateFunc func(t *testing.T, result interface{}) error
}

// ConfigTestCase represents a standardized configuration test case
type ConfigTestCase struct {
	Name         string
	ConfigPath   string
	ConfigData   interface{}
	ExpectError  bool
	ValidateFunc func(t *testing.T, loaded interface{}) error
}

// TestServiceManager provides utilities for testing service operations
type TestServiceManager struct {
	rc            *eos_io.RuntimeContext
	serviceManager *shared.SystemdServiceManager
	createdServices []string // Track services created during tests
}

// NewTestServiceManager creates a service manager for testing
func NewTestServiceManager(t *testing.T) *TestServiceManager {
	t.Helper()
	rc := TestRuntimeContext(t)
	return &TestServiceManager{
		rc:            rc,
		serviceManager: serviceutil.NewServiceManager(rc),
		createdServices: make([]string, 0),
	}
}

// CreateTestService creates a test service and tracks it for cleanup
func (tsm *TestServiceManager) CreateTestService(t *testing.T, config *shared.ServiceConfig) error {
	t.Helper()
	
	if err := tsm.serviceManager.InstallService(config); err != nil {
		return err
	}
	
	// Track for cleanup
	tsm.createdServices = append(tsm.createdServices, config.Name)
	
	// Register cleanup function
	t.Cleanup(func() {
		tsm.serviceManager.RemoveService(config.Name)
	})
	
	return nil
}

// RunServiceTests runs standardized service tests
func (tsm *TestServiceManager) RunServiceTests(t *testing.T, testCases []ServiceTestCase) {
	t.Helper()
	
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Setup
			if tc.SetupFunc != nil {
				require.NoError(t, tc.SetupFunc(t), "Setup should not fail")
			}
			
			// Cleanup
			if tc.CleanupFunc != nil {
				t.Cleanup(func() {
					tc.CleanupFunc(t)
				})
			}
			
			// Test service state
			state, err := tsm.serviceManager.GetServiceState(tc.ServiceName)
			require.NoError(t, err, "Should be able to get service state")
			
			assert.Equal(t, tc.ShouldBeActive, state.Active, 
				"Service active state should match expected")
			assert.Equal(t, tc.ShouldBeEnabled, state.Enabled, 
				"Service enabled state should match expected")
		})
	}
}

// TestConfigManager provides utilities for testing configuration operations
type TestConfigManager struct {
	rc            *eos_io.RuntimeContext
	configManager *shared.ConfigManager
	tempDir       string
	createdFiles  []string // Track files created during tests
}

// NewTestConfigManager creates a config manager for testing
func NewTestConfigManager(t *testing.T) *TestConfigManager {
	t.Helper()
	
	rc := TestRuntimeContext(t)
	tempDir := t.TempDir() // Automatically cleaned up
	
	return &TestConfigManager{
		rc:            rc,
		configManager: serviceutil.NewConfigManager(rc),
		tempDir:       tempDir,
		createdFiles:  make([]string, 0),
	}
}

// CreateTestConfigFile creates a temporary config file for testing
func (tcm *TestConfigManager) CreateTestConfigFile(t *testing.T, filename string, content interface{}) string {
	t.Helper()
	
	path := filepath.Join(tcm.tempDir, filename)
	
	opts := &shared.ConfigOptions{
		Path:   path,
		Format: shared.FormatJSON, // Default to JSON for tests
	}
	
	err := tcm.configManager.SaveConfig(opts, content)
	require.NoError(t, err, "Should be able to create test config file")
	
	// Track for potential cleanup
	tcm.createdFiles = append(tcm.createdFiles, path)
	
	return path
}

// RunConfigTests runs standardized configuration tests
func (tcm *TestConfigManager) RunConfigTests(t *testing.T, testCases []ConfigTestCase) {
	t.Helper()
	
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Create test config file
			configPath := tc.ConfigPath
			if configPath == "" {
				configPath = tcm.CreateTestConfigFile(t, "test_config.json", tc.ConfigData)
			}
			
			// Load configuration
			var loaded interface{}
			opts := &shared.ConfigOptions{Path: configPath}
			err := tcm.configManager.LoadConfig(opts, &loaded)
			
			if tc.ExpectError {
				assert.Error(t, err, "Should expect an error")
				return
			}
			
			require.NoError(t, err, "Should be able to load config")
			
			// Validate if provided
			if tc.ValidateFunc != nil {
				err := tc.ValidateFunc(t, loaded)
				assert.NoError(t, err, "Validation should pass")
			}
		})
	}
}

// TestInstallationFramework provides utilities for testing installations
type TestInstallationFramework struct {
	rc          *eos_io.RuntimeContext
	framework   *installation.InstallationFramework
	tempDir     string
	installedItems []string // Track items installed during tests
}

// NewTestInstallationFramework creates an installation framework for testing
func NewTestInstallationFramework(t *testing.T) *TestInstallationFramework {
	t.Helper()
	
	rc := TestRuntimeContext(t)
	tempDir := t.TempDir()
	
	return &TestInstallationFramework{
		rc:          rc,
		framework:   installation.NewInstallationFramework(rc),
		tempDir:     tempDir,
		installedItems: make([]string, 0),
	}
}

// RunInstallationTests runs standardized installation tests
func (tif *TestInstallationFramework) RunInstallationTests(t *testing.T, testCases []InstallationTestCase) {
	t.Helper()
	
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Convert config to InstallationConfig
			config, ok := tc.Config.(*installation.InstallationConfig)
			require.True(t, ok, "Config should be InstallationConfig")
			
			// Modify paths to use temp directory
			if config.InstallPath == "" {
				config.InstallPath = tif.tempDir
			}
			
			// Run installation
			result, err := tif.framework.Install(config)
			
			if tc.ExpectError {
				assert.Error(t, err, "Should expect an error")
				return
			}
			
			require.NoError(t, err, "Installation should succeed")
			assert.True(t, result.Success, "Installation result should be successful")
			
			// Track for cleanup
			if result.InstalledTo != "" {
				tif.installedItems = append(tif.installedItems, result.InstalledTo)
			}
			
			// Validate if provided
			if tc.ValidateFunc != nil {
				err := tc.ValidateFunc(t, result)
				assert.NoError(t, err, "Validation should pass")
			}
		})
	}
}

// Common test patterns and assertions

// AssertServiceRunning asserts that a service is running
func AssertServiceRunning(t *testing.T, serviceName string) {
	t.Helper()
	rc := TestRuntimeContext(t)
	sm := serviceutil.NewServiceManager(rc)
	
	active, err := sm.IsActive(serviceName)
	require.NoError(t, err, "Should be able to check service status")
	assert.True(t, active, "Service %s should be running", serviceName)
}

// AssertServiceStopped asserts that a service is stopped
func AssertServiceStopped(t *testing.T, serviceName string) {
	t.Helper()
	rc := TestRuntimeContext(t)
	sm := serviceutil.NewServiceManager(rc)
	
	active, err := sm.IsActive(serviceName)
	require.NoError(t, err, "Should be able to check service status")
	assert.False(t, active, "Service %s should be stopped", serviceName)
}

// AssertConfigValue asserts that a configuration value matches expected
func AssertConfigValue(t *testing.T, configPath, key string, expected interface{}) {
	t.Helper()
	rc := TestRuntimeContext(t)
	cm := serviceutil.NewConfigManager(rc)
	
	value, err := cm.GetConfigValue(configPath, key)
	require.NoError(t, err, "Should be able to get config value")
	assert.Equal(t, expected, value, "Config value for key %s should match", key)
}

// AssertPackageInstalled asserts that a package is installed
func AssertPackageInstalled(t *testing.T, packageName string) {
	t.Helper()
	// Implementation would check if package is installed
	// This is a placeholder for the actual implementation
	assert.True(t, shared.FileExists("/usr/bin/"+packageName) || 
		shared.FileExists("/usr/local/bin/"+packageName),
		"Package %s should be installed", packageName)
}

// Time-based test utilities

// WithTimeout runs a test function with a timeout
func WithTimeout(t *testing.T, timeout time.Duration, testFunc func()) {
	t.Helper()
	
	done := make(chan bool, 1)
	go func() {
		testFunc()
		done <- true
	}()
	
	select {
	case <-done:
		// Test completed within timeout
	case <-time.After(timeout):
		t.Fatalf("Test timed out after %v", timeout)
	}
}

// EventuallyTrue polls a condition until it becomes true or times out
func EventuallyTrue(t *testing.T, condition func() bool, timeout time.Duration, interval time.Duration, msg string) {
	t.Helper()
	
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(interval)
	}
	
	t.Fatalf("Condition was not true within %v: %s", timeout, msg)
}

// MockCommand provides utilities for mocking command execution in tests
type MockCommand struct {
	Commands map[string]MockCommandResult
}

type MockCommandResult struct {
	Output   string
	ExitCode int
	Error    error
}

// NewMockCommand creates a new command mocker
func NewMockCommand() *MockCommand {
	return &MockCommand{
		Commands: make(map[string]MockCommandResult),
	}
}

// SetCommand sets the expected result for a command
func (mc *MockCommand) SetCommand(command string, result MockCommandResult) {
	mc.Commands[command] = result
}

// GetResult returns the mocked result for a command
func (mc *MockCommand) GetResult(command string) (MockCommandResult, bool) {
	result, exists := mc.Commands[command]
	return result, exists
}

// Test data generators

// GenerateTestConfig generates test configuration data
func GenerateTestConfig() map[string]interface{} {
	return map[string]interface{}{
		"name":    "test-service",
		"version": "1.0.0",
		"enabled": true,
		"settings": map[string]interface{}{
			"debug": true,
			"port":  8080,
		},
	}
}

// GenerateTestServiceConfig generates test service configuration
func GenerateTestServiceConfig(name string) *shared.ServiceConfig {
	return &shared.ServiceConfig{
		Name:        name,
		Description: "Test service for " + name,
		ExecStart:   "/usr/bin/test-service",
		User:        "test",
		Restart:     "always",
	}
}

// GenerateTestInstallationConfig generates test installation configuration
func GenerateTestInstallationConfig(name string) *installation.InstallationConfig {
	return &installation.InstallationConfig{
		Name:        name,
		Method:      installation.MethodApt,
		PackageName: name,
		Description: "Test installation for " + name,
	}
}

// Test validation helpers

// ValidateJSONStructure validates that data has expected JSON structure
func ValidateJSONStructure(t *testing.T, data interface{}, expectedKeys []string) {
	t.Helper()
	
	// Convert to map for validation
	dataMap, ok := data.(map[string]interface{})
	require.True(t, ok, "Data should be a map")
	
	for _, key := range expectedKeys {
		assert.Contains(t, dataMap, key, "Should contain key: %s", key)
	}
}

// ValidateFilePermissions validates file permissions
func ValidateFilePermissions(t *testing.T, path string, expectedPerm os.FileMode) {
	t.Helper()
	
	info, err := os.Stat(path)
	require.NoError(t, err, "Should be able to stat file")
	
	actualPerm := info.Mode().Perm()
	assert.Equal(t, expectedPerm, actualPerm, 
		"File %s should have permissions %o, got %o", path, expectedPerm, actualPerm)
}