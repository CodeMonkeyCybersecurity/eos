// pkg/shared/service_management_simple_test.go

package shared

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap/zaptest"
)

// MockSimpleServiceRegistry is a simplified mock implementation
type MockSimpleServiceRegistry struct {
	mock.Mock
}

func (m *MockSimpleServiceRegistry) GetActiveServices() map[string]WazuhServiceDefinition {
	args := m.Called()
	return args.Get(0).(map[string]WazuhServiceDefinition)
}

func (m *MockSimpleServiceRegistry) GetActiveServiceNames() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockSimpleServiceRegistry) GetService(name string) (WazuhServiceDefinition, bool) {
	args := m.Called(name)
	return args.Get(0).(WazuhServiceDefinition), args.Bool(1)
}

func (m *MockSimpleServiceRegistry) CheckServiceInstallationStatus(serviceName string) (ServiceInstallationStatus, error) {
	args := m.Called(serviceName)
	return args.Get(0).(ServiceInstallationStatus), args.Error(1)
}

func TestServiceManager_CreateAndBasicFunctionality(t *testing.T) {
	// Test that we can create a service manager
	sm := NewServiceManager()
	assert.NotNil(t, sm)
	assert.NotNil(t, sm.registry)
}

func TestServiceManager_GetEnhancedServiceStatus_BasicFlow(t *testing.T) {
	// Setup logger
	logger := zaptest.NewLogger(t)
	defer func() {
		_ = logger.Sync() // Ignore error in test cleanup
	}()
	otelLogger := otelzap.New(logger)
	otelzap.ReplaceGlobals(otelLogger)
	ctx := context.Background()

	// Setup mock registry
	mockRegistry := new(MockSimpleServiceRegistry)

	// Create service manager with mock registry
	sm := &ServiceManager{
		registry: mockRegistry,
	}

	// Test case: service not found
	mockRegistry.On("CheckServiceInstallationStatus", "non-existent-service").Return(
		ServiceInstallationStatus{},
		assert.AnError,
	)

	status, err := sm.GetEnhancedServiceStatus(ctx, "non-existent-service")
	assert.Error(t, err)
	assert.Equal(t, EnhancedServiceStatus{}, status)

	mockRegistry.AssertExpectations(t)
}

func TestServiceManager_GetServicesRequiringInstallation_BasicFlow(t *testing.T) {
	// Setup logger
	logger := zaptest.NewLogger(t)
	defer func() {
		_ = logger.Sync() // Ignore error in test cleanup
	}()
	otelLogger := otelzap.New(logger)
	otelzap.ReplaceGlobals(otelLogger)
	ctx := context.Background()

	// Setup mock registry
	mockRegistry := new(MockSimpleServiceRegistry)

	// Create service manager with mock registry
	sm := &ServiceManager{
		registry: mockRegistry,
	}

	// Mock return values
	mockServices := map[string]WazuhServiceDefinition{
		"test-service": {
			Name:         "test-service",
			WorkerScript: "/opt/test-service.py",
			ServiceFile:  "/etc/systemd/system/test-service.service",
		},
	}

	mockRegistry.On("GetActiveServices").Return(mockServices)
	mockRegistry.On("GetActiveServiceNames").Return([]string{"test-service"})

	// Mock that service needs installation
	mockRegistry.On("CheckServiceInstallationStatus", "test-service").Return(
		ServiceInstallationStatus{
			ServiceName:      "test-service",
			WorkerInstalled:  true,
			ServiceInstalled: false, // Needs installation
		},
		nil,
	)

	// Execute
	missingServices, err := sm.GetServicesRequiringInstallation(ctx)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, missingServices, 1)
	assert.Contains(t, missingServices, "test-service")

	mockRegistry.AssertExpectations(t)
}

func TestServiceManager_AutoInstallServices_BasicFlow(t *testing.T) {
	// Setup logger
	logger := zaptest.NewLogger(t)
	defer func() {
		_ = logger.Sync() // Ignore error in test cleanup
	}()
	otelLogger := otelzap.New(logger)
	otelzap.ReplaceGlobals(otelLogger)
	ctx := context.Background()

	// Create service manager
	sm := NewServiceManager()

	// Test with empty services list (should not crash)
	emptyServicesList := []string{}
	err := sm.AutoInstallServices(ctx, emptyServicesList)
	assert.NoError(t, err)
}

func TestServiceManager_CrashPrevention(t *testing.T) {
	// Test scenarios that previously caused crashes

	// Setup logger
	logger := zaptest.NewLogger(t)
	defer func() {
		_ = logger.Sync() // Ignore error in test cleanup
	}()
	otelLogger := otelzap.New(logger)
	otelzap.ReplaceGlobals(otelLogger)
	ctx := context.Background()

	sm := NewServiceManager()

	// Test with services that previously caused crashes
	crashCausingServices := []string{
		"alert-to-db",
		"ab-test-analyzer",
		"non-existent-service",
		"",
	}

	for _, serviceName := range crashCausingServices {
		t.Run("crash_prevention_"+serviceName, func(t *testing.T) {
			// This should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("GetEnhancedServiceStatus crashed with panic: %v, serviceName: %q", r, serviceName)
				}
			}()

			// Execute - we don't care about errors, just that it doesn't crash
			_, err := sm.GetEnhancedServiceStatus(ctx, serviceName)
			_ = err // Ignore errors, just testing for crashes
		})
	}
}

func TestServiceManager_Integration_CrashPrevention(t *testing.T) {
	// Integration test for crash prevention during full workflow

	// Setup logger
	logger := zaptest.NewLogger(t)
	defer func() {
		_ = logger.Sync() // Ignore error in test cleanup
	}()
	otelLogger := otelzap.New(logger)
	otelzap.ReplaceGlobals(otelLogger)
	ctx := context.Background()

	sm := NewServiceManager()

	t.Run("full_workflow_crash_prevention", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Full workflow crashed with panic: %v", r)
			}
		}()

		// Test the full workflow that previously crashed
		// 1. Get services requiring installation
		missingServices, err := sm.GetServicesRequiringInstallation(ctx)
		_ = err // Ignore errors, just testing for crashes

		// 2. Try auto-installation (should not crash even if services are missing)
		if missingServices != nil {
			// Convert map to slice of service names
			serviceNames := make([]string, 0, len(missingServices))
			for serviceName := range missingServices {
				serviceNames = append(serviceNames, serviceName)
			}
			err = sm.AutoInstallServices(ctx, serviceNames)
			_ = err // Ignore errors, just testing for crashes
		}
	})
}
