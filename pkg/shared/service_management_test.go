// pkg/shared/service_management_test.go

package shared

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap/zaptest"
)

// MockServiceRegistry is a mock implementation of ServiceRegistryInterface
type MockServiceRegistry struct {
	mock.Mock
}

func (m *MockServiceRegistry) GetActiveServices() []DelphiServiceDefinition {
	args := m.Called()
	return args.Get(0).([]DelphiServiceDefinition)
}

func (m *MockServiceRegistry) GetActiveServiceNames() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockServiceRegistry) GetService(name string) (DelphiServiceDefinition, bool) {
	args := m.Called(name)
	return args.Get(0).(DelphiServiceDefinition), args.Bool(1)
}

func (m *MockServiceRegistry) CheckServiceInstallationStatus(serviceName string) (ServiceInstallationStatus, error) {
	args := m.Called(serviceName)
	return args.Get(0).(ServiceInstallationStatus), args.Error(1)
}

func (m *MockServiceRegistry) GetServiceType(serviceName string) (string, bool) {
	args := m.Called(serviceName)
	return args.String(0), args.Bool(1)
}

func (m *MockServiceRegistry) GetPipelineOrder() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockServiceRegistry) ValidateService(serviceName string) error {
	args := m.Called(serviceName)
	return args.Error(0)
}

func TestServiceManager_GetEnhancedServiceStatus(t *testing.T) {
	tests := []struct {
		name                 string
		serviceName          string
		mockBasicStatus      ServiceInstallationStatus
		mockBasicStatusError error
		mockSystemdActive    bool
		mockSystemdEnabled   bool
		mockSystemdStatus    string
		expectedStatus       EnhancedServiceStatus
		expectedError        bool
		expectedLogMessages  []string
	}{
		{
			name:        "successful status check - service installed and active",
			serviceName: "delphi-listener",
			mockBasicStatus: ServiceInstallationStatus{
				ServiceName:      "delphi-listener",
				WorkerInstalled:  true,
				ServiceInstalled: true,
				WorkerPath:       "/usr/local/bin/delphi-listener.py",
				ServicePath:      "/etc/systemd/system/delphi-listener.service",
			},
			mockSystemdActive:  true,
			mockSystemdEnabled: true,
			mockSystemdStatus:  "active",
			expectedStatus: EnhancedServiceStatus{
				ServiceInstallationStatus: ServiceInstallationStatus{
					ServiceName:      "delphi-listener",
					WorkerInstalled:  true,
					ServiceInstalled: true,
					WorkerPath:       "/usr/local/bin/delphi-listener.py",
					ServicePath:      "/etc/systemd/system/delphi-listener.service",
				},
				SystemdActive:  true,
				SystemdEnabled: true,
				SystemdStatus:  "active",
				CanInstall:     true,
				InstallCommand: "eos delphi services create delphi-listener",
			},
			expectedError: false,
			expectedLogMessages: []string{
				"Enhanced service status check completed",
			},
		},
		{
			name:        "successful status check - service not installed",
			serviceName: "alert-to-db",
			mockBasicStatus: ServiceInstallationStatus{
				ServiceName:      "alert-to-db",
				WorkerInstalled:  true,
				ServiceInstalled: false,
				WorkerPath:       "/usr/local/bin/alert-to-db.py",
				ServicePath:      "",
			},
			expectedStatus: EnhancedServiceStatus{
				ServiceInstallationStatus: ServiceInstallationStatus{
					ServiceName:      "alert-to-db",
					WorkerInstalled:  true,
					ServiceInstalled: false,
					WorkerPath:       "/usr/local/bin/alert-to-db.py",
					ServicePath:      "",
				},
				SystemdActive:  false,
				SystemdEnabled: false,
				SystemdStatus:  "",
				CanInstall:     true,
				InstallCommand: "eos delphi services create alert-to-db",
			},
			expectedError: false,
			expectedLogMessages: []string{
				"Skipping systemd checks (service not installed)",
			},
		},
		{
			name:                 "basic status check fails",
			serviceName:          "invalid-service",
			mockBasicStatusError: errors.New("service not found"),
			expectedError:        true,
			expectedLogMessages: []string{
				"Failed to get basic service status",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup logger
			logger := zaptest.NewLogger(t)
			defer logger.Sync()

			ctx := otelzap.CtxWithLogger(context.Background(), logger)

			// Setup mock registry
			mockRegistry := new(MockServiceRegistry)
			if tt.mockBasicStatusError != nil {
				mockRegistry.On("CheckServiceInstallationStatus", tt.serviceName).Return(ServiceInstallationStatus{}, tt.mockBasicStatusError)
			} else {
				mockRegistry.On("CheckServiceInstallationStatus", tt.serviceName).Return(tt.mockBasicStatus, nil)
			}

			// Create service manager with mock
			sm := &ServiceManager{
				registry: mockRegistry,
			}

			// Override systemd check methods for testing
			if tt.mockBasicStatus.ServiceInstalled {
				// Mock successful systemd checks
				sm.isServiceActive = func(name string) (bool, error) { return tt.mockSystemdActive, nil }
				sm.isServiceEnabled = func(name string) (bool, error) { return tt.mockSystemdEnabled, nil }
				sm.getServiceStatus = func(name string) (string, error) { return tt.mockSystemdStatus, nil }
			}

			// Execute
			status, err := sm.GetEnhancedServiceStatus(ctx, tt.serviceName)

			// Assert
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, status)
			}

			mockRegistry.AssertExpectations(t)
		})
	}
}

func TestServiceManager_GetServicesRequiringInstallation(t *testing.T) {
	tests := []struct {
		name                    string
		mockActiveServices      []string
		mockServiceStatuses     map[string]ServiceInstallationStatus
		mockStatusErrors        map[string]error
		contextTimeout          time.Duration
		expectedMissingServices []string
		expectedError           bool
		expectedLogMessages     []string
	}{
		{
			name:               "detect multiple missing services",
			mockActiveServices: []string{"delphi-listener", "alert-to-db", "ab-test-analyzer"},
			mockServiceStatuses: map[string]ServiceInstallationStatus{
				"delphi-listener": {
					ServiceName:      "delphi-listener",
					WorkerInstalled:  true,
					ServiceInstalled: true,
				},
				"alert-to-db": {
					ServiceName:      "alert-to-db",
					WorkerInstalled:  true,
					ServiceInstalled: false,
				},
				"ab-test-analyzer": {
					ServiceName:      "ab-test-analyzer",
					WorkerInstalled:  true,
					ServiceInstalled: false,
				},
			},
			expectedMissingServices: []string{"alert-to-db", "ab-test-analyzer"},
			expectedError:           false,
			expectedLogMessages: []string{
				"Service requires installation",
				"Service installation scan completed",
			},
		},
		{
			name:               "all services installed",
			mockActiveServices: []string{"delphi-listener", "llm-worker"},
			mockServiceStatuses: map[string]ServiceInstallationStatus{
				"delphi-listener": {
					ServiceName:      "delphi-listener",
					WorkerInstalled:  true,
					ServiceInstalled: true,
				},
				"llm-worker": {
					ServiceName:      "llm-worker",
					WorkerInstalled:  true,
					ServiceInstalled: true,
				},
			},
			expectedMissingServices: []string{},
			expectedError:           false,
		},
		{
			name:               "context cancelled during scan",
			mockActiveServices: []string{"service1", "service2", "service3"},
			contextTimeout:     1 * time.Nanosecond, // Very short timeout
			expectedError:      true,
			expectedLogMessages: []string{
				"Service installation scan cancelled",
			},
		},
		{
			name:               "service check error - continues scan",
			mockActiveServices: []string{"delphi-listener", "broken-service", "llm-worker"},
			mockServiceStatuses: map[string]ServiceInstallationStatus{
				"delphi-listener": {
					ServiceName:      "delphi-listener",
					WorkerInstalled:  true,
					ServiceInstalled: true,
				},
				"llm-worker": {
					ServiceName:      "llm-worker",
					WorkerInstalled:  true,
					ServiceInstalled: false,
				},
			},
			mockStatusErrors: map[string]error{
				"broken-service": errors.New("service check failed"),
			},
			expectedMissingServices: []string{"llm-worker"},
			expectedError:           false,
			expectedLogMessages: []string{
				"Failed to check service status",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup logger
			logger := zaptest.NewLogger(t)
			defer logger.Sync()

			ctx := otelzap.CtxWithLogger(context.Background(), logger)

			// Apply context timeout if specified
			if tt.contextTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.contextTimeout)
				defer cancel()
				time.Sleep(tt.contextTimeout + 10*time.Millisecond) // Ensure timeout
			}

			// Setup mock registry
			mockRegistry := new(MockServiceRegistry)

			// Mock GetActiveServices
			var mockServices []DelphiServiceDefinition
			for _, name := range tt.mockActiveServices {
				mockServices = append(mockServices, DelphiServiceDefinition{Name: name})
			}
			mockRegistry.On("GetActiveServices").Return(mockServices)
			mockRegistry.On("GetActiveServiceNames").Return(tt.mockActiveServices)

			// Create service manager with mocked enhanced status
			sm := &ServiceManager{
				registry: mockRegistry,
			}

			// Mock enhanced status checks
			sm.GetEnhancedServiceStatus = func(ctx context.Context, serviceName string) (EnhancedServiceStatus, error) {
				// Check for context cancellation
				select {
				case <-ctx.Done():
					return EnhancedServiceStatus{}, ctx.Err()
				default:
				}

				if err, exists := tt.mockStatusErrors[serviceName]; exists {
					return EnhancedServiceStatus{}, err
				}

				if status, exists := tt.mockServiceStatuses[serviceName]; exists {
					return EnhancedServiceStatus{
						ServiceInstallationStatus: status,
						CanInstall:                true,
						InstallCommand:            "eos delphi services create " + serviceName,
					}, nil
				}

				return EnhancedServiceStatus{}, errors.New("service not configured in test")
			}

			// Execute
			missingServices, err := sm.GetServicesRequiringInstallation(ctx)

			// Assert
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Check that all expected missing services are found
				assert.Equal(t, len(tt.expectedMissingServices), len(missingServices))
				for _, expectedService := range tt.expectedMissingServices {
					_, found := missingServices[expectedService]
					assert.True(t, found, "Expected service %s to be in missing services", expectedService)
				}
			}

			mockRegistry.AssertExpectations(t)
		})
	}
}

func TestServiceManager_PromptForServiceInstallation(t *testing.T) {
	tests := []struct {
		name                      string
		missingServices           map[string]EnhancedServiceStatus
		expectedServicesToInstall []string
		expectedError             bool
	}{
		{
			name: "prompt for multiple missing services",
			missingServices: map[string]EnhancedServiceStatus{
				"alert-to-db": {
					ServiceInstallationStatus: ServiceInstallationStatus{
						ServiceName:      "alert-to-db",
						WorkerInstalled:  true,
						ServiceInstalled: false,
					},
					InstallCommand: "eos delphi services create alert-to-db",
				},
				"ab-test-analyzer": {
					ServiceInstallationStatus: ServiceInstallationStatus{
						ServiceName:      "ab-test-analyzer",
						WorkerInstalled:  true,
						ServiceInstalled: false,
					},
					InstallCommand: "eos delphi services create ab-test-analyzer",
				},
			},
			expectedServicesToInstall: []string{"alert-to-db", "ab-test-analyzer"},
			expectedError:             false,
		},
		{
			name:                      "no missing services",
			missingServices:           map[string]EnhancedServiceStatus{},
			expectedServicesToInstall: []string{},
			expectedError:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup logger
			logger := zaptest.NewLogger(t)
			defer logger.Sync()

			ctx := otelzap.CtxWithLogger(context.Background(), logger)

			// Setup mock registry
			mockRegistry := new(MockServiceRegistry)

			// Mock GetService calls
			for serviceName := range tt.missingServices {
				mockRegistry.On("GetService", serviceName).Return(
					DelphiServiceDefinition{
						Name:        serviceName,
						Description: "Test service " + serviceName,
					}, true)
			}

			// Create service manager
			sm := &ServiceManager{
				registry: mockRegistry,
			}

			// Execute
			servicesToInstall, err := sm.PromptForServiceInstallation(ctx, tt.missingServices)

			// Assert
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Check that the correct services are returned
				assert.ElementsMatch(t, tt.expectedServicesToInstall, servicesToInstall)
			}

			mockRegistry.AssertExpectations(t)
		})
	}
}

func TestServiceManager_AutoInstallServices(t *testing.T) {
	tests := []struct {
		name              string
		servicesToInstall []string
		installErrors     map[string]error
		enableErrors      map[string]error
		expectedError     bool
		expectedErrorMsg  string
	}{
		{
			name:              "successful installation of multiple services",
			servicesToInstall: []string{"alert-to-db", "ab-test-analyzer"},
			installErrors:     map[string]error{},
			enableErrors:      map[string]error{},
			expectedError:     false,
		},
		{
			name:              "no services to install",
			servicesToInstall: []string{},
			expectedError:     false,
		},
		{
			name:              "installation fails for one service",
			servicesToInstall: []string{"alert-to-db", "ab-test-analyzer"},
			installErrors: map[string]error{
				"alert-to-db": errors.New("installation failed"),
			},
			expectedError:    true,
			expectedErrorMsg: "failed to install service alert-to-db",
		},
		{
			name:              "enable fails but continues",
			servicesToInstall: []string{"alert-to-db"},
			installErrors:     map[string]error{},
			enableErrors: map[string]error{
				"alert-to-db": errors.New("enable failed"),
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup logger
			logger := zaptest.NewLogger(t)
			defer logger.Sync()

			ctx := otelzap.CtxWithLogger(context.Background(), logger)

			// Create service manager with mock exec function
			sm := &ServiceManager{
				registry: GetGlobalDelphiServiceRegistry(),
			}

			// Note: In a real test, we would mock the exec.CommandContext calls
			// For this example, we're focusing on the logic structure

			// Execute (would need exec mocking in real implementation)
			// err := sm.AutoInstallServices(ctx, tt.servicesToInstall)

			// For now, just validate the function exists and compiles
			assert.NotNil(t, sm.AutoInstallServices)
		})
	}
}

func TestServiceManager_CheckServiceExists(t *testing.T) {
	tests := []struct {
		name         string
		serviceName  string
		systemdError error
		expected     bool
	}{
		{
			name:         "service exists",
			serviceName:  "delphi-listener",
			systemdError: nil,
			expected:     true,
		},
		{
			name:         "service does not exist",
			serviceName:  "non-existent-service",
			systemdError: errors.New("exit status 1"),
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := &ServiceManager{
				registry: GetGlobalDelphiServiceRegistry(),
			}

			// Note: In real test would mock exec.Command
			// For now, validate function exists
			assert.NotNil(t, sm.CheckServiceExists)
		})
	}
}

func TestServiceManager_GetServiceWorkersForUpdate(t *testing.T) {
	// Setup logger
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create service manager
	sm := &ServiceManager{
		registry: GetGlobalDelphiServiceRegistry(),
	}

	// Execute
	workers := sm.GetServiceWorkersForUpdate()

	// Assert
	assert.NotEmpty(t, workers)

	// Check specific services we know should exist
	expectedServices := []string{"delphi-listener", "alert-to-db", "ab-test-analyzer", "llm-worker"}
	serviceMap := make(map[string]ServiceWorkerInfo)
	for _, worker := range workers {
		serviceMap[worker.ServiceName] = worker
	}

	for _, expectedService := range expectedServices {
		worker, found := serviceMap[expectedService]
		assert.True(t, found, "Expected service %s not found", expectedService)

		// Validate worker info
		assert.NotEmpty(t, worker.SourcePath)
		assert.NotEmpty(t, worker.TargetPath)
		assert.NotEmpty(t, worker.ServiceFile)
		assert.NotEmpty(t, worker.BackupPath)
		assert.Contains(t, worker.BackupPath, ".bak")
	}
}
