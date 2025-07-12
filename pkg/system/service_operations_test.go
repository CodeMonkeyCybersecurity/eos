package system_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap/zaptest"
)

// MockSaltClient implements saltstack.ClientInterface for testing system operations
type MockSaltClient struct {
	CmdRunResults map[string]string
	CmdRunErrors  map[string]error
	CmdRunCalls   []CmdRunCall
}

type CmdRunCall struct {
	Target  string
	Command string
}

func (m *MockSaltClient) CmdRun(ctx context.Context, target string, command string) (string, error) {
	if m.CmdRunCalls == nil {
		m.CmdRunCalls = make([]CmdRunCall, 0)
	}
	m.CmdRunCalls = append(m.CmdRunCalls, CmdRunCall{
		Target:  target,
		Command: command,
	})

	if m.CmdRunErrors != nil {
		if err, exists := m.CmdRunErrors[command]; exists {
			return "", err
		}
	}
	if m.CmdRunResults != nil {
		if result, exists := m.CmdRunResults[command]; exists {
			return result, nil
		}
	}
	return "", errors.New("command not found in mock")
}

// Other methods needed for the interface
func (m *MockSaltClient) TestPing(ctx context.Context, target string) (bool, error) {
	return true, nil
}

func (m *MockSaltClient) StateApply(ctx context.Context, target string, state string, pillar map[string]interface{}) error {
	return nil
}

func (m *MockSaltClient) GrainGet(ctx context.Context, target string, grain string) (map[string]interface{}, error) {
	return nil, nil
}

func (m *MockSaltClient) CheckMinion(ctx context.Context, minion string) (bool, error) {
	return true, nil
}

func createTestLogger(t *testing.T) otelzap.LoggerWithCtx {
	logger := zaptest.NewLogger(t)
	return otelzap.New(logger).Ctx(context.Background())
}

// Test ServiceOperation
func TestServiceOperation_Assess_SystemdAvailable(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl --version": "systemd 249",
			"systemctl cat nginx >/dev/null 2>&1 && echo exists || echo notfound": "exists",
			"systemctl is-active nginx 2>/dev/null || echo inactive":              "inactive",
			"systemctl is-enabled nginx 2>/dev/null || echo disabled":             "disabled",
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nginx",
		Action:      "start",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.True(t, result.CanProceed)
	assert.True(t, result.Prerequisites["systemd_available"])
	assert.True(t, result.Prerequisites["service_exists"])
	assert.Equal(t, "inactive", result.Context["current_state"])
	assert.Equal(t, "disabled", result.Context["enabled_state"])
}

func TestServiceOperation_Assess_SystemdNotAvailable(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunErrors: map[string]error{
			"systemctl --version": errors.New("command not found"),
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nginx",
		Action:      "start",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Equal(t, "systemd not available on target", result.Reason)
}

func TestServiceOperation_Assess_ServiceNotFound(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl --version": "systemd 249",
			"systemctl cat nonexistent >/dev/null 2>&1 && echo exists || echo notfound": "notfound",
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nonexistent",
		Action:      "start",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Equal(t, "service nonexistent not found", result.Reason)
	assert.False(t, result.Prerequisites["service_exists"])
}

func TestServiceOperation_Assess_AlreadyActive(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl --version": "systemd 249",
			"systemctl cat nginx >/dev/null 2>&1 && echo exists || echo notfound": "exists",
			"systemctl is-active nginx 2>/dev/null || echo inactive":              "active",
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nginx",
		Action:      "start",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Equal(t, "service is already active", result.Reason)
}

func TestServiceOperation_Intervene_StartService(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl start nginx": "",
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nginx",
		Action:      "start",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{
		CanProceed: true,
		Context: map[string]interface{}{
			"current_state": "inactive",
		},
	}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "service nginx start completed", result.Message)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "service_operation", result.Changes[0].Type)

	// Verify the correct command was called
	require.Len(t, saltClient.CmdRunCalls, 1)
	assert.Equal(t, "systemctl start nginx", saltClient.CmdRunCalls[0].Command)
}

func TestServiceOperation_Intervene_CommandFails(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunErrors: map[string]error{
			"systemctl start nginx": errors.New("service failed to start"),
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nginx",
		Action:      "start",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "service operation failed")
}

func TestServiceOperation_Evaluate_StartSuccess(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl is-active nginx": "active",
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nginx",
		Action:      "start",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "service started",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "service operation validated", result.Message)
	assert.True(t, result.Validations["service_active"].Passed)
}

func TestServiceOperation_Evaluate_StartFailed(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl is-active nginx": "failed",
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nginx",
		Action:      "start",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "service started",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.False(t, result.Validations["service_active"].Passed)
	assert.Contains(t, result.Validations["service_active"].Message, "not active")
}

// Test different service actions
func TestServiceOperation_AllActions(t *testing.T) {
	tests := []struct {
		name           string
		action         string
		currentState   string
		enabledState   string
		shouldProceed  bool
		expectedReason string
	}{
		{
			name:          "start inactive service",
			action:        "start",
			currentState:  "inactive",
			enabledState:  "disabled",
			shouldProceed: true,
		},
		{
			name:           "start active service",
			action:         "start",
			currentState:   "active",
			enabledState:   "enabled",
			shouldProceed:  false,
			expectedReason: "service is already active",
		},
		{
			name:          "stop active service",
			action:        "stop",
			currentState:  "active",
			enabledState:  "enabled",
			shouldProceed: true,
		},
		{
			name:           "stop inactive service",
			action:         "stop",
			currentState:   "inactive",
			enabledState:   "disabled",
			shouldProceed:  false,
			expectedReason: "service is already inactive",
		},
		{
			name:          "enable disabled service",
			action:        "enable",
			currentState:  "inactive",
			enabledState:  "disabled",
			shouldProceed: true,
		},
		{
			name:           "enable enabled service",
			action:         "enable",
			currentState:   "active",
			enabledState:   "enabled",
			shouldProceed:  false,
			expectedReason: "service is already enabled",
		},
		{
			name:          "disable enabled service",
			action:        "disable",
			currentState:  "active",
			enabledState:  "enabled",
			shouldProceed: true,
		},
		{
			name:           "disable disabled service",
			action:         "disable",
			currentState:   "inactive",
			enabledState:   "disabled",
			shouldProceed:  false,
			expectedReason: "service is already disabled",
		},
		{
			name:          "mask any service",
			action:        "mask",
			currentState:  "active",
			enabledState:  "enabled",
			shouldProceed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createTestLogger(t)
			saltClient := &MockSaltClient{
				CmdRunResults: map[string]string{
					"systemctl --version": "systemd 249",
					"systemctl cat testservice >/dev/null 2>&1 && echo exists || echo notfound": "exists",
					"systemctl is-active testservice 2>/dev/null || echo inactive":              tt.currentState,
					"systemctl is-enabled testservice 2>/dev/null || echo disabled":             tt.enabledState,
				},
			}

			operation := &system.ServiceOperation{
				ServiceName: "testservice",
				Action:      tt.action,
				Target:      "test-target",
				SaltClient:  saltClient,
				Logger:      logger,
			}

			ctx := context.Background()
			result, err := operation.Assess(ctx)

			require.NoError(t, err)
			assert.Equal(t, tt.shouldProceed, result.CanProceed)
			if !tt.shouldProceed {
				assert.Contains(t, result.Reason, tt.expectedReason)
			}
		})
	}
}

// Test SleepDisableOperation
func TestSleepDisableOperation_Assess(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl --version": "systemd 249",
			"systemctl is-enabled sleep.target 2>/dev/null || echo not-found":        "enabled",
			"systemctl is-enabled suspend.target 2>/dev/null || echo not-found":      "enabled",
			"systemctl is-enabled hibernate.target 2>/dev/null || echo not-found":    "disabled",
			"systemctl is-enabled hybrid-sleep.target 2>/dev/null || echo not-found": "not-found",
		},
	}

	operation := &system.SleepDisableOperation{
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.True(t, result.CanProceed)
	assert.True(t, result.Prerequisites["sleep.target_exists"])
	assert.True(t, result.Prerequisites["suspend.target_exists"])
	assert.True(t, result.Prerequisites["hibernate.target_exists"])
	assert.False(t, result.Prerequisites["hybrid-sleep.target_exists"])
}

func TestSleepDisableOperation_Intervene(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl mask sleep.target":        "",
			"systemctl mask suspend.target":      "",
			"systemctl mask hibernate.target":    "",
			"systemctl mask hybrid-sleep.target": "",
			"echo '[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\nHandleLidSwitchDocked=ignore\nHandleSuspendKey=ignore\nHandleHibernateKey=ignore\nHandlePowerKey=poweroff' > /etc/systemd/logind.conf.d/disable-sleep.conf": "",
			"systemctl restart systemd-logind": "",
		},
	}

	operation := &system.SleepDisableOperation{
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "sleep functionality disabled", result.Message)
	assert.GreaterOrEqual(t, len(result.Changes), 4) // At least 4 mask operations
}

func TestSleepDisableOperation_Evaluate(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl is-enabled sleep.target":        "masked",
			"systemctl is-enabled suspend.target":      "masked",
			"systemctl is-enabled hibernate.target":    "masked",
			"systemctl is-enabled hybrid-sleep.target": "masked",
			"grep -q 'HandleSuspendKey=ignore' /etc/systemd/logind.conf.d/disable-sleep.conf && echo configured || echo missing": "configured",
		},
	}

	operation := &system.SleepDisableOperation{
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "sleep disabled",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "sleep disable validation completed", result.Message)
	assert.True(t, result.Validations["sleep.target_masked"].Passed)
	assert.True(t, result.Validations["suspend.target_masked"].Passed)
	assert.True(t, result.Validations["hibernate.target_masked"].Passed)
	assert.True(t, result.Validations["hybrid-sleep.target_masked"].Passed)
	assert.True(t, result.Validations["logind_configured"].Passed)
}

// Test PortKillOperation
func TestPortKillOperation_Assess_ProcessesFound(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"lsof -ti:8080 2>/dev/null || echo none": "1234\n5678",
		},
	}

	operation := &system.PortKillOperation{
		Port:       8080,
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.True(t, result.CanProceed)
	assert.True(t, result.Prerequisites["processes_found"])
	assert.Equal(t, []string{"1234", "5678"}, result.Context["pids"])
	assert.Equal(t, 2, result.Context["pid_count"])
}

func TestPortKillOperation_Assess_NoProcesses(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"lsof -ti:8080 2>/dev/null || echo none": "none",
		},
	}

	operation := &system.PortKillOperation{
		Port:       8080,
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Equal(t, "no processes found on port", result.Reason)
}

func TestPortKillOperation_Intervene(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"lsof -ti:8080 | xargs -r kill -9": "",
		},
	}

	operation := &system.PortKillOperation{
		Port:       8080,
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{
		CanProceed: true,
		Context: map[string]interface{}{
			"pids": []string{"1234", "5678"},
		},
	}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "killed processes on port 8080", result.Message)
	assert.Len(t, result.Changes, 2) // One change per PID
}

func TestPortKillOperation_Evaluate_Success(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"lsof -ti:8080 2>/dev/null | wc -l": "0",
		},
	}

	operation := &system.PortKillOperation{
		Port:       8080,
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "processes killed",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "no processes remain on port", result.Message)
	assert.True(t, result.Validations["port_clear"].Passed)
}

func TestPortKillOperation_Evaluate_ProcessesRemain(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"lsof -ti:8080 2>/dev/null | wc -l": "2",
		},
	}

	operation := &system.PortKillOperation{
		Port:       8080,
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "processes killed",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "processes still exist on port", result.Message)
	assert.False(t, result.Validations["port_clear"].Passed)
}

// Test helper functions
func TestManageService(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl --version": "systemd 249",
			"systemctl cat nginx >/dev/null 2>&1 && echo exists || echo notfound": "exists",
			"systemctl is-active nginx 2>/dev/null || echo inactive":              "inactive",
			"systemctl is-enabled nginx 2>/dev/null || echo disabled":             "disabled",
			"systemctl start nginx":     "",
			"systemctl is-active nginx": "active",
		},
	}

	ctx := context.Background()
	err := system.ManageService(ctx, logger, saltClient, "test-target", "nginx", "start")

	assert.NoError(t, err)

	// Verify the correct commands were called
	commandsRun := make(map[string]bool)
	for _, call := range saltClient.CmdRunCalls {
		commandsRun[call.Command] = true
	}
	assert.True(t, commandsRun["systemctl start nginx"])
}

func TestDisableSystemSleep(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl --version": "systemd 249",
			"systemctl is-enabled sleep.target 2>/dev/null || echo not-found":        "enabled",
			"systemctl is-enabled suspend.target 2>/dev/null || echo not-found":      "enabled",
			"systemctl is-enabled hibernate.target 2>/dev/null || echo not-found":    "enabled",
			"systemctl is-enabled hybrid-sleep.target 2>/dev/null || echo not-found": "enabled",
			"systemctl mask sleep.target":                                            "",
			"systemctl mask suspend.target":                                          "",
			"systemctl mask hibernate.target":                                        "",
			"systemctl mask hybrid-sleep.target":                                     "",
			"echo '[Login]\\nHandleLidSwitch=ignore\\nHandleLidSwitchExternalPower=ignore\\nHandleLidSwitchDocked=ignore\\nHandleSuspendKey=ignore\\nHandleHibernateKey=ignore\\nHandlePowerKey=poweroff' > /etc/systemd/logind.conf.d/disable-sleep.conf": "",
			"systemctl restart systemd-logind":         "",
			"systemctl is-enabled sleep.target":        "masked",
			"systemctl is-enabled suspend.target":      "masked",
			"systemctl is-enabled hibernate.target":    "masked",
			"systemctl is-enabled hybrid-sleep.target": "masked",
			"grep -q 'HandleSuspendKey=ignore' /etc/systemd/logind.conf.d/disable-sleep.conf && echo configured || echo missing": "configured",
		},
	}

	ctx := context.Background()
	err := system.DisableSystemSleep(ctx, logger, saltClient, "test-target")

	assert.NoError(t, err)
}

func TestKillProcessesByPort(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"lsof -ti:8080 2>/dev/null || echo none": "1234\n5678",
			"lsof -ti:8080 | xargs -r kill -9":       "",
			"lsof -ti:8080 2>/dev/null | wc -l":      "0",
		},
	}

	ctx := context.Background()
	err := system.KillProcessesByPort(ctx, logger, saltClient, "test-target", 8080)

	assert.NoError(t, err)
}

// Benchmark tests
func BenchmarkServiceOperation_Assess(b *testing.B) {
	logger := zaptest.NewLogger(b)
	otelLogger := otelzap.New(logger).Ctx(context.Background())
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"systemctl --version": "systemd 249",
			"systemctl cat nginx >/dev/null 2>&1 && echo exists || echo notfound": "exists",
			"systemctl is-active nginx 2>/dev/null || echo inactive":              "inactive",
			"systemctl is-enabled nginx 2>/dev/null || echo disabled":             "disabled",
		},
	}

	operation := &system.ServiceOperation{
		ServiceName: "nginx",
		Action:      "start",
		Target:      "bench-target",
		SaltClient:  saltClient,
		Logger:      otelLogger,
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		saltClient.CmdRunCalls = nil // Reset calls
		_, err := operation.Assess(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Integration test
func TestSystemOperations_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			// Service operation sequence
			"systemctl --version": "systemd 249",
			"systemctl cat nginx >/dev/null 2>&1 && echo exists || echo notfound": "exists",
			"systemctl is-active nginx 2>/dev/null || echo inactive":              "inactive",
			"systemctl is-enabled nginx 2>/dev/null || echo disabled":             "disabled",
			"systemctl start nginx":     "",
			"systemctl is-active nginx": "active",

			// Sleep disable sequence
			"systemctl is-enabled sleep.target 2>/dev/null || echo not-found":        "enabled",
			"systemctl is-enabled suspend.target 2>/dev/null || echo not-found":      "enabled",
			"systemctl is-enabled hibernate.target 2>/dev/null || echo not-found":    "enabled",
			"systemctl is-enabled hybrid-sleep.target 2>/dev/null || echo not-found": "enabled",
			"systemctl mask sleep.target":                                            "",
			"systemctl mask suspend.target":                                          "",
			"systemctl mask hibernate.target":                                        "",
			"systemctl mask hybrid-sleep.target":                                     "",
			"echo '[Login]\\nHandleLidSwitch=ignore\\nHandleLidSwitchExternalPower=ignore\\nHandleLidSwitchDocked=ignore\\nHandleSuspendKey=ignore\\nHandleHibernateKey=ignore\\nHandlePowerKey=poweroff' > /etc/systemd/logind.conf.d/disable-sleep.conf": "",
			"systemctl restart systemd-logind":         "",
			"systemctl is-enabled sleep.target":        "masked",
			"systemctl is-enabled suspend.target":      "masked",
			"systemctl is-enabled hibernate.target":    "masked",
			"systemctl is-enabled hybrid-sleep.target": "masked",
			"grep -q 'HandleSuspendKey=ignore' /etc/systemd/logind.conf.d/disable-sleep.conf && echo configured || echo missing": "configured",
		},
	}

	ctx := context.Background()

	// Test complete service management workflow
	t.Run("service start workflow", func(t *testing.T) {
		err := system.ManageService(ctx, logger, saltClient, "test-target", "nginx", "start")
		require.NoError(t, err)

		// Verify commands were executed in order
		commands := make([]string, len(saltClient.CmdRunCalls))
		for i, call := range saltClient.CmdRunCalls {
			commands[i] = call.Command
		}

		// Should include assessment, intervention, and evaluation commands
		assert.Contains(t, commands, "systemctl --version")
		assert.Contains(t, commands, "systemctl start nginx")
		assert.Contains(t, commands, "systemctl is-active nginx")
	})

	// Reset for next test
	saltClient.CmdRunCalls = nil

	t.Run("system sleep disable workflow", func(t *testing.T) {
		err := system.DisableSystemSleep(ctx, logger, saltClient, "test-target")
		require.NoError(t, err)

		// Verify sleep targets were masked
		commands := make([]string, len(saltClient.CmdRunCalls))
		for i, call := range saltClient.CmdRunCalls {
			commands[i] = call.Command
		}

		assert.Contains(t, commands, "systemctl mask sleep.target")
		assert.Contains(t, commands, "systemctl mask suspend.target")
		assert.Contains(t, commands, "systemctl restart systemd-logind")
	})
}
