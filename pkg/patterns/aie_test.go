package patterns_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap/zaptest"
)

// MockOperation implements AIEOperation for testing
type MockOperation struct {
	AssessResult      *patterns.AssessmentResult
	AssessError       error
	InterventionResult *patterns.InterventionResult
	InterventionError  error
	EvaluationResult   *patterns.EvaluationResult
	EvaluationError    error
	CallSequence       []string
}

func (m *MockOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	m.CallSequence = append(m.CallSequence, "assess")
	return m.AssessResult, m.AssessError
}

func (m *MockOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	m.CallSequence = append(m.CallSequence, "intervene")
	return m.InterventionResult, m.InterventionError
}

func (m *MockOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	m.CallSequence = append(m.CallSequence, "evaluate")
	return m.EvaluationResult, m.EvaluationError
}

// MockRollbackOperation implements RollbackOperation for testing
type MockRollbackOperation struct {
	RollbackError error
	RolledBack    bool
}

func (m *MockRollbackOperation) Rollback(ctx context.Context) error {
	m.RolledBack = true
	return m.RollbackError
}

func createTestExecutor(t testing.TB) *patterns.Executor {
	logger := zaptest.NewLogger(t)
	otelLogger := otelzap.New(logger)
	return patterns.NewExecutor(otelLogger.Ctx(context.Background()))
}

func TestExecutor_Execute_SuccessfulOperation(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
			Prerequisites: map[string]bool{
				"test_prereq": true,
			},
		},
		InterventionResult: &patterns.InterventionResult{
			Success: true,
			Message: "operation completed",
			Changes: []patterns.Change{
				{
					Type:        "test_change",
					Description: "test change made",
				},
			},
		},
		EvaluationResult: &patterns.EvaluationResult{
			Success: true,
			Message: "operation validated",
			Validations: map[string]patterns.ValidationResult{
				"test_validation": {
					Passed:  true,
					Message: "validation passed",
				},
			},
		},
	}

	err := executor.Execute(ctx, operation, "test_operation")

	assert.NoError(t, err)
	assert.Equal(t, []string{"assess", "intervene", "evaluate"}, operation.CallSequence)
}

func TestExecutor_Execute_AssessmentFails(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessError: errors.New("assessment failed"),
	}

	err := executor.Execute(ctx, operation, "test_operation")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assessment failed")
	assert.Equal(t, []string{"assess"}, operation.CallSequence)
}

func TestExecutor_Execute_AssessmentCannotProceed(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "prerequisites not met",
		},
	}

	err := executor.Execute(ctx, operation, "test_operation")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot proceed")
	assert.Contains(t, err.Error(), "prerequisites not met")
	assert.Equal(t, []string{"assess"}, operation.CallSequence)
}

func TestExecutor_Execute_InterventionFails(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
		},
		InterventionError: errors.New("intervention failed"),
	}

	err := executor.Execute(ctx, operation, "test_operation")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "intervention failed")
	assert.Equal(t, []string{"assess", "intervene"}, operation.CallSequence)
}

func TestExecutor_Execute_InterventionUnsuccessful(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
		},
		InterventionResult: &patterns.InterventionResult{
			Success: false,
			Message: "intervention unsuccessful",
		},
	}

	err := executor.Execute(ctx, operation, "test_operation")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "intervention unsuccessful")
	assert.Equal(t, []string{"assess", "intervene"}, operation.CallSequence)
}

func TestExecutor_Execute_EvaluationFails(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
		},
		InterventionResult: &patterns.InterventionResult{
			Success: true,
			Message: "intervention completed",
		},
		EvaluationError: errors.New("evaluation failed"),
	}

	err := executor.Execute(ctx, operation, "test_operation")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "evaluation failed")
	assert.Equal(t, []string{"assess", "intervene", "evaluate"}, operation.CallSequence)
}

func TestExecutor_Execute_EvaluationUnsuccessful(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
		},
		InterventionResult: &patterns.InterventionResult{
			Success: true,
			Message: "intervention completed",
		},
		EvaluationResult: &patterns.EvaluationResult{
			Success: false,
			Message: "evaluation failed",
			Validations: map[string]patterns.ValidationResult{
				"test_validation": {
					Passed:  false,
					Message: "validation failed",
				},
			},
		},
	}

	err := executor.Execute(ctx, operation, "test_operation")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "evaluation failed")
	assert.Equal(t, []string{"assess", "intervene", "evaluate"}, operation.CallSequence)
}

func TestExecutor_ExecuteWithRollback_Success(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
		},
		InterventionResult: &patterns.InterventionResult{
			Success: true,
			Message: "intervention completed",
		},
		EvaluationResult: &patterns.EvaluationResult{
			Success: true,
			Message: "evaluation passed",
		},
	}

	rollback := &MockRollbackOperation{}

	err := executor.ExecuteWithRollback(ctx, operation, rollback, "test_operation")

	assert.NoError(t, err)
	assert.False(t, rollback.RolledBack) // Should not rollback on success
	assert.Equal(t, []string{"assess", "intervene", "evaluate"}, operation.CallSequence)
}

func TestExecutor_ExecuteWithRollback_FailureTriggersRollback(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
		},
		InterventionError: errors.New("intervention failed"),
	}

	rollback := &MockRollbackOperation{}

	err := executor.ExecuteWithRollback(ctx, operation, rollback, "test_operation")

	assert.Error(t, err)
	assert.True(t, rollback.RolledBack) // Should rollback on failure
	assert.Equal(t, []string{"assess", "intervene"}, operation.CallSequence)
}

func TestExecutor_ExecuteWithRollback_RollbackFails(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
		},
		InterventionError: errors.New("intervention failed"),
	}

	rollback := &MockRollbackOperation{
		RollbackError: errors.New("rollback failed"),
	}

	err := executor.ExecuteWithRollback(ctx, operation, rollback, "test_operation")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "intervention failed")
	assert.Contains(t, err.Error(), "rollback failed")
	assert.True(t, rollback.RolledBack)
}

func TestAssessmentResult_Validation(t *testing.T) {
	tests := []struct {
		name           string
		result         *patterns.AssessmentResult
		expectedValid  bool
		expectedReason string
	}{
		{
			name: "can proceed with prerequisites",
			result: &patterns.AssessmentResult{
				CanProceed: true,
				Prerequisites: map[string]bool{
					"prereq1": true,
					"prereq2": true,
				},
			},
			expectedValid: true,
		},
		{
			name: "cannot proceed with reason",
			result: &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     "missing permissions",
			},
			expectedValid:  false,
			expectedReason: "missing permissions",
		},
		{
			name: "mixed prerequisites",
			result: &patterns.AssessmentResult{
				CanProceed: true,
				Prerequisites: map[string]bool{
					"prereq1": true,
					"prereq2": false,
				},
			},
			expectedValid: true, // CanProceed is the final decision
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedValid, tt.result.CanProceed)
			if !tt.expectedValid {
				assert.Equal(t, tt.expectedReason, tt.result.Reason)
			}
		})
	}
}

func TestInterventionResult_Changes(t *testing.T) {
	result := &patterns.InterventionResult{
		Success: true,
		Message: "operation completed",
		Changes: []patterns.Change{
			{
				Type:        "file_creation",
				Description: "created config file",
				Before:      nil,
				After:       "/etc/config.conf",
			},
			{
				Type:        "service_start",
				Description: "started service",
				Before:      "inactive",
				After:       "active",
			},
		},
	}

	assert.True(t, result.Success)
	assert.Len(t, result.Changes, 2)
	assert.Equal(t, "file_creation", result.Changes[0].Type)
	assert.Equal(t, "service_start", result.Changes[1].Type)
}

func TestEvaluationResult_Validations(t *testing.T) {
	result := &patterns.EvaluationResult{
		Success: true,
		Message: "all validations passed",
		Validations: map[string]patterns.ValidationResult{
			"file_exists": {
				Passed:  true,
				Message: "config file exists",
				Details: "/etc/config.conf",
			},
			"service_running": {
				Passed:  true,
				Message: "service is active",
				Details: "active (running)",
			},
		},
	}

	assert.True(t, result.Success)
	assert.Len(t, result.Validations, 2)

	fileValidation := result.Validations["file_exists"]
	assert.True(t, fileValidation.Passed)
	assert.Equal(t, "config file exists", fileValidation.Message)

	serviceValidation := result.Validations["service_running"]
	assert.True(t, serviceValidation.Passed)
	assert.Equal(t, "service is active", serviceValidation.Message)
}

func TestExecutor_NewExecutor(t *testing.T) {
	logger := zaptest.NewLogger(nil)
	otelLogger := otelzap.New(logger)
	executor := patterns.NewExecutor(otelLogger.Ctx(context.Background()))

	assert.NotNil(t, executor)
}

// Integration test with context cancellation
func TestExecutor_Execute_ContextCancellation(t *testing.T) {
	executor := createTestExecutor(t)
	ctx, cancel := context.WithCancel(context.Background())

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
		},
		InterventionResult: &patterns.InterventionResult{
			Success: true,
			Message: "intervention completed",
		},
		EvaluationResult: &patterns.EvaluationResult{
			Success: true,
			Message: "evaluation passed",
		},
	}

	// Cancel context before execution
	cancel()

	err := executor.Execute(ctx, operation, "test_operation")

	// The operation should still complete as we don't check context in our mock
	// In real implementations, operations should respect context cancellation
	assert.NoError(t, err)
}

// Benchmark test for executor performance
func BenchmarkExecutor_Execute(b *testing.B) {
	executor := createTestExecutor(b)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
			Prerequisites: map[string]bool{
				"test_prereq": true,
			},
		},
		InterventionResult: &patterns.InterventionResult{
			Success: true,
			Message: "operation completed",
		},
		EvaluationResult: &patterns.EvaluationResult{
			Success: true,
			Message: "operation validated",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		operation.CallSequence = nil // Reset for each iteration
		err := executor.Execute(ctx, operation, "benchmark_operation")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test with complex validation scenarios
func TestExecutor_Execute_ComplexValidations(t *testing.T) {
	executor := createTestExecutor(t)
	ctx := context.Background()

	operation := &MockOperation{
		AssessResult: &patterns.AssessmentResult{
			CanProceed: true,
			Prerequisites: map[string]bool{
				"disk_space":     true,
				"permissions":    true,
				"network_access": true,
				"dependencies":   true,
			},
			Context: map[string]interface{}{
				"available_space": "10GB",
				"user_id":         1000,
			},
		},
		InterventionResult: &patterns.InterventionResult{
			Success: true,
			Message: "complex operation completed",
			Changes: []patterns.Change{
				{
					Type:        "file_creation",
					Description: "created database file",
					Before:      nil,
					After:       "/var/lib/app/database.db",
				},
				{
					Type:        "permission_change",
					Description: "set file permissions",
					Before:      "644",
					After:       "600",
				},
				{
					Type:        "service_configuration",
					Description: "updated service config",
					Before:      map[string]interface{}{"enabled": false},
					After:       map[string]interface{}{"enabled": true, "port": 8080},
				},
			},
		},
		EvaluationResult: &patterns.EvaluationResult{
			Success: true,
			Message: "all complex validations passed",
			Validations: map[string]patterns.ValidationResult{
				"database_accessible": {
					Passed:  true,
					Message: "database file is accessible",
					Details: map[string]interface{}{
						"file_size": "1024KB",
						"permissions": "600",
					},
				},
				"service_responding": {
					Passed:  true,
					Message: "service is responding on configured port",
					Details: map[string]interface{}{
						"port": 8080,
						"response_time": "50ms",
					},
				},
				"security_validation": {
					Passed:  true,
					Message: "security requirements met",
					Details: map[string]interface{}{
						"tls_enabled": true,
						"auth_required": true,
					},
				},
			},
		},
	}

	err := executor.Execute(ctx, operation, "complex_operation")

	require.NoError(t, err)
	assert.Equal(t, []string{"assess", "intervene", "evaluate"}, operation.CallSequence)

	// Verify complex data structures
	assert.Len(t, operation.InterventionResult.Changes, 3)
	assert.Len(t, operation.EvaluationResult.Validations, 3)

	// Verify nested data in validations
	dbValidation := operation.EvaluationResult.Validations["database_accessible"]
	assert.True(t, dbValidation.Passed)
	details := dbValidation.Details.(map[string]interface{})
	assert.Equal(t, "1024KB", details["file_size"])
	assert.Equal(t, "600", details["permissions"])
}