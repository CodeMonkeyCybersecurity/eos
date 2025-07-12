// pkg/patterns/aie_comprehensive_test.go - Comprehensive tests for AIE pattern framework
package patterns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// MockAIEOperation for testing the executor
type MockAIEOperation struct {
	mock.Mock
}

func (m *MockAIEOperation) Assess(ctx context.Context) (*AssessmentResult, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AssessmentResult), args.Error(1)
}

func (m *MockAIEOperation) Intervene(ctx context.Context, assessment *AssessmentResult) (*InterventionResult, error) {
	args := m.Called(ctx, assessment)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*InterventionResult), args.Error(1)
}

func (m *MockAIEOperation) Evaluate(ctx context.Context, intervention *InterventionResult) (*EvaluationResult, error) {
	args := m.Called(ctx, intervention)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*EvaluationResult), args.Error(1)
}

// createTestContext creates a context with otelzap logger
func createTestContext() (context.Context, otelzap.LoggerWithCtx) {
	ctx := context.Background()
	return ctx, otelzap.Ctx(ctx)
}

// TestExecutor_SuccessfulExecution tests complete successful AIE execution
func TestExecutor_SuccessfulExecution(t *testing.T) {
	ctx, logger := createTestContext()
	executor := NewExecutor(logger)

	mockOp := &MockAIEOperation{}

	// Setup successful execution
	assessment := &AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"prerequisite_1": true,
			"prerequisite_2": true,
		},
		Context: map[string]interface{}{
			"test_data": "value",
		},
	}

	intervention := &InterventionResult{
		Success: true,
		Message: "operation completed successfully",
		Changes: []Change{
			{
				Type:        "test_change",
				Description: "Test change made",
				Before:      "old_value",
				After:       "new_value",
			},
		},
	}

	evaluation := &EvaluationResult{
		Success: true,
		Message: "operation validated successfully",
		Validations: map[string]ValidationResult{
			"test_validation": {
				Passed:  true,
				Message: "validation passed",
			},
		},
	}

	mockOp.On("Assess", ctx).Return(assessment, nil)
	mockOp.On("Intervene", ctx, assessment).Return(intervention, nil)
	mockOp.On("Evaluate", ctx, intervention).Return(evaluation, nil)

	// Execute the operation
	err := executor.Execute(ctx, mockOp, "test_operation")

	// Verify success
	assert.NoError(t, err)
	mockOp.AssertExpectations(t)
}

// TestExecutor_AssessmentFailure tests failure during assessment phase
func TestExecutor_AssessmentFailure(t *testing.T) {
	tests := []struct {
		name          string
		assessment    *AssessmentResult
		assessmentErr error
		expectedError string
	}{
		{
			name:          "assessment_error",
			assessment:    nil,
			assessmentErr: errors.New("assessment failed"),
			expectedError: "assessment failed",
		},
		{
			name: "cannot_proceed",
			assessment: &AssessmentResult{
				CanProceed: false,
				Reason:     "prerequisites not met",
			},
			assessmentErr: nil,
			expectedError: "assessment failed: prerequisites not met",
		},
		{
			name:          "nil_assessment_result",
			assessment:    nil,
			assessmentErr: nil,
			expectedError: "assessment returned nil result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, logger := createTestContext()
			executor := NewExecutor(logger)

			mockOp := &MockAIEOperation{}
			mockOp.On("Assess", ctx).Return(tt.assessment, tt.assessmentErr)

			err := executor.Execute(ctx, mockOp, "test_operation")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
			mockOp.AssertExpectations(t)
		})
	}
}

// TestExecutor_InterventionFailure tests failure during intervention phase
func TestExecutor_InterventionFailure(t *testing.T) {
	tests := []struct {
		name            string
		intervention    *InterventionResult
		interventionErr error
		expectedError   string
	}{
		{
			name:            "intervention_error",
			intervention:    nil,
			interventionErr: errors.New("intervention failed"),
			expectedError:   "intervention failed",
		},
		{
			name: "intervention_unsuccessful",
			intervention: &InterventionResult{
				Success: false,
				Message: "operation failed",
			},
			interventionErr: nil,
			expectedError:   "intervention failed: operation failed",
		},
		{
			name:            "nil_intervention_result",
			intervention:    nil,
			interventionErr: nil,
			expectedError:   "intervention returned nil result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, logger := createTestContext()
			executor := NewExecutor(logger)

			mockOp := &MockAIEOperation{}

			assessment := &AssessmentResult{
				CanProceed: true,
			}

			mockOp.On("Assess", ctx).Return(assessment, nil)
			mockOp.On("Intervene", ctx, assessment).Return(tt.intervention, tt.interventionErr)

			err := executor.Execute(ctx, mockOp, "test_operation")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
			mockOp.AssertExpectations(t)
		})
	}
}

// TestExecutor_EvaluationFailure tests failure during evaluation phase
func TestExecutor_EvaluationFailure(t *testing.T) {
	tests := []struct {
		name          string
		evaluation    *EvaluationResult
		evaluationErr error
		expectedError string
	}{
		{
			name:          "evaluation_error",
			evaluation:    nil,
			evaluationErr: errors.New("evaluation failed"),
			expectedError: "evaluation failed",
		},
		{
			name: "evaluation_unsuccessful",
			evaluation: &EvaluationResult{
				Success: false,
				Message: "validation failed",
			},
			evaluationErr: nil,
			expectedError: "evaluation failed: validation failed",
		},
		{
			name:          "nil_evaluation_result",
			evaluation:    nil,
			evaluationErr: nil,
			expectedError: "evaluation returned nil result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, logger := createTestContext()
			executor := NewExecutor(logger)

			mockOp := &MockAIEOperation{}

			assessment := &AssessmentResult{
				CanProceed: true,
			}

			intervention := &InterventionResult{
				Success: true,
				Message: "operation completed",
			}

			mockOp.On("Assess", ctx).Return(assessment, nil)
			mockOp.On("Intervene", ctx, assessment).Return(intervention, nil)
			mockOp.On("Evaluate", ctx, intervention).Return(tt.evaluation, tt.evaluationErr)

			err := executor.Execute(ctx, mockOp, "test_operation")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
			mockOp.AssertExpectations(t)
		})
	}
}

// TestExecutor_ContextCancellation tests behavior when context is cancelled
func TestExecutor_ContextCancellation(t *testing.T) {
	t.Run("cancellation_during_assessment", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		_, logger := createTestContext()
		executor := NewExecutor(logger)

		mockOp := &MockAIEOperation{}

		// Cancel context before assessment completes
		mockOp.On("Assess", mock.Anything).Run(func(args mock.Arguments) {
			cancel()
		}).Return(nil, context.Canceled)

		err := executor.Execute(ctx, mockOp, "test_operation")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
		mockOp.AssertExpectations(t)
	})

	t.Run("cancellation_during_intervention", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		_, logger := createTestContext()
		executor := NewExecutor(logger)

		mockOp := &MockAIEOperation{}

		assessment := &AssessmentResult{
			CanProceed: true,
		}

		mockOp.On("Assess", mock.Anything).Return(assessment, nil)
		mockOp.On("Intervene", mock.Anything, assessment).Run(func(args mock.Arguments) {
			cancel()
		}).Return(nil, context.Canceled)

		err := executor.Execute(ctx, mockOp, "test_operation")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
		mockOp.AssertExpectations(t)
	})
}

// TestExecutor_Timeout tests timeout behavior
func TestExecutor_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, logger := createTestContext()
	executor := NewExecutor(logger)

	mockOp := &MockAIEOperation{}

	// Simulate slow assessment that times out
	mockOp.On("Assess", mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(200 * time.Millisecond)
	}).Return(nil, context.DeadlineExceeded)

	err := executor.Execute(ctx, mockOp, "test_operation")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "deadline exceeded")
	mockOp.AssertExpectations(t)
}

// TestAssessmentResult_Validation tests assessment result validation
func TestAssessmentResult_Validation(t *testing.T) {
	tests := []struct {
		name       string
		result     *AssessmentResult
		shouldPass bool
	}{
		{
			name: "valid_can_proceed",
			result: &AssessmentResult{
				CanProceed: true,
				Prerequisites: map[string]bool{
					"req1": true,
				},
			},
			shouldPass: true,
		},
		{
			name: "valid_cannot_proceed",
			result: &AssessmentResult{
				CanProceed: false,
				Reason:     "Missing requirements",
				Prerequisites: map[string]bool{
					"req1": false,
				},
			},
			shouldPass: false,
		},
		{
			name: "cannot_proceed_without_reason",
			result: &AssessmentResult{
				CanProceed: false,
			},
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPass {
				assert.True(t, tt.result.CanProceed)
			} else {
				assert.False(t, tt.result.CanProceed)
				if !tt.result.CanProceed && tt.result.Reason == "" {
					t.Log("Assessment cannot proceed but no reason provided")
				}
			}
		})
	}
}

// TestInterventionResult_ChangeTracking tests change tracking in intervention results
func TestInterventionResult_ChangeTracking(t *testing.T) {
	result := &InterventionResult{
		Success: true,
		Message: "Changes applied successfully",
		Changes: []Change{
			{
				Type:        "file_modification",
				Description: "Updated configuration file",
				Before:      "old_config",
				After:       "new_config",
			},
			{
				Type:        "service_restart",
				Description: "Restarted service",
			},
		},
		RollbackData: map[string]interface{}{
			"backup_path":   "/tmp/backup",
			"service_state": "running",
		},
	}

	assert.True(t, result.Success)
	assert.Len(t, result.Changes, 2)
	assert.Equal(t, "file_modification", result.Changes[0].Type)
	assert.Equal(t, "service_restart", result.Changes[1].Type)
	assert.NotNil(t, result.RollbackData)
}

// TestEvaluationResult_ValidationTracking tests validation tracking
func TestEvaluationResult_ValidationTracking(t *testing.T) {
	result := &EvaluationResult{
		Success: true,
		Message: "All validations passed",
		Validations: map[string]ValidationResult{
			"config_valid": {
				Passed:  true,
				Message: "Configuration is valid",
			},
			"service_running": {
				Passed:  true,
				Message: "Service is running",
				Details: "Process ID: 1234",
			},
		},
	}

	assert.True(t, result.Success)
	assert.Len(t, result.Validations, 2)
	assert.True(t, result.Validations["config_valid"].Passed)
	assert.True(t, result.Validations["service_running"].Passed)
	assert.Equal(t, "Process ID: 1234", result.Validations["service_running"].Details)
}

// TestExecutor_RollbackScenario tests rollback when evaluation fails
func TestExecutor_RollbackScenario(t *testing.T) {
	ctx := context.Background()
	_, logger := createTestContext()
	executor := NewExecutor(logger)

	mockOp := &MockAIEOperation{}

	assessment := &AssessmentResult{
		CanProceed: true,
	}

	intervention := &InterventionResult{
		Success: true,
		Message: "operation completed",
		RollbackData: map[string]interface{}{
			"backup_created": true,
			"original_state": "preserved",
		},
	}

	evaluation := &EvaluationResult{
		Success:       false,
		Message:       "validation failed",
		NeedsRollback: true,
		Validations: map[string]ValidationResult{
			"integrity_check": {
				Passed:  false,
				Message: "Data integrity compromised",
			},
		},
	}

	mockOp.On("Assess", ctx).Return(assessment, nil)
	mockOp.On("Intervene", ctx, assessment).Return(intervention, nil)
	mockOp.On("Evaluate", ctx, intervention).Return(evaluation, nil)

	err := executor.Execute(ctx, mockOp, "test_operation")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "evaluation failed: validation failed")

	// Verify that rollback data was available
	assert.NotNil(t, intervention.RollbackData)
	assert.True(t, evaluation.NeedsRollback)

	mockOp.AssertExpectations(t)
}

// TestExecutor_ConcurrentExecution tests thread safety
func TestExecutor_ConcurrentExecution(t *testing.T) {
	const goroutines = 10
	const iterations = 5

	_, logger := createTestContext()
	executor := NewExecutor(logger)

	results := make(chan error, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		go func(goroutineID int) {
			for i := 0; i < iterations; i++ {
				mockOp := &MockAIEOperation{}

				assessment := &AssessmentResult{
					CanProceed: true,
					Context: map[string]interface{}{
						"goroutine_id": goroutineID,
						"iteration":    i,
					},
				}

				intervention := &InterventionResult{
					Success: true,
					Message: "concurrent operation successful",
				}

				evaluation := &EvaluationResult{
					Success: true,
					Message: "concurrent validation successful",
				}

				ctx := context.Background()
				mockOp.On("Assess", ctx).Return(assessment, nil)
				mockOp.On("Intervene", ctx, assessment).Return(intervention, nil)
				mockOp.On("Evaluate", ctx, intervention).Return(evaluation, nil)

				err := executor.Execute(ctx, mockOp, "concurrent_test")
				results <- err
			}
		}(g)
	}

	// Collect all results
	for i := 0; i < goroutines*iterations; i++ {
		err := <-results
		assert.NoError(t, err, "Concurrent execution should succeed")
	}
}

// TestExecutor_EdgeCases tests edge cases and error conditions
func TestExecutor_EdgeCases(t *testing.T) {
	t.Run("nil_operation", func(t *testing.T) {
		ctx := context.Background()
		_, logger := createTestContext()
		executor := NewExecutor(logger)

		err := executor.Execute(ctx, nil, "test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operation cannot be nil")
	})

	t.Run("empty_operation_name", func(t *testing.T) {
		ctx := context.Background()
		_, logger := createTestContext()
		executor := NewExecutor(logger)

		mockOp := &MockAIEOperation{}
		assessment := &AssessmentResult{CanProceed: true}
		intervention := &InterventionResult{Success: true}
		evaluation := &EvaluationResult{Success: true}

		mockOp.On("Assess", ctx).Return(assessment, nil)
		mockOp.On("Intervene", ctx, assessment).Return(intervention, nil)
		mockOp.On("Evaluate", ctx, intervention).Return(evaluation, nil)

		// Should still work with empty name
		err := executor.Execute(ctx, mockOp, "")
		assert.NoError(t, err)
	})
}

// BenchmarkExecutor_SuccessfulExecution benchmarks AIE execution performance
func BenchmarkExecutor_SuccessfulExecution(b *testing.B) {
	ctx := context.Background()
	_, logger := createTestContext()
	executor := NewExecutor(logger)

	assessment := &AssessmentResult{
		CanProceed:    true,
		Prerequisites: map[string]bool{"req1": true},
	}

	intervention := &InterventionResult{
		Success: true,
		Message: "benchmark operation",
		Changes: []Change{{Type: "benchmark", Description: "test change"}},
	}

	evaluation := &EvaluationResult{
		Success: true,
		Message: "benchmark validation",
		Validations: map[string]ValidationResult{
			"test": {Passed: true, Message: "passed"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mockOp := &MockAIEOperation{}
		mockOp.On("Assess", ctx).Return(assessment, nil)
		mockOp.On("Intervene", ctx, assessment).Return(intervention, nil)
		mockOp.On("Evaluate", ctx, intervention).Return(evaluation, nil)

		err := executor.Execute(ctx, mockOp, "benchmark")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Example implementation for testing
type ExampleOperation struct {
	shouldFail string
	logger     otelzap.LoggerWithCtx
}

func (e *ExampleOperation) Assess(ctx context.Context) (*AssessmentResult, error) {
	if e.shouldFail == "assess" {
		return nil, errors.New("assessment failure")
	}

	return &AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"system_ready": true,
		},
	}, nil
}

func (e *ExampleOperation) Intervene(ctx context.Context, assessment *AssessmentResult) (*InterventionResult, error) {
	if e.shouldFail == "intervene" {
		return &InterventionResult{
			Success: false,
			Message: "intervention failure",
		}, nil
	}

	return &InterventionResult{
		Success: true,
		Message: "operation completed",
		Changes: []Change{
			{
				Type:        "example_change",
				Description: "Made example change",
			},
		},
	}, nil
}

func (e *ExampleOperation) Evaluate(ctx context.Context, intervention *InterventionResult) (*EvaluationResult, error) {
	if e.shouldFail == "evaluate" {
		return &EvaluationResult{
			Success: false,
			Message: "evaluation failure",
		}, nil
	}

	return &EvaluationResult{
		Success: true,
		Message: "validation successful",
		Validations: map[string]ValidationResult{
			"example_validation": {
				Passed:  true,
				Message: "validation passed",
			},
		},
	}, nil
}

// TestRealImplementation tests a real AIE implementation
func TestRealImplementation(t *testing.T) {
	ctx := context.Background()
	_, logger := createTestContext()
	executor := NewExecutor(logger)

	tests := []struct {
		name        string
		shouldFail  string
		expectError bool
	}{
		{
			name:        "successful_execution",
			shouldFail:  "",
			expectError: false,
		},
		{
			name:        "assessment_failure",
			shouldFail:  "assess",
			expectError: true,
		},
		{
			name:        "intervention_failure",
			shouldFail:  "intervene",
			expectError: true,
		},
		{
			name:        "evaluation_failure",
			shouldFail:  "evaluate",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := &ExampleOperation{
				shouldFail: tt.shouldFail,
				logger:     otelzap.Ctx(context.Background()),
			}

			err := executor.Execute(ctx, op, "example_operation")

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
