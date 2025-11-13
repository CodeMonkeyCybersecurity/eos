// Package patterns provides common design patterns for Eos operations
package patterns

import (
	"context"
	"fmt"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AIEOperation represents an Assessment-Intervention-Evaluation operation
type AIEOperation interface {
	// Assess checks if the operation can be performed
	Assess(ctx context.Context) (*AssessmentResult, error)

	// Intervene performs the actual operation
	Intervene(ctx context.Context, assessment *AssessmentResult) (*InterventionResult, error)

	// Evaluate verifies the operation completed successfully
	Evaluate(ctx context.Context, intervention *InterventionResult) (*EvaluationResult, error)
}

// AssessmentResult contains the results of the assessment phase
type AssessmentResult struct {
	CanProceed    bool
	Reason        string
	Prerequisites map[string]bool
	Context       map[string]interface{}
}

// InterventionResult contains the results of the intervention phase
type InterventionResult struct {
	Success      bool
	Message      string
	Changes      []Change
	RollbackData interface{}
}

// EvaluationResult contains the results of the evaluation phase
type EvaluationResult struct {
	Success       bool
	Message       string
	Validations   map[string]ValidationResult
	NeedsRollback bool
}

// Change represents a single change made during intervention
type Change struct {
	Type        string
	Description string
	Before      interface{}
	After       interface{}
}

// ValidationResult represents a single validation check
type ValidationResult struct {
	Passed  bool
	Message string
	Details interface{}
}

// Executor runs AIE operations with proper logging and error handling
type Executor struct {
	logger otelzap.LoggerWithCtx
}

// NewExecutor creates a new AIE operation executor
func NewExecutor(logger otelzap.LoggerWithCtx) *Executor {
	return &Executor{
		logger: logger,
	}
}

// Execute runs a complete AIE operation
func (e *Executor) Execute(ctx context.Context, operation AIEOperation, operationName string) error {
	e.logger.Info("Starting AIE operation",
		zap.String("operation", operationName),
		zap.String("phase", "assessment"))

	// Assessment Phase
	assessment, err := operation.Assess(ctx)
	if err != nil {
		e.logger.Error("Assessment failed",
			zap.String("operation", operationName),
			zap.Error(err))
		return fmt.Errorf("assessment failed: %w", err)
	}

	if !assessment.CanProceed {
		e.logger.Warn("Cannot proceed with operation",
			zap.String("operation", operationName),
			zap.String("reason", assessment.Reason))
		return fmt.Errorf("cannot proceed: %s", assessment.Reason)
	}

	e.logger.Info("Assessment complete",
		zap.String("operation", operationName),
		zap.Any("prerequisites", assessment.Prerequisites))

	// Intervention Phase
	e.logger.Info("Starting intervention",
		zap.String("operation", operationName),
		zap.String("phase", "intervention"))

	intervention, err := operation.Intervene(ctx, assessment)
	if err != nil {
		e.logger.Error("Intervention failed",
			zap.String("operation", operationName),
			zap.Error(err))
		return fmt.Errorf("intervention failed: %w", err)
	}

	if !intervention.Success {
		e.logger.Error("Intervention unsuccessful",
			zap.String("operation", operationName),
			zap.String("message", intervention.Message))
		return fmt.Errorf("intervention unsuccessful: %s", intervention.Message)
	}

	e.logger.Info("Intervention complete",
		zap.String("operation", operationName),
		zap.Int("changes", len(intervention.Changes)))

	// Evaluation Phase
	e.logger.Info("Starting evaluation",
		zap.String("operation", operationName),
		zap.String("phase", "evaluation"))

	evaluation, err := operation.Evaluate(ctx, intervention)
	if err != nil {
		e.logger.Error("Evaluation failed",
			zap.String("operation", operationName),
			zap.Error(err))
		return fmt.Errorf("evaluation failed: %w", err)
	}

	if !evaluation.Success {
		e.logger.Error("Evaluation failed",
			zap.String("operation", operationName),
			zap.String("message", evaluation.Message),
			zap.Bool("needs_rollback", evaluation.NeedsRollback))

		if evaluation.NeedsRollback {
			// TODO: Implement rollback mechanism
			e.logger.Warn("Rollback needed but not implemented",
				zap.String("operation", operationName))
		}

		return fmt.Errorf("evaluation failed: %s", evaluation.Message)
	}

	e.logger.Info("Operation completed successfully",
		zap.String("operation", operationName),
		zap.Any("validations", evaluation.Validations))

	return nil
}

// ExecuteWithRollback runs an AIE operation with rollback support
func (e *Executor) ExecuteWithRollback(ctx context.Context, operation AIEOperation, rollback RollbackOperation, operationName string) error {
	err := e.Execute(ctx, operation, operationName)
	if err != nil {
		e.logger.Warn("Operation failed, attempting rollback",
			zap.String("operation", operationName),
			zap.Error(err))

		rollbackErr := rollback.Rollback(ctx)
		if rollbackErr != nil {
			e.logger.Error("Rollback failed",
				zap.String("operation", operationName),
				zap.Error(rollbackErr))
			return fmt.Errorf("operation failed: %w, rollback failed: %w", err, rollbackErr)
		}

		e.logger.Info("Rollback completed successfully",
			zap.String("operation", operationName))
	}

	return err
}

// RollbackOperation defines rollback functionality
type RollbackOperation interface {
	Rollback(ctx context.Context) error
}
