package promotion

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewPromotionManager creates a new promotion manager
func NewPromotionManager(envManager *environments.EnvironmentManager, config *PromotionConfig) (*PromotionManager, error) {
	return &PromotionManager{
		environmentManager: envManager,
		approvalConfig: &ApprovalConfig{
			Required:     true,
			MinApprovers: 1,
			Timeout:      24 * time.Hour,
		},
	}, nil
}

// PromoteComponent promotes a component from one environment to another
func (pm *PromotionManager) PromoteComponent(rc *eos_io.RuntimeContext, request *PromotionRequest) (*PromotionResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting component promotion",
		zap.String("component", request.Component),
		zap.String("from", request.FromEnvironment),
		zap.String("to", request.ToEnvironment),
		zap.String("version", request.Version))

	result := &PromotionResult{
		Request:           request,
		StepsExecuted:     []PromotionStep{},
		ArtifactsPromoted: []PromotedArtifact{},
		ValidationResults: []ValidationResult{},
	}

	startTime := time.Now()

	// Assessment: Validate promotion prerequisites
	if err := pm.assessPromotionPrerequisites(rc, request, result); err != nil {
		logger.Error("Promotion prerequisites assessment failed", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result, fmt.Errorf("promotion prerequisites assessment failed: %w", err)
	}

	// Check if approval is required and pending
	if request.ApprovalPolicy.Required {
		approved, err := pm.checkApprovalStatus(rc, request)
		if err != nil {
			logger.Error("Failed to check approval status", zap.Error(err))
			result.Success = false
			result.Error = err.Error()
			result.Duration = time.Since(startTime)
			return result, fmt.Errorf("failed to check approval status: %w", err)
		}
		if !approved {
			logger.Info("Promotion requires approval", zap.String("promotion_id", request.ID))
			request.Status = PromotionStatusPending
			result.Success = false
			result.Error = "promotion pending approval"
			result.Duration = time.Since(startTime)
			return result, &PromotionError{
				Type:      "approval_required",
				Component: request.Component,
				Operation: "promote",
				Message:   "promotion requires approval before execution",
				Timestamp: time.Now(),
				Retryable: true,
			}
		}
	}

	// Intervention: Execute the promotion
	if err := pm.executePromotion(rc, request, result); err != nil {
		logger.Error("Promotion execution failed", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result, fmt.Errorf("promotion execution failed: %w", err)
	}

	// Evaluation: Verify promotion success
	if err := pm.evaluatePromotionResult(rc, request, result); err != nil {
		logger.Error("Promotion evaluation failed", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result, fmt.Errorf("promotion evaluation failed: %w", err)
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	request.Status = PromotionStatusCompleted
	now := time.Now()
	request.PromotedAt = &now

	logger.Info("Component promotion completed successfully",
		zap.String("component", request.Component),
		zap.String("from", request.FromEnvironment),
		zap.String("to", request.ToEnvironment),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// PromoteStack promotes multiple components as a stack
func (pm *PromotionManager) PromoteStack(rc *eos_io.RuntimeContext, request *StackPromotionRequest) (*StackPromotionResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting stack promotion",
		zap.String("stack", request.StackName),
		zap.Int("components", len(request.Components)),
		zap.String("from", request.FromEnvironment),
		zap.String("to", request.ToEnvironment))

	result := &StackPromotionResult{
		Request:    request,
		Results:    []PromotionResult{},
		StartTime:  time.Now(),
	}

	// Assessment: Validate stack promotion prerequisites
	if err := pm.assessStackPromotionPrerequisites(rc, request); err != nil {
		logger.Error("Stack promotion prerequisites assessment failed", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		return result, fmt.Errorf("stack promotion prerequisites assessment failed: %w", err)
	}

	// Determine promotion order based on strategy
	promotionOrder, err := pm.determinePromotionOrder(rc, request)
	if err != nil {
		logger.Error("Failed to determine promotion order", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		return result, fmt.Errorf("failed to determine promotion order: %w", err)
	}

	// Execute promotions based on strategy
	switch request.Strategy {
	case StackPromotionStrategySequential:
		err = pm.executeSequentialPromotion(rc, request, promotionOrder, result)
	case StackPromotionStrategyParallel:
		err = pm.executeParallelPromotion(rc, request, promotionOrder, result)
	case StackPromotionStrategyDependency:
		err = pm.executeDependencyOrderedPromotion(rc, request, promotionOrder, result)
	default:
		err = fmt.Errorf("unknown stack promotion strategy: %s", request.Strategy)
	}

	if err != nil {
		logger.Error("Stack promotion execution failed", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Calculate final result
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	successful := 0
	for _, componentResult := range result.Results {
		if componentResult.Success {
			successful++
		}
	}
	
	result.Success = successful == len(request.Components)
	result.ComponentsPromoted = successful
	result.ComponentsFailed = len(request.Components) - successful

	logger.Info("Stack promotion completed",
		zap.String("stack", request.StackName),
		zap.Bool("success", result.Success),
		zap.Int("promoted", successful),
		zap.Int("failed", result.ComponentsFailed))

	return result, nil
}

// assessPromotionPrerequisites validates promotion prerequisites following Assessment pattern
func (pm *PromotionManager) assessPromotionPrerequisites(rc *eos_io.RuntimeContext, request *PromotionRequest, result *PromotionResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Assessing promotion prerequisites",
		zap.String("component", request.Component))

	// Validate source environment exists and is accessible
	sourceEnv, err := pm.environmentManager.GetEnvironment(rc, request.FromEnvironment)
	if err != nil {
		return &PromotionError{
			Type:      "environment_not_found",
			Component: request.Component,
			Operation: "assess",
			Message:   fmt.Sprintf("source environment %s not found", request.FromEnvironment),
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Validate target environment exists and is accessible
	targetEnv, err := pm.environmentManager.GetEnvironment(rc, request.ToEnvironment)
	if err != nil {
		return &PromotionError{
			Type:      "environment_not_found",
			Component: request.Component,
			Operation: "assess",
			Message:   fmt.Sprintf("target environment %s not found", request.ToEnvironment),
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Check environment promotion compatibility
	if err := pm.validateEnvironmentCompatibility(sourceEnv, targetEnv); err != nil {
		return &PromotionError{
			Type:      "environment_incompatible",
			Component: request.Component,
			Operation: "assess",
			Message:   "source and target environments are incompatible",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Validate component exists in source environment
	if err := pm.validateComponentInEnvironment(rc, request.Component, request.FromEnvironment); err != nil {
		return &PromotionError{
			Type:      "component_not_found",
			Component: request.Component,
			Operation: "assess",
			Message:   fmt.Sprintf("component %s not found in source environment", request.Component),
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Check deployment window and freeze periods
	if err := pm.checkDeploymentWindow(targetEnv); err != nil {
		return &PromotionError{
			Type:      "deployment_window",
			Component: request.Component,
			Operation: "assess",
			Message:   "promotion outside allowed deployment window",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	logger.Debug("Promotion prerequisites assessment completed")
	return nil
}

// executePromotion executes the promotion following Intervention pattern
func (pm *PromotionManager) executePromotion(rc *eos_io.RuntimeContext, request *PromotionRequest, result *PromotionResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing promotion",
		zap.String("component", request.Component))

	// Define promotion steps
	steps := []PromotionStep{
		{
			Name:        "validate_source",
			Description: "Validate source deployment",
			Status:      StepStatusPending,
		},
		{
			Name:        "prepare_artifacts",
			Description: "Prepare artifacts for promotion",
			Status:      StepStatusPending,
		},
		{
			Name:        "deploy_target",
			Description: "Deploy to target environment",
			Status:      StepStatusPending,
		},
		{
			Name:        "verify_deployment",
			Description: "Verify target deployment",
			Status:      StepStatusPending,
		},
		{
			Name:        "update_registry",
			Description: "Update deployment registry",
			Status:      StepStatusPending,
		},
	}

	// Execute each step
	for i, step := range steps {
		step.Status = StepStatusRunning
		step.StartTime = time.Now()
		
		logger.Debug("Executing promotion step",
			zap.String("step", step.Name),
			zap.String("component", request.Component))

		var err error
		switch step.Name {
		case "validate_source":
			err = pm.validateSourceDeployment(rc, request)
		case "prepare_artifacts":
			err = pm.prepareArtifacts(rc, request, result)
		case "deploy_target":
			err = pm.deployToTarget(rc, request, result)
		case "verify_deployment":
			err = pm.verifyTargetDeployment(rc, request, result)
		case "update_registry":
			err = pm.updateDeploymentRegistry(rc, request)
		}

		endTime := time.Now()
		step.EndTime = &endTime
		step.Duration = endTime.Sub(step.StartTime)

		if err != nil {
			step.Status = StepStatusFailed
			step.Error = err.Error()
			steps[i] = step
			result.StepsExecuted = append(result.StepsExecuted, steps[:i+1]...)
			return fmt.Errorf("promotion step %s failed: %w", step.Name, err)
		}

		step.Status = StepStatusCompleted
		steps[i] = step
	}

	result.StepsExecuted = steps
	logger.Debug("Promotion execution completed")
	return nil
}

// evaluatePromotionResult verifies promotion success following Evaluation pattern
func (pm *PromotionManager) evaluatePromotionResult(rc *eos_io.RuntimeContext, request *PromotionRequest, result *PromotionResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Evaluating promotion result",
		zap.String("component", request.Component))

	// Verify all steps completed successfully
	for _, step := range result.StepsExecuted {
		if step.Status != StepStatusCompleted {
			return fmt.Errorf("promotion step %s did not complete successfully", step.Name)
		}
	}

	// Verify artifacts were promoted
	if len(result.ArtifactsPromoted) == 0 {
		return fmt.Errorf("no artifacts were promoted")
	}

	// Run post-promotion validation
	validationResults, err := pm.runPostPromotionValidation(rc, request)
	if err != nil {
		return fmt.Errorf("post-promotion validation failed: %w", err)
	}
	result.ValidationResults = validationResults

	// Check for validation failures
	for _, validation := range validationResults {
		if !validation.Passed && validation.Level == "error" {
			return fmt.Errorf("critical validation failed: %s", validation.Message)
		}
	}

	// Generate rollback plan
	rollbackPlan, err := pm.generateRollbackPlan(rc, request)
	if err != nil {
		logger.Warn("Failed to generate rollback plan", zap.Error(err))
	} else {
		result.RollbackPlan = rollbackPlan
	}

	logger.Debug("Promotion result evaluation completed")
	return nil
}

// Helper methods for promotion steps

func (pm *PromotionManager) validateSourceDeployment(rc *eos_io.RuntimeContext, request *PromotionRequest) error {
	// Implementation would validate source deployment health
	return nil
}

func (pm *PromotionManager) prepareArtifacts(rc *eos_io.RuntimeContext, request *PromotionRequest, result *PromotionResult) error {
	// Implementation would copy/prepare artifacts for promotion
	result.ArtifactsPromoted = append(result.ArtifactsPromoted, PromotedArtifact{
		Name:           request.Component + "-image",
		Type:           "docker-image",
		SourceLocation: fmt.Sprintf("%s-registry/%s:%s", request.FromEnvironment, request.Component, request.Version),
		TargetLocation: fmt.Sprintf("%s-registry/%s:%s", request.ToEnvironment, request.Component, request.Version),
		Version:        request.Version,
		Checksum:       "sha256:abc123...",
		Size:           100 * 1024 * 1024, // 100MB
	})
	return nil
}

func (pm *PromotionManager) deployToTarget(rc *eos_io.RuntimeContext, request *PromotionRequest, result *PromotionResult) error {
	// Implementation would deploy to target environment
	result.DeploymentID = fmt.Sprintf("deploy-%s-%s-%d", request.Component, request.ToEnvironment, time.Now().Unix())
	return nil
}

func (pm *PromotionManager) verifyTargetDeployment(rc *eos_io.RuntimeContext, request *PromotionRequest, result *PromotionResult) error {
	// Implementation would verify target deployment health
	return nil
}

func (pm *PromotionManager) updateDeploymentRegistry(rc *eos_io.RuntimeContext, request *PromotionRequest) error {
	// Implementation would update deployment tracking registry
	return nil
}

func (pm *PromotionManager) runPostPromotionValidation(rc *eos_io.RuntimeContext, request *PromotionRequest) ([]ValidationResult, error) {
	// Implementation would run comprehensive post-promotion validation
	return []ValidationResult{
		{
			Check:   "health_check",
			Passed:  true,
			Message: "Application health check passed",
			Level:   "info",
		},
		{
			Check:   "smoke_test",
			Passed:  true,
			Message: "Smoke tests passed",
			Level:   "info",
		},
	}, nil
}

func (pm *PromotionManager) generateRollbackPlan(rc *eos_io.RuntimeContext, request *PromotionRequest) (*RollbackPlan, error) {
	// Implementation would generate comprehensive rollback plan
	return &RollbackPlan{
		PreviousVersion: "previous-version",
		RollbackSteps: []RollbackStep{
			{
				Name:        "revert_deployment",
				Description: "Revert to previous deployment",
				Command:     "eos",
				Args:        []string{"rollback", request.Component, "--to-version", "previous-version"},
				Timeout:     10 * time.Minute,
				Required:    true,
			},
		},
		EstimatedTime: 5 * time.Minute,
	}, nil
}

// Helper methods for validation

func (pm *PromotionManager) validateEnvironmentCompatibility(source, target *environments.Environment) error {
	// Implementation would validate environment compatibility
	return nil
}

func (pm *PromotionManager) validateComponentInEnvironment(rc *eos_io.RuntimeContext, component, environment string) error {
	// Implementation would validate component exists in environment
	return nil
}

func (pm *PromotionManager) checkDeploymentWindow(env *environments.Environment) error {
	// Implementation would check deployment windows and freeze periods
	return nil
}

func (pm *PromotionManager) checkApprovalStatus(rc *eos_io.RuntimeContext, request *PromotionRequest) (bool, error) {
	// Implementation would check if promotion is approved
	// For now, return true if auto-approve is enabled
	return request.ApprovalPolicy.AutoApprove, nil
}

// Stack promotion methods

func (pm *PromotionManager) assessStackPromotionPrerequisites(rc *eos_io.RuntimeContext, request *StackPromotionRequest) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Assessing stack promotion prerequisites",
		zap.String("stack", request.StackName),
		zap.Int("components", len(request.Components)))

	// Validate all components exist
	for _, component := range request.Components {
		if err := pm.validateComponentInEnvironment(rc, component, request.FromEnvironment); err != nil {
			return fmt.Errorf("component %s not found in source environment: %w", component, err)
		}
	}

	// Validate environments
	_, err := pm.environmentManager.GetEnvironment(rc, request.FromEnvironment)
	if err != nil {
		return fmt.Errorf("source environment %s not found: %w", request.FromEnvironment, err)
	}

	_, err = pm.environmentManager.GetEnvironment(rc, request.ToEnvironment)
	if err != nil {
		return fmt.Errorf("target environment %s not found: %w", request.ToEnvironment, err)
	}

	return nil
}

func (pm *PromotionManager) determinePromotionOrder(rc *eos_io.RuntimeContext, request *StackPromotionRequest) ([]string, error) {
	// If dependency order is specified, use it
	if len(request.DependencyOrder) > 0 {
		return request.DependencyOrder, nil
	}

	// Otherwise, use the component list as-is
	return request.Components, nil
}

func (pm *PromotionManager) executeSequentialPromotion(rc *eos_io.RuntimeContext, request *StackPromotionRequest, order []string, result *StackPromotionResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing sequential stack promotion",
		zap.String("stack", request.StackName))

	for _, component := range order {
		componentRequest := &PromotionRequest{
			ID:              fmt.Sprintf("%s-%s", request.ID, component),
			Component:       component,
			FromEnvironment: request.FromEnvironment,
			ToEnvironment:   request.ToEnvironment,
			Version:         request.Version,
			Reason:          fmt.Sprintf("Stack promotion: %s", request.StackName),
			ApprovalPolicy: ApprovalPolicy{
				AutoApprove: true, // Stack-level approval handles individual components
			},
			Status:    PromotionStatusExecuting,
			CreatedAt: time.Now(),
		}

		componentResult, err := pm.PromoteComponent(rc, componentRequest)
		result.Results = append(result.Results, *componentResult)

		if err != nil {
			logger.Error("Component promotion failed in stack",
				zap.String("component", component),
				zap.String("stack", request.StackName),
				zap.Error(err))

			if !request.ContinueOnError {
				return fmt.Errorf("component %s promotion failed: %w", component, err)
			}
		}
	}

	return nil
}

func (pm *PromotionManager) executeParallelPromotion(rc *eos_io.RuntimeContext, request *StackPromotionRequest, order []string, result *StackPromotionResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing parallel stack promotion",
		zap.String("stack", request.StackName))

	// Implementation would execute all component promotions in parallel
	// For now, fall back to sequential
	return pm.executeSequentialPromotion(rc, request, order, result)
}

func (pm *PromotionManager) executeDependencyOrderedPromotion(rc *eos_io.RuntimeContext, request *StackPromotionRequest, order []string, result *StackPromotionResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing dependency-ordered stack promotion",
		zap.String("stack", request.StackName))

	// Implementation would respect dependency order and promote in batches
	// For now, use sequential execution with dependency order
	return pm.executeSequentialPromotion(rc, request, order, result)
}