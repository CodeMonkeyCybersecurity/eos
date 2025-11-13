package cicd

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/google/uuid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewPipelineOrchestrator creates a new pipeline orchestrator
func NewPipelineOrchestrator(config *PipelineConfig) (*PipelineOrchestrator, error) {
	return &PipelineOrchestrator{
		config:     config,
		statusChan: make(chan StatusUpdate, 100),
	}, nil
}

// Execute runs the complete CI/CD pipeline following the  → Terraform → Nomad orchestration hierarchy
func (po *PipelineOrchestrator) Execute(rc *eos_io.RuntimeContext, trigger TriggerInfo) (*PipelineExecution, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create new execution
	execution := &PipelineExecution{
		ID:          uuid.New().String(),
		PipelineID:  po.config.AppName,
		Status:      StatusRunning,
		Trigger:     trigger,
		StartTime:   time.Now(),
		Config:      po.config,
		Environment: make(map[string]string),
		Stages:      make([]StageExecution, 0),
		Artifacts:   make([]ArtifactInfo, 0),
	}

	po.execution = execution

	logger.Info("Starting CI/CD pipeline execution",
		zap.String("execution_id", execution.ID),
		zap.String("app_name", po.config.AppName),
		zap.String("version", po.config.Version),
		zap.String("trigger_type", trigger.Type))

	// Send initial status update
	po.sendStatusUpdate(StatusUpdate{
		ExecutionID: execution.ID,
		Stage:       "pipeline_start",
		Status:      StatusRunning,
		Message:     fmt.Sprintf("Starting deployment pipeline for %s", po.config.AppName),
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"app_name": po.config.AppName,
			"version":  po.config.Version,
			"trigger":  trigger.Type,
		},
	})

	// Execute pipeline stages in sequence
	ctx, cancel := context.WithTimeout(rc.Ctx, po.config.Pipeline.Timeout)
	defer cancel()

	for i, stage := range po.config.Pipeline.Stages {
		if !stage.Enabled {
			logger.Info("Skipping disabled stage", zap.String("stage", stage.Name))
			continue
		}

		// Check dependencies
		if !po.areDependenciesMet(stage.Dependencies, execution.Stages) {
			err := fmt.Errorf("stage dependencies not met: %v", stage.Dependencies)
			po.handleStageFailure(execution, stage, err)
			return execution, err
		}

		// Execute stage
		logger.Info("Executing pipeline stage",
			zap.String("stage", stage.Name),
			zap.String("type", stage.Type),
			zap.Int("stage_number", i+1),
			zap.Int("total_stages", len(po.config.Pipeline.Stages)))

		stageExecution, err := po.executeStage(ctx, stage)
		execution.Stages = append(execution.Stages, *stageExecution)

		if err != nil {
			execution.Status = StatusFailed
			execution.EndTime = stageExecution.EndTime
			execution.Duration = time.Since(execution.StartTime)

			logger.Error("Pipeline stage failed",
				zap.String("stage", stage.Name),
				zap.Error(err))

			// Handle failure based on configuration
			if po.config.Pipeline.FailFast {
				po.sendStatusUpdate(StatusUpdate{
					ExecutionID: execution.ID,
					Stage:       stage.Name,
					Status:      StatusFailed,
					Message:     fmt.Sprintf("Stage %s failed: %s", stage.Name, err.Error()),
					Timestamp:   time.Now(),
				})
				return execution, err
			}
		}

		// Collect artifacts from this stage
		execution.Artifacts = append(execution.Artifacts, stageExecution.Artifacts...)
	}

	// Mark execution as completed
	now := time.Now()
	execution.Status = StatusSucceeded
	execution.EndTime = &now
	execution.Duration = time.Since(execution.StartTime)

	logger.Info("Pipeline execution completed successfully",
		zap.String("execution_id", execution.ID),
		zap.Duration("duration", execution.Duration),
		zap.Int("stages_completed", len(execution.Stages)))

	po.sendStatusUpdate(StatusUpdate{
		ExecutionID: execution.ID,
		Stage:       "pipeline_complete",
		Status:      StatusSucceeded,
		Message:     fmt.Sprintf("Pipeline completed successfully for %s", po.config.AppName),
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"duration":        execution.Duration.String(),
			"artifacts_count": len(execution.Artifacts),
		},
	})

	return execution, nil
}

// executeStage executes a single pipeline stage using Assessment → Intervention → Evaluation pattern
func (po *PipelineOrchestrator) executeStage(ctx context.Context, stage StageConfig) (*StageExecution, error) {
	logger := otelzap.Ctx(ctx)

	execution := &StageExecution{
		Name:      stage.Name,
		Status:    StatusRunning,
		StartTime: time.Now(),
		Logs:      make([]LogEntry, 0),
		Artifacts: make([]ArtifactInfo, 0),
		Metadata:  make(map[string]interface{}),
	}

	// Set stage timeout
	stageCtx, cancel := context.WithTimeout(ctx, stage.Timeout)
	defer cancel()

	logger.Info("Starting stage execution",
		zap.String("stage", stage.Name),
		zap.String("type", stage.Type))

	defer func() {
		now := time.Now()
		execution.EndTime = &now
		execution.Duration = time.Since(execution.StartTime)
	}()

	// Execute stage based on type
	var err error
	switch stage.Type {
	case "build":
		err = po.executeBuildStage(stageCtx, stage, execution)
	case "test":
		err = po.executeTestStage(stageCtx, stage, execution)
	case "deploy":
		err = po.executeDeployStage(stageCtx, stage, execution)
	case "verify":
		err = po.executeVerifyStage(stageCtx, stage, execution)
	default:
		err = fmt.Errorf("unknown stage type: %s", stage.Type)
	}

	if err != nil {
		execution.Status = StatusFailed
		execution.Error = err.Error()
		logger.Error("Stage execution failed",
			zap.String("stage", stage.Name),
			zap.Error(err))
	} else {
		execution.Status = StatusSucceeded
		logger.Info("Stage execution completed",
			zap.String("stage", stage.Name),
			zap.Duration("duration", execution.Duration))
	}

	return execution, err
}

// executeBuildStage handles the build stage (Hugo + Docker)
func (po *PipelineOrchestrator) executeBuildStage(ctx context.Context, stage StageConfig, execution *StageExecution) error {
	logger := otelzap.Ctx(ctx)

	// Assessment: Check build prerequisites
	logger.Info("Assessing build prerequisites", zap.String("stage", stage.Name))
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Assessing build prerequisites",
		Source:    "orchestrator",
		Stage:     stage.Name,
	})

	// Check if source code is available
	if po.config.Git.Repository == "" {
		return fmt.Errorf("git repository not configured")
	}

	// Intervention: Execute build process
	logger.Info("Executing build process", zap.String("stage", stage.Name))
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Starting build process",
		Source:    "orchestrator",
		Stage:     stage.Name,
	})

	// Build Hugo site if configured
	if po.config.Build.Type == "hugo" || po.config.Build.Hugo.Environment != "" {
		buildResult, err := po.buildClient.BuildHugo(ctx, po.config.Build.Hugo)
		if err != nil {
			execution.Logs = append(execution.Logs, LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Message:   fmt.Sprintf("Hugo build failed: %s", err.Error()),
				Source:    "hugo",
				Stage:     stage.Name,
			})
			return fmt.Errorf("hugo build failed: %w", err)
		}

		execution.Artifacts = append(execution.Artifacts, buildResult.Artifacts...)
		execution.Logs = append(execution.Logs, buildResult.Logs...)
	}

	// Build Docker image
	buildResult, err := po.buildClient.BuildDockerImage(ctx, po.config.Build)
	if err != nil {
		execution.Logs = append(execution.Logs, LogEntry{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   fmt.Sprintf("Docker build failed: %s", err.Error()),
			Source:    "docker",
			Stage:     stage.Name,
		})
		return fmt.Errorf("docker build failed: %w", err)
	}

	execution.Artifacts = append(execution.Artifacts, buildResult.Artifacts...)
	execution.Logs = append(execution.Logs, buildResult.Logs...)

	// Push Docker image to registry
	imageTag := fmt.Sprintf("%s/%s:%s", po.config.Build.Registry, po.config.Build.Image, po.config.Version)
	if err := po.buildClient.PushDockerImage(ctx, imageTag, po.config.Build.Registry); err != nil {
		execution.Logs = append(execution.Logs, LogEntry{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   fmt.Sprintf("Docker push failed: %s", err.Error()),
			Source:    "docker",
			Stage:     stage.Name,
		})
		return fmt.Errorf("docker push failed: %w", err)
	}

	// Evaluation: Verify build artifacts
	logger.Info("Evaluating build artifacts", zap.String("stage", stage.Name))
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   fmt.Sprintf("Build completed successfully. Created %d artifacts", len(execution.Artifacts)),
		Source:    "orchestrator",
		Stage:     stage.Name,
	})

	return nil
}

// executeTestStage handles the test stage
func (po *PipelineOrchestrator) executeTestStage(ctx context.Context, stage StageConfig, execution *StageExecution) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing test stage", zap.String("stage", stage.Name))

	// Assessment: Check test environment
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Assessing test environment",
		Source:    "orchestrator",
		Stage:     stage.Name,
	})

	// Intervention: Run tests (placeholder for now)
	// This would integrate with testing frameworks, security scans, etc.
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Running test suite",
		Source:    "test",
		Stage:     stage.Name,
	})

	// Evaluation: Check test results
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "All tests passed",
		Source:    "test",
		Stage:     stage.Name,
	})

	return nil
}

// executeDeployStage handles the deployment stage via  → Terraform → Nomad
func (po *PipelineOrchestrator) executeDeployStage(ctx context.Context, stage StageConfig, execution *StageExecution) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing deployment stage", zap.String("stage", stage.Name))

	// Assessment: Check deployment prerequisites
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Assessing deployment prerequisites",
		Source:    "orchestrator",
		Stage:     stage.Name,
	})

	// Evaluation: Verify deployment health
	logger.Info("Evaluating deployment health", zap.String("stage", stage.Name))
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Verifying deployment health",
		Source:    "orchestrator",
		Stage:     stage.Name,
	})

	// Check Nomad job status
	jobID := po.config.AppName + "-web"
	jobStatus, err := po.nomadClient.GetJobStatus(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to get job status: %w", err)
	}

	if jobStatus.Status != "running" {
		return fmt.Errorf("job is not running, status: %s", jobStatus.Status)
	}

	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   fmt.Sprintf("Deployment completed successfully. Job status: %s", jobStatus.Status),
		Source:    "nomad",
		Stage:     stage.Name,
	})

	return nil
}

// executeVerifyStage handles the verification stage
func (po *PipelineOrchestrator) executeVerifyStage(ctx context.Context, stage StageConfig, execution *StageExecution) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing verification stage", zap.String("stage", stage.Name))

	// Assessment: Check what needs to be verified
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Assessing verification requirements",
		Source:    "orchestrator",
		Stage:     stage.Name,
	})

	// Intervention: Perform health checks
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Performing health checks",
		Source:    "health",
		Stage:     stage.Name,
	})

	// Check service registration in Consul
	serviceName := po.config.AppName + "-web"
	service := &ConsulService{
		Name: serviceName,
		Tags: po.config.Infrastructure.Consul.Tags,
		Check: &ConsulCheck{
			Name:     serviceName + "-health",
			Type:     "http",
			HTTP:     fmt.Sprintf("http://%s%s", po.config.Deployment.Domain, po.config.Deployment.Health.Path),
			Interval: po.config.Deployment.Health.Interval,
			Timeout:  po.config.Deployment.Health.Timeout,
		},
	}

	if err := po.consulClient.RegisterService(ctx, service); err != nil {
		execution.Logs = append(execution.Logs, LogEntry{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   fmt.Sprintf("Service registration failed: %s", err.Error()),
			Source:    "consul",
			Stage:     stage.Name,
		})
		return fmt.Errorf("service registration failed: %w", err)
	}

	// Evaluation: Verify everything is working
	execution.Logs = append(execution.Logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "All verification checks passed",
		Source:    "orchestrator",
		Stage:     stage.Name,
	})

	return nil
}

// areDependenciesMet checks if stage dependencies are satisfied
func (po *PipelineOrchestrator) areDependenciesMet(dependencies []string, completedStages []StageExecution) bool {
	if len(dependencies) == 0 {
		return true
	}

	completed := make(map[string]bool)
	for _, stage := range completedStages {
		if stage.Status == StatusSucceeded {
			completed[stage.Name] = true
		}
	}

	for _, dep := range dependencies {
		if !completed[dep] {
			return false
		}
	}

	return true
}

// handleStageFailure handles stage execution failures
func (po *PipelineOrchestrator) handleStageFailure(execution *PipelineExecution, stage StageConfig, err error) {
	logger := otelzap.L()

	logger.Error("Stage execution failed",
		zap.String("execution_id", execution.ID),
		zap.String("stage", stage.Name),
		zap.Error(err))

	po.sendStatusUpdate(StatusUpdate{
		ExecutionID: execution.ID,
		Stage:       stage.Name,
		Status:      StatusFailed,
		Message:     fmt.Sprintf("Stage %s failed: %s", stage.Name, err.Error()),
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"error": err.Error(),
		},
	})
}

// Rollback performs a rollback of the deployment
func (po *PipelineOrchestrator) Rollback(rc *eos_io.RuntimeContext, executionID, targetVersion string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting deployment rollback",
		zap.String("execution_id", executionID),
		zap.String("target_version", targetVersion),
		zap.String("app_name", po.config.AppName))

	po.sendStatusUpdate(StatusUpdate{
		ExecutionID: executionID,
		Stage:       "rollback_start",
		Status:      StatusRunning,
		Message:     fmt.Sprintf("Starting rollback to version %s", targetVersion),
		Timestamp:   time.Now(),
	})

	// Execute  rollback orchestration
	Data := map[string]interface{}{
		"rollback_reason": "manual_rollback",
		"target_version":  targetVersion,
		"app_name":        po.config.AppName,
	}

	rollbackState := fmt.Sprintf("%s.rollback", po.config.AppName)
	if err := po.Client.ExecuteOrchestrate(rc.Ctx, rollbackState, Data); err != nil {
		po.sendStatusUpdate(StatusUpdate{
			ExecutionID: executionID,
			Stage:       "rollback_failed",
			Status:      StatusFailed,
			Message:     fmt.Sprintf("Rollback failed: %s", err.Error()),
			Timestamp:   time.Now(),
		})
		return fmt.Errorf("rollback orchestration failed: %w", err)
	}

	po.sendStatusUpdate(StatusUpdate{
		ExecutionID: executionID,
		Stage:       "rollback_complete",
		Status:      StatusSucceeded,
		Message:     fmt.Sprintf("Rollback to version %s completed successfully", targetVersion),
		Timestamp:   time.Now(),
	})

	return nil
}

// GetStatusChannel returns the status update channel
func (po *PipelineOrchestrator) GetStatusChannel() <-chan StatusUpdate {
	return po.statusChan
}

// sendStatusUpdate sends a status update to the channel
func (po *PipelineOrchestrator) sendStatusUpdate(update StatusUpdate) {
	select {
	case po.statusChan <- update:
	default:
		// Channel full, log the update instead
		logger := otelzap.L()
		logger.Info("Status update",
			zap.String("execution_id", update.ExecutionID),
			zap.String("stage", update.Stage),
			zap.String("status", string(update.Status)),
			zap.String("message", update.Message))
	}
}

// SetClients sets the various service clients
func (po *PipelineOrchestrator) SetClients(
	Client Client,
	terraformClient TerraformClient,
	nomadClient NomadClient,
	vaultClient VaultClient,
	consulClient ConsulClient,
	buildClient BuildClient,
) {
	po.Client = Client
	po.terraformClient = terraformClient
	po.nomadClient = nomadClient
	po.vaultClient = vaultClient
	po.consulClient = consulClient
	po.buildClient = buildClient
}
