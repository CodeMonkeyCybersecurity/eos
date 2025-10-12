package cicd

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/google/uuid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PipelineEngine orchestrates CI/CD pipeline execution
type PipelineEngine struct {
	mu              sync.RWMutex
	executions      map[string]*PipelineExecution
	orchestrators   map[string]*PipelineOrchestrator
	statusListeners []chan StatusUpdate
	webhookManager  *WebhookManager
	store           PipelineStore
	logger          *zap.Logger
}

// PipelineStore persists pipeline state
type PipelineStore interface {
	SaveExecution(execution *PipelineExecution) error
	GetExecution(id string) (*PipelineExecution, error)
	ListExecutions(pipelineID string, limit int) ([]*PipelineExecution, error)
	UpdateExecutionStatus(id string, status ExecutionStatus) error
	SaveStageExecution(executionID string, stage *StageExecution) error
}

// NewPipelineEngine creates a new pipeline execution engine
func NewPipelineEngine(store PipelineStore, logger *zap.Logger) *PipelineEngine {
	return &PipelineEngine{
		executions:      make(map[string]*PipelineExecution),
		orchestrators:   make(map[string]*PipelineOrchestrator),
		statusListeners: make([]chan StatusUpdate, 0),
		webhookManager:  NewWebhookManager(logger),
		store:           store,
		logger:          logger,
	}
}

// StartPipeline starts a new pipeline execution
func (pe *PipelineEngine) StartPipeline(rc *eos_io.RuntimeContext, config *PipelineConfig, trigger TriggerInfo) (*PipelineExecution, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create execution record
	execution := &PipelineExecution{
		ID:         uuid.New().String(),
		PipelineID: config.AppName,
		Status:     StatusPending,
		Trigger:    trigger,
		StartTime:  time.Now(),
		Config:     config,
		Stages:     make([]StageExecution, 0),
		Artifacts:  make([]ArtifactInfo, 0),
	}

	// Save initial execution state
	if err := pe.store.SaveExecution(execution); err != nil {
		return nil, fmt.Errorf("failed to save execution: %w", err)
	}

	// Create orchestrator
	orchestrator := &PipelineOrchestrator{
		config:     config,
		execution:  execution,
		statusChan: make(chan StatusUpdate, 100),
	}

	// Store references
	pe.mu.Lock()
	pe.executions[execution.ID] = execution
	pe.orchestrators[execution.ID] = orchestrator
	pe.mu.Unlock()

	// Start execution in background
	go pe.executePipeline(rc, orchestrator)

	logger.Info("Pipeline execution started",
		zap.String("execution_id", execution.ID),
		zap.String("pipeline", config.AppName),
		zap.String("trigger", trigger.Type))

	return execution, nil
}

// executePipeline runs the pipeline execution
func (pe *PipelineEngine) executePipeline(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator) {
	logger := otelzap.Ctx(rc.Ctx)
	execution := orchestrator.execution

	// Update status to running
	execution.Status = StatusRunning
	execution.StartTime = time.Now()
	_ = pe.store.UpdateExecutionStatus(execution.ID, StatusRunning)

	// Send status update
	pe.sendStatusUpdate(StatusUpdate{
		ExecutionID: execution.ID,
		Stage:       "pipeline",
		Status:      StatusRunning,
		Message:     "Pipeline execution started",
		Timestamp:   time.Now(),
	})

	// Execute stages in order
	for _, stageConfig := range orchestrator.config.Pipeline.Stages {
		if !stageConfig.Enabled {
			logger.Info("Skipping disabled stage",
				zap.String("stage", stageConfig.Name))
			continue
		}

		// Check dependencies
		if !pe.checkDependencies(execution, stageConfig.Dependencies) {
			logger.Error("Stage dependencies not met",
				zap.String("stage", stageConfig.Name))
			execution.Status = StatusFailed
			break
		}

		// Execute stage
		stageExecution := &StageExecution{
			Name:      stageConfig.Name,
			Status:    StatusRunning,
			StartTime: time.Now(),
			Logs:      make([]LogEntry, 0),
			Artifacts: make([]ArtifactInfo, 0),
			Metadata:  make(map[string]interface{}),
		}

		execution.Stages = append(execution.Stages, *stageExecution)
		_ = pe.store.SaveStageExecution(execution.ID, stageExecution)

		// Send stage start update
		pe.sendStatusUpdate(StatusUpdate{
			ExecutionID: execution.ID,
			Stage:       stageConfig.Name,
			Status:      StatusRunning,
			Message:     fmt.Sprintf("Stage %s started", stageConfig.Name),
			Timestamp:   time.Now(),
		})

		// Execute based on stage type
		var err error
		switch stageConfig.Type {
		case "build":
			err = pe.executeBuildStage(rc, orchestrator, &stageConfig, stageExecution)
		case "deploy":
			err = pe.executeDeployStage(rc, orchestrator, &stageConfig, stageExecution)
		case "test":
			err = pe.executeTestStage(rc, orchestrator, &stageConfig, stageExecution)
		case "verify":
			err = pe.executeVerifyStage(rc, orchestrator, &stageConfig, stageExecution)
		default:
			err = fmt.Errorf("unknown stage type: %s", stageConfig.Type)
		}

		// Update stage status
		endTime := time.Now()
		stageExecution.EndTime = &endTime
		stageExecution.Duration = endTime.Sub(stageExecution.StartTime)

		if err != nil {
			stageExecution.Status = StatusFailed
			stageExecution.Error = err.Error()
			execution.Status = StatusFailed

			logger.Error("Stage execution failed",
				zap.String("stage", stageConfig.Name),
				zap.Error(err))

			// Check if we should fail fast
			if orchestrator.config.Pipeline.FailFast {
				break
			}
		} else {
			stageExecution.Status = StatusSucceeded
			logger.Info("Stage execution succeeded",
				zap.String("stage", stageConfig.Name),
				zap.Duration("duration", stageExecution.Duration))
		}

		// Save stage result
		_ = pe.store.SaveStageExecution(execution.ID, stageExecution)

		// Send stage completion update
		pe.sendStatusUpdate(StatusUpdate{
			ExecutionID: execution.ID,
			Stage:       stageConfig.Name,
			Status:      stageExecution.Status,
			Message:     fmt.Sprintf("Stage %s %s", stageConfig.Name, stageExecution.Status),
			Timestamp:   time.Now(),
		})
	}

	// Finalize execution
	endTime := time.Now()
	execution.EndTime = &endTime
	execution.Duration = endTime.Sub(execution.StartTime)

	// Set final status if not already failed
	if execution.Status != StatusFailed {
		execution.Status = StatusSucceeded
	}

	// Handle auto-rollback if deployment failed
	if execution.Status == StatusFailed && orchestrator.config.Deployment.Strategy.AutoRevert {
		logger.Info("Initiating automatic rollback due to failed deployment")
		if err := pe.performRollback(rc, orchestrator); err != nil {
			logger.Error("Rollback failed", zap.Error(err))
		} else {
			execution.Status = StatusRolledBack
		}
	}

	// Save final state
	_ = pe.store.SaveExecution(execution)

	// Send completion update
	pe.sendStatusUpdate(StatusUpdate{
		ExecutionID: execution.ID,
		Stage:       "pipeline",
		Status:      execution.Status,
		Message:     fmt.Sprintf("Pipeline execution %s", execution.Status),
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"duration": execution.Duration.String(),
		},
	})

	// Cleanup
	pe.mu.Lock()
	delete(pe.orchestrators, execution.ID)
	pe.mu.Unlock()

	logger.Info("Pipeline execution completed",
		zap.String("execution_id", execution.ID),
		zap.String("status", string(execution.Status)),
		zap.Duration("duration", execution.Duration))
}

// executeBuildStage executes the build stage
func (pe *PipelineEngine) executeBuildStage(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, config *StageConfig, execution *StageExecution) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing build stage",
		zap.String("type", orchestrator.config.Build.Type))

	switch orchestrator.config.Build.Type {
	case "hugo":
		result, err := orchestrator.buildClient.BuildHugo(rc.Ctx, orchestrator.config.Build.Hugo)
		if err != nil {
			return fmt.Errorf("Hugo build failed: %w", err)
		}
		execution.Artifacts = append(execution.Artifacts, result.Artifacts...)
		execution.Logs = append(execution.Logs, result.Logs...)

	case "docker":
		result, err := orchestrator.buildClient.BuildDockerImage(rc.Ctx, orchestrator.config.Build)
		if err != nil {
			return fmt.Errorf("Docker build failed: %w", err)
		}
		execution.Artifacts = append(execution.Artifacts, result.Artifacts...)
		execution.Logs = append(execution.Logs, result.Logs...)

		// Push image if registry is configured
		if orchestrator.config.Build.Registry != "" {
			imageName := fmt.Sprintf("%s/%s:%s",
				orchestrator.config.Build.Registry,
				orchestrator.config.Build.Image,
				orchestrator.config.Version)

			if err := orchestrator.buildClient.PushDockerImage(rc.Ctx, imageName, orchestrator.config.Build.Registry); err != nil {
				return fmt.Errorf("Docker push failed: %w", err)
			}
		}

	default:
		return fmt.Errorf("unsupported build type: %s", orchestrator.config.Build.Type)
	}

	return nil
}

// executeDeployStage executes the deployment stage
func (pe *PipelineEngine) executeDeployStage(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, config *StageConfig, execution *StageExecution) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing deploy stage",
		zap.String("stage", config.Name),
		zap.String("strategy", orchestrator.config.Deployment.Strategy.Type))

	// Execute based on deployment strategy
	switch orchestrator.config.Deployment.Strategy.Type {
	case "rolling":
		return pe.executeRollingDeployment(rc, orchestrator, execution)
	case "blue-green":
		return pe.executeBlueGreenDeployment(rc, orchestrator, execution)
	case "canary":
		return pe.executeCanaryDeployment(rc, orchestrator, execution)
	default:
		return fmt.Errorf("unsupported deployment strategy: %s", orchestrator.config.Deployment.Strategy.Type)
	}
}

// executeTestStage executes the test stage
func (pe *PipelineEngine) executeTestStage(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, config *StageConfig, execution *StageExecution) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing test stage",
		zap.String("stage", config.Name))

	// Run infrastructure tests
	if testRunner, ok := orchestrator.buildClient.(InfrastructureTestRunner); ok {
		if err := testRunner.RunInfrastructureTests(rc.Ctx, orchestrator.config); err != nil {
			return fmt.Errorf("infrastructure tests failed: %w", err)
		}
	}

	return nil
}

// executeVerifyStage executes the verification stage
func (pe *PipelineEngine) executeVerifyStage(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, config *StageConfig, execution *StageExecution) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing verify stage",
		zap.String("stage", config.Name))

	// Verify deployment health
	if orchestrator.config.Deployment.Health.Enabled {
		// Wait for minimum healthy time
		time.Sleep(orchestrator.config.Deployment.Strategy.MinHealthyTime)

		// Check health endpoint
		// This would integrate with actual health checking logic
		logger.Info("Verifying deployment health",
			zap.String("endpoint", orchestrator.config.Deployment.Health.Path))
	}

	return nil
}

// checkDependencies checks if stage dependencies are met
func (pe *PipelineEngine) checkDependencies(execution *PipelineExecution, dependencies []string) bool {
	for _, dep := range dependencies {
		found := false
		for _, stage := range execution.Stages {
			if stage.Name == dep && stage.Status == StatusSucceeded {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// performRollback performs automatic rollback
func (pe *PipelineEngine) performRollback(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Performing automatic rollback",
		zap.String("app", orchestrator.config.AppName))

	// Create rollback execution
	rollbackConfig := *orchestrator.config
	rollbackConfig.Version = "previous" // This would be determined from deployment history

	rollbackTrigger := TriggerInfo{
		Type:    "rollback",
		Source:  "automatic",
		Message: "Automatic rollback due to deployment failure",
		Timestamp: time.Now(),
	}

	_, err := pe.StartPipeline(rc, &rollbackConfig, rollbackTrigger)
	return err
}

// GetExecution retrieves a pipeline execution by ID
func (pe *PipelineEngine) GetExecution(id string) (*PipelineExecution, error) {
	pe.mu.RLock()
	execution, exists := pe.executions[id]
	pe.mu.RUnlock()

	if exists {
		return execution, nil
	}

	// Try loading from store
	return pe.store.GetExecution(id)
}

// ListExecutions lists recent pipeline executions
func (pe *PipelineEngine) ListExecutions(pipelineID string, limit int) ([]*PipelineExecution, error) {
	return pe.store.ListExecutions(pipelineID, limit)
}

// CancelExecution cancels a running pipeline execution
func (pe *PipelineEngine) CancelExecution(executionID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	execution, exists := pe.executions[executionID]
	if !exists {
		return fmt.Errorf("execution not found: %s", executionID)
	}

	if execution.Status != StatusRunning {
		return fmt.Errorf("execution is not running: %s", execution.Status)
	}

	execution.Status = StatusCancelled
	_ = pe.store.UpdateExecutionStatus(executionID, StatusCancelled)

	pe.sendStatusUpdate(StatusUpdate{
		ExecutionID: executionID,
		Stage:       "pipeline",
		Status:      StatusCancelled,
		Message:     "Pipeline execution cancelled",
		Timestamp:   time.Now(),
	})

	return nil
}

// Subscribe subscribes to pipeline status updates
func (pe *PipelineEngine) Subscribe() <-chan StatusUpdate {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	ch := make(chan StatusUpdate, 100)
	pe.statusListeners = append(pe.statusListeners, ch)
	return ch
}

// sendStatusUpdate sends status update to all listeners
func (pe *PipelineEngine) sendStatusUpdate(update StatusUpdate) {
	pe.mu.RLock()
	listeners := make([]chan StatusUpdate, len(pe.statusListeners))
	copy(listeners, pe.statusListeners)
	pe.mu.RUnlock()

	for _, listener := range listeners {
		select {
		case listener <- update:
		default:
			// Channel full, skip
		}
	}

	// Also send webhook notifications
	pe.webhookManager.SendNotification(update)
}

// executeRollingDeployment implements rolling deployment strategy
func (pe *PipelineEngine) executeRollingDeployment(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, execution *StageExecution) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing rolling deployment",
		zap.String("app", orchestrator.config.AppName),
		zap.Int("max_parallel", orchestrator.config.Deployment.Strategy.MaxParallel))

	// Submit Nomad job with rolling update configuration
	jobSpec := generateNomadJobSpec(orchestrator.config)
	jobStatus, err := orchestrator.nomadClient.SubmitJob(rc.Ctx, jobSpec)
	if err != nil {
		return fmt.Errorf("failed to submit Nomad job: %w", err)
	}

	// Monitor deployment progress
	deadline := time.Now().Add(orchestrator.config.Deployment.Strategy.ProgressDeadline)
	for time.Now().Before(deadline) {
		status, err := orchestrator.nomadClient.GetJobStatus(rc.Ctx, jobStatus.ID)
		if err != nil {
			return fmt.Errorf("failed to get job status: %w", err)
		}

		if status.Running == status.Desired {
			logger.Info("Rolling deployment completed successfully",
				zap.Int("running", status.Running))
			return nil
		}

		if status.Failed > 0 {
			return fmt.Errorf("deployment failed with %d failed allocations", status.Failed)
		}

		time.Sleep(10 * time.Second)
	}

	return fmt.Errorf("deployment deadline exceeded")
}

// executeBlueGreenDeployment implements blue-green deployment strategy
func (pe *PipelineEngine) executeBlueGreenDeployment(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, execution *StageExecution) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing blue-green deployment",
		zap.String("app", orchestrator.config.AppName))

	// Deploy to green environment
	greenConfig := *orchestrator.config
	greenConfig.AppName = fmt.Sprintf("%s-green", orchestrator.config.AppName)

	jobSpec := generateNomadJobSpec(&greenConfig)
	jobStatus, err := orchestrator.nomadClient.SubmitJob(rc.Ctx, jobSpec)
	if err != nil {
		return fmt.Errorf("failed to deploy green environment: %w", err)
	}

	// Wait for green environment to be healthy
	if err := pe.waitForHealthy(rc, orchestrator, jobStatus.ID); err != nil {
		return fmt.Errorf("green environment failed health check: %w", err)
	}

	// Switch traffic to green environment
	if err := pe.switchTraffic(rc, orchestrator, "green"); err != nil {
		return fmt.Errorf("failed to switch traffic: %w", err)
	}

	// Decommission blue environment
	blueJobID := fmt.Sprintf("%s-blue", orchestrator.config.AppName)
	if err := orchestrator.nomadClient.StopJob(rc.Ctx, blueJobID, false); err != nil {
		logger.Warn("Failed to stop blue environment",
			zap.String("job", blueJobID),
			zap.Error(err))
	}

	logger.Info("Blue-green deployment completed successfully")
	return nil
}

// executeCanaryDeployment implements canary deployment strategy
func (pe *PipelineEngine) executeCanaryDeployment(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, execution *StageExecution) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing canary deployment",
		zap.String("app", orchestrator.config.AppName),
		zap.Int("canary_instances", orchestrator.config.Deployment.Strategy.Canary))

	// Deploy canary instances
	canaryConfig := *orchestrator.config
	canaryConfig.AppName = fmt.Sprintf("%s-canary", orchestrator.config.AppName)
	
	// Set canary instance count
	jobSpec := generateNomadJobSpec(&canaryConfig)
	jobStatus, err := orchestrator.nomadClient.SubmitJob(rc.Ctx, jobSpec)
	if err != nil {
		return fmt.Errorf("failed to deploy canary instances: %w", err)
	}

	// Monitor canary health
	if err := pe.waitForHealthy(rc, orchestrator, jobStatus.ID); err != nil {
		return fmt.Errorf("canary instances failed health check: %w", err)
	}

	// If auto-promote is enabled, promote canary
	if orchestrator.config.Deployment.Strategy.AutoPromote {
		logger.Info("Auto-promoting canary deployment")
		
		// Scale up canary to full deployment
		fullJobSpec := generateNomadJobSpec(orchestrator.config)
		if _, err := orchestrator.nomadClient.SubmitJob(rc.Ctx, fullJobSpec); err != nil {
			return fmt.Errorf("failed to promote canary: %w", err)
		}
		
		// Remove canary designation
		if err := orchestrator.nomadClient.StopJob(rc.Ctx, jobStatus.ID, true); err != nil {
			logger.Warn("Failed to remove canary job",
				zap.String("job", jobStatus.ID),
				zap.Error(err))
		}
	}

	logger.Info("Canary deployment completed successfully")
	return nil
}

// waitForHealthy waits for deployment to become healthy
func (pe *PipelineEngine) waitForHealthy(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, jobID string) error {
	deadline := time.Now().Add(orchestrator.config.Deployment.Strategy.HealthyDeadline)
	
	for time.Now().Before(deadline) {
		status, err := orchestrator.nomadClient.GetJobStatus(rc.Ctx, jobID)
		if err != nil {
			return err
		}

		if status.Running == status.Desired && status.Failed == 0 {
			// Wait for minimum healthy time
			time.Sleep(orchestrator.config.Deployment.Strategy.MinHealthyTime)
			return nil
		}

		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("health check deadline exceeded")
}

// switchTraffic switches traffic between deployments
func (pe *PipelineEngine) switchTraffic(rc *eos_io.RuntimeContext, orchestrator *PipelineOrchestrator, target string) error {
	// Update Consul service registration to point to new deployment
	service := &ConsulService{
		ID:      orchestrator.config.AppName,
		Name:    orchestrator.config.AppName,
		Tags:    []string{target, orchestrator.config.Deployment.Environment},
		Port:    80,
		Address: orchestrator.config.Deployment.Domain,
	}

	return orchestrator.consulClient.RegisterService(rc.Ctx, service)
}

// generateNomadJobSpec generates a Nomad job specification
func generateNomadJobSpec(config *PipelineConfig) string {
	// This would generate actual Nomad job spec from template
	// For now, return a placeholder
	return fmt.Sprintf(`
job "%s" {
  datacenters = ["dc1"]
  type = "service"
  
  update {
    max_parallel = %d
    min_healthy_time = "%s"
    healthy_deadline = "%s"
    progress_deadline = "%s"
    auto_revert = %t
    auto_promote = %t
    canary = %d
  }
  
  group "web" {
    count = 1
    
    task "%s" {
      driver = "docker"
      
      config {
        image = "%s/%s:%s"
      }
      
      resources {
        cpu = %d
        memory = %d
      }
    }
  }
}
`, config.AppName,
		config.Deployment.Strategy.MaxParallel,
		config.Deployment.Strategy.MinHealthyTime,
		config.Deployment.Strategy.HealthyDeadline,
		config.Deployment.Strategy.ProgressDeadline,
		config.Deployment.Strategy.AutoRevert,
		config.Deployment.Strategy.AutoPromote,
		config.Deployment.Strategy.Canary,
		config.AppName,
		config.Build.Registry,
		config.Build.Image,
		config.Version,
		config.Deployment.Resources.CPU,
		config.Deployment.Resources.Memory)
}

// InfrastructureTestRunner interface for running infrastructure tests
type InfrastructureTestRunner interface {
	RunInfrastructureTests(ctx context.Context, config *PipelineConfig) error
}