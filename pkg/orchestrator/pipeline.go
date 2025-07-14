// pkg/orchestrator/pipeline.go
package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Pipeline implements the complete orchestration pipeline
type pipeline struct {
	rc            *eos_io.RuntimeContext
	salt          SaltOrchestrator
	terraform     TerraformProvider
	nomad         NomadClient
	stateStore    StateStore
	config        PipelineConfig
}

// PipelineConfig holds pipeline configuration
type PipelineConfig struct {
	DryRun      bool
	AutoApprove bool
	Timeout     time.Duration
}

// SaltOrchestrator defines the interface for Salt operations
type SaltOrchestrator interface {
	Deploy(ctx context.Context, component Component) (*Deployment, error)
	Rollback(ctx context.Context, deployment *Deployment) error
	GetStatus(ctx context.Context, deploymentID string) (*Status, error)
	PreviewState(component Component) (string, error)
	PreviewPillar(component Component) (string, error)
}

// TerraformProvider defines the interface for Terraform operations
type TerraformProvider interface {
	Apply(ctx context.Context, component Component) error
	Destroy(ctx context.Context, component Component) error
	GetOutputs(ctx context.Context, component Component) (map[string]string, error)
	Preview(component Component) (string, error)
}

// NomadClient defines the interface for Nomad operations
type NomadClient interface {
	WaitForJob(ctx context.Context, jobID string, timeout time.Duration) error
	GetJobStatus(ctx context.Context, jobID string) (interface{}, error)
	GetLogs(ctx context.Context, jobID string, options LogOptions) ([]LogEntry, error)
	StopJob(ctx context.Context, jobID string) error
	VerifyHealth(ctx context.Context, jobID string) error
}

// PipelineOption defines options for creating a pipeline
type PipelineOption func(*pipeline)

// WithSalt configures the Salt orchestrator
func WithSalt(salt SaltOrchestrator) PipelineOption {
	return func(p *pipeline) {
		p.salt = salt
	}
}

// WithTerraform configures the Terraform provider
func WithTerraform(terraform TerraformProvider) PipelineOption {
	return func(p *pipeline) {
		p.terraform = terraform
	}
}

// WithNomad configures the Nomad client
func WithNomad(nomad NomadClient) PipelineOption {
	return func(p *pipeline) {
		p.nomad = nomad
	}
}

// WithStateStore configures the state store
func WithStateStore(store StateStore) PipelineOption {
	return func(p *pipeline) {
		p.stateStore = store
	}
}

// WithConfig configures pipeline options
func WithConfig(config PipelineConfig) PipelineOption {
	return func(p *pipeline) {
		p.config = config
	}
}

// NewPipeline creates a new orchestration pipeline
func NewPipeline(rc *eos_io.RuntimeContext, opts ...PipelineOption) Pipeline {
	p := &pipeline{
		rc: rc,
		config: PipelineConfig{
			Timeout: 10 * time.Minute,
		},
	}
	
	for _, opt := range opts {
		opt(p)
	}
	
	return p
}

// Deploy runs a component through the entire pipeline
func (p *pipeline) Deploy(ctx context.Context, component Component) (*Deployment, error) {
	logger := otelzap.Ctx(p.rc.Ctx)
	logger.Info("Starting pipeline deployment",
		zap.String("component", component.Name),
		zap.Bool("dry_run", p.config.DryRun))

	// Create deployment record
	deployment := &Deployment{
		ID:        fmt.Sprintf("pipeline-%s-%d", component.Name, time.Now().Unix()),
		Component: component,
		Status:    StatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Outputs:   make(map[string]string),
	}

	// Save initial state
	if p.stateStore != nil {
		if err := p.stateStore.SaveDeployment(deployment); err != nil {
			logger.Warn("Failed to save initial deployment state", zap.Error(err))
		}
	}

	// Create error chain for collecting errors
	errorChain := &ErrorChain{}

	// Phase 1: Salt Configuration
	if p.salt != nil {
		logger.Info("Phase 1: Applying Salt configuration")
		deployment.Status = StatusDeploying
		
		if !p.config.DryRun {
			saltDeployment, err := p.salt.Deploy(ctx, component)
			if err != nil {
				errorChain.Add(err.(*OrchestrationError))
				deployment.Status = StatusFailed
				deployment.Error = err.Error()
				
				// Attempt rollback
				p.rollbackSalt(ctx, saltDeployment)
				
				return deployment, errorChain
			}
			
			deployment.Outputs["salt_deployment_id"] = saltDeployment.ID
		}
	}

	// Phase 2: Terraform Infrastructure
	if p.terraform != nil {
		logger.Info("Phase 2: Applying Terraform configuration")
		
		if !p.config.DryRun {
			if err := p.terraform.Apply(ctx, component); err != nil {
				orchErr := NewOrchestrationError(
					LayerTerraform,
					PhaseApplication,
					component.Name,
					"Terraform apply failed",
					err,
				)
				errorChain.Add(orchErr)
				deployment.Status = StatusFailed
				deployment.Error = err.Error()
				
				// Rollback Salt changes
				if p.salt != nil {
					p.rollbackSalt(ctx, deployment)
				}
				
				return deployment, errorChain
			}
			
			// Get Terraform outputs
			outputs, err := p.terraform.GetOutputs(ctx, component)
			if err != nil {
				logger.Warn("Failed to get Terraform outputs", zap.Error(err))
			} else {
				for k, v := range outputs {
					deployment.Outputs[fmt.Sprintf("tf_%s", k)] = v
				}
			}
		}
	}

	// Phase 3: Wait for Nomad job health
	if p.nomad != nil && !p.config.DryRun {
		logger.Info("Phase 3: Waiting for Nomad job health")
		
		// Get job ID from Terraform outputs
		jobID, ok := deployment.Outputs["tf_job_id"]
		if !ok {
			// Try to construct job ID
			jobID = component.Name
		}
		
		if err := p.nomad.WaitForJob(ctx, jobID, p.config.Timeout); err != nil {
			orchErr := NewOrchestrationError(
				LayerNomad,
				PhaseVerification,
				component.Name,
				"Nomad job failed to stabilize",
				err,
			)
			errorChain.Add(orchErr)
			deployment.Status = StatusUnhealthy
			deployment.Error = err.Error()
			
			// Don't rollback yet - job might recover
			logger.Warn("Nomad job is unhealthy but deployment continues",
				zap.String("job_id", jobID))
		} else {
			deployment.Status = StatusHealthy
		}
	}

	// Update final state
	deployment.UpdatedAt = time.Now()
	if p.stateStore != nil {
		if err := p.stateStore.SaveDeployment(deployment); err != nil {
			logger.Warn("Failed to save final deployment state", zap.Error(err))
		}
	}

	if errorChain.HasErrors() {
		return deployment, errorChain
	}

	logger.Info("Pipeline deployment completed successfully",
		zap.String("component", component.Name),
		zap.String("deployment_id", deployment.ID),
		zap.Duration("duration", deployment.UpdatedAt.Sub(deployment.CreatedAt)))

	return deployment, nil
}

// rollbackSalt attempts to rollback Salt changes
func (p *pipeline) rollbackSalt(ctx context.Context, deployment *Deployment) {
	logger := otelzap.Ctx(p.rc.Ctx)
	logger.Info("Attempting Salt rollback",
		zap.String("deployment_id", deployment.ID))
	
	if err := p.salt.Rollback(ctx, deployment); err != nil {
		logger.Error("Salt rollback failed",
			zap.Error(err),
			zap.String("deployment_id", deployment.ID))
	}
}

// WaitForHealthy waits for a deployment to become healthy
func (p *pipeline) WaitForHealthy(ctx context.Context, deployment *Deployment, timeout time.Duration) error {
	logger := otelzap.Ctx(p.rc.Ctx)
	logger.Info("Waiting for deployment to become healthy",
		zap.String("deployment_id", deployment.ID),
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for health")
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for deployment health")
			}

			// Check component-specific health
			healthy, err := p.checkComponentHealth(ctx, deployment)
			if err != nil {
				logger.Warn("Health check error",
					zap.Error(err),
					zap.String("deployment_id", deployment.ID))
				continue
			}

			if healthy {
				logger.Info("Deployment is healthy",
					zap.String("deployment_id", deployment.ID))
				return nil
			}

			logger.Debug("Deployment not yet healthy, continuing to wait",
				zap.String("deployment_id", deployment.ID))
		}
	}
}

// checkComponentHealth checks if a component is healthy
func (p *pipeline) checkComponentHealth(ctx context.Context, deployment *Deployment) (bool, error) {
	// Check Salt status
	if p.salt != nil {
		saltStatus, err := p.salt.GetStatus(ctx, deployment.ID)
		if err != nil {
			return false, fmt.Errorf("failed to get salt status: %w", err)
		}
		if !saltStatus.Healthy {
			return false, nil
		}
	}

	// Check Nomad job health
	if p.nomad != nil {
		jobID := deployment.Outputs["tf_job_id"]
		if jobID == "" {
			jobID = deployment.Component.Name
		}
		
		if err := p.nomad.VerifyHealth(ctx, jobID); err != nil {
			return false, nil
		}
	}

	return true, nil
}

// GetLogs retrieves logs for a deployment
func (p *pipeline) GetLogs(ctx context.Context, deploymentID string, options LogOptions) ([]LogEntry, error) {
	// Get deployment
	if p.stateStore == nil {
		return nil, fmt.Errorf("no state store configured")
	}

	deployment, err := p.stateStore.GetDeployment(deploymentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Get logs from Nomad
	if p.nomad != nil {
		jobID := deployment.Outputs["tf_job_id"]
		if jobID == "" {
			jobID = deployment.Component.Name
		}
		
		return p.nomad.GetLogs(ctx, jobID, options)
	}

	return nil, fmt.Errorf("no log source available")
}

// PreviewSalt returns the generated Salt states without applying
func (p *pipeline) PreviewSalt(component Component) (string, error) {
	if p.salt == nil {
		return "", fmt.Errorf("salt orchestrator not configured")
	}
	
	return p.salt.PreviewState(component)
}

// PreviewTerraform returns the generated Terraform configuration without applying
func (p *pipeline) PreviewTerraform(component Component) (string, error) {
	if p.terraform == nil {
		return "", fmt.Errorf("terraform provider not configured")
	}
	
	return p.terraform.Preview(component)
}

// PreviewNomad returns the generated Nomad job specification without applying
func (p *pipeline) PreviewNomad(component Component) (string, error) {
	// Nomad jobs are generated by Terraform in this architecture
	if p.terraform == nil {
		return "", fmt.Errorf("terraform provider not configured")
	}
	
	// Get the Terraform preview which includes Nomad job specs
	preview, err := p.terraform.Preview(component)
	if err != nil {
		return "", err
	}
	
	// Extract just the Nomad job portion
	// This is a simplified extraction - in production you'd parse more carefully
	startMarker := "=== jobs/"
	if idx := strings.Index(preview, startMarker); idx != -1 {
		return preview[idx:], nil
	}
	
	return preview, nil
}