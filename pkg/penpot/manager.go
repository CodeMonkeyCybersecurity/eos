package penpot

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/nomad/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewManager creates a new Penpot manager instance
func NewManager(config *Config) (*Manager, error) {
	// Initialize Nomad client
	nomadConfig := api.DefaultConfig()
	if config.NomadAddr != "" {
		nomadConfig.Address = config.NomadAddr
	}
	nomadClient, err := api.NewClient(nomadConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Initialize Vault client
	vaultConfig := vault.DefaultConfig()
	if config.VaultAddr != "" {
		vaultConfig.Address = config.VaultAddr
	}
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	if config.VaultToken != "" {
		vaultClient.SetToken(config.VaultToken)
	}

	return &Manager{
		config:      config,
		nomadClient: nomadClient,
		vaultClient: vaultClient,
		statusChan:  make(chan DeploymentStatus, 100),
	}, nil
}

// Deploy orchestrates the complete Penpot deployment process
func (m *Manager) Deploy(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Starting Penpot deployment orchestration")

	// Define deployment steps following assessment->intervention->evaluation pattern
	steps := []DeploymentStep{
		{
			Name:          "prerequisites",
			Description:   "Verify system prerequisites",
			AssessFunc:    m.assessPrerequisites,
			InterventFunc: m.ensurePrerequisites,
			EvaluateFunc:  m.evaluatePrerequisites,
		},
		{
			Name:          "vault_secrets",
			Description:   "Setup Vault secrets",
			AssessFunc:    m.assessVaultSecrets,
			InterventFunc: m.setupVaultSecrets,
			EvaluateFunc:  m.evaluateVaultSecrets,
		},
		{
			Name:          "terraform_config",
			Description:   "Create Terraform configuration",
			AssessFunc:    m.assessTerraformConfig,
			InterventFunc: m.createTerraformConfig,
			EvaluateFunc:  m.evaluateTerraformConfig,
		},
		{
			Name:          "terraform_apply",
			Description:   "Apply Terraform infrastructure",
			AssessFunc:    m.assessTerraformState,
			InterventFunc: m.applyTerraform,
			EvaluateFunc:  m.evaluateTerraformState,
		},
		{
			Name:          "nomad_job",
			Description:   "Deploy Nomad job",
			AssessFunc:    m.assessNomadJob,
			InterventFunc: m.deployNomadJob,
			EvaluateFunc:  m.evaluateNomadJob,
		},
		{
			Name:          "health_check",
			Description:   "Verify deployment health",
			AssessFunc:    m.assessDeploymentHealth,
			InterventFunc: m.waitForHealthy,
			EvaluateFunc:  m.evaluateDeploymentHealth,
		},
	}

	// Execute each step
	for _, step := range steps {
		if err := m.executeStep(ctx, step); err != nil {
			m.reportStatus(step.Name+"_failed", false,
				fmt.Sprintf("Step %s failed", step.Description),
				map[string]interface{}{"error": err.Error()})
			return fmt.Errorf("deployment step %s failed: %w", step.Name, err)
		}
	}

	m.reportStatus("deployment_complete", true, "Penpot deployment completed successfully",
		map[string]interface{}{
			"url":       fmt.Sprintf("http://localhost:%d", m.config.Port),
			"namespace": m.config.Namespace,
		})

	return nil
}

// executeStep executes a single deployment step with assessment->intervention->evaluation
func (m *Manager) executeStep(ctx context.Context, step DeploymentStep) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Executing deployment step",
		zap.String("step", step.Name),
		zap.String("description", step.Description))

	// Assessment phase
	m.reportStatus(step.Name+"_assess", true, "Assessing "+step.Description, nil)
	if err := step.AssessFunc(ctx, m); err != nil {
		logger.Error(" Assessment failed",
			zap.String("step", step.Name),
			zap.Error(err))
		return fmt.Errorf("assessment failed: %w", err)
	}

	// Intervention phase
	m.reportStatus(step.Name+"_intervene", true, "Executing "+step.Description, nil)
	if err := step.InterventFunc(ctx, m); err != nil {
		logger.Error(" Intervention failed",
			zap.String("step", step.Name),
			zap.Error(err))
		return fmt.Errorf("intervention failed: %w", err)
	}

	// Evaluation phase
	m.reportStatus(step.Name+"_evaluate", true, "Evaluating "+step.Description, nil)
	if err := step.EvaluateFunc(ctx, m); err != nil {
		logger.Error(" Evaluation failed",
			zap.String("step", step.Name),
			zap.Error(err))
		return fmt.Errorf("evaluation failed: %w", err)
	}

	m.reportStatus(step.Name+"_complete", true, step.Description+" completed successfully", nil)
	return nil
}

// GetStatusChannel returns the status channel for monitoring
func (m *Manager) GetStatusChannel() <-chan DeploymentStatus {
	return m.statusChan
}

// reportStatus sends a status update to the status channel
func (m *Manager) reportStatus(step string, success bool, message string, details map[string]interface{}) {
	status := DeploymentStatus{
		Step:      step,
		Success:   success,
		Message:   message,
		Timestamp: time.Now(),
		Details:   details,
	}

	select {
	case m.statusChan <- status:
	default:
		// Channel full, log the status instead
		if success {
			fmt.Printf(" [%s] %s\n", step, message)
		} else {
			fmt.Printf(" [%s] %s\n", step, message)
		}
	}
}

// DeploymentExists checks if a deployment exists in the specified namespace
func (m *Manager) DeploymentExists(ctx context.Context) (bool, error) {
	jobs, _, err := m.nomadClient.Jobs().List(&api.QueryOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return false, fmt.Errorf("failed to list jobs: %w", err)
	}

	for _, job := range jobs {
		if job.ID == "penpot" {
			return true, nil
		}
	}

	return false, nil
}

// GetDeploymentInfo retrieves information about the deployment
func (m *Manager) GetDeploymentInfo(ctx context.Context) (*DeploymentInfo, error) {
	logger := otelzap.Ctx(ctx)

	// Check if job exists
	job, _, err := m.nomadClient.Jobs().Info("penpot", &api.QueryOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		logger.Debug("Job not found", zap.Error(err))
		return nil, fmt.Errorf("job not found: %w", err)
	}

	// Get job allocations
	allocs, _, err := m.nomadClient.Jobs().Allocations("penpot", false, &api.QueryOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get allocations: %w", err)
	}

	// Build service info
	services := make([]ServiceInfo, 0)
	healthy := true

	for _, alloc := range allocs {
		if alloc.ClientStatus != "running" {
			healthy = false
		}

		// Get task states
		for taskName, taskState := range alloc.TaskStates {
			service := ServiceInfo{
				Name:    taskName,
				Status:  taskState.State,
				Healthy: taskState.State == "running",
			}
			services = append(services, service)
		}
	}

	info := &DeploymentInfo{
		Namespace: m.config.Namespace,
		Status:    *job.Status,
		Healthy:   healthy,
		Port:      m.config.Port,
		Services:  services,
		Resources: m.config.Resources,
		URL:       fmt.Sprintf("http://localhost:%d", m.config.Port),
		Version:   "latest",
	}

	if job.CreateIndex != nil {
		info.CreatedAt = time.Now().Format(time.RFC3339) // Use current time as fallback
	}

	if job.ModifyIndex != nil {
		info.UpdatedAt = time.Now().Format(time.RFC3339) // Use current time as fallback
	}

	return info, nil
}

// ListDeployments returns all Penpot deployments across namespaces
func (m *Manager) ListDeployments(ctx context.Context) ([]*DeploymentInfo, error) {
	// Get all namespaces
	namespaces, _, err := m.nomadClient.Namespaces().List(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	var deployments []*DeploymentInfo

	for _, ns := range namespaces {
		// Create temporary manager for this namespace
		config := *m.config
		config.Namespace = ns.Name

		nsManager, err := NewManager(&config)
		if err != nil {
			continue // Skip this namespace if we can't create a manager
		}

		// Check if deployment exists in this namespace
		exists, err := nsManager.DeploymentExists(ctx)
		if err != nil || !exists {
			continue
		}

		// Get deployment info
		info, err := nsManager.GetDeploymentInfo(ctx)
		if err != nil {
			continue // Skip if we can't get info
		}

		deployments = append(deployments, info)
	}

	return deployments, nil
}

// GetHealthStatus returns the health status of the deployment
func (m *Manager) GetHealthStatus(ctx context.Context) (*HealthStatus, error) {
	start := time.Now()

	// Get job info
	job, _, err := m.nomadClient.Jobs().Info("penpot", &api.QueryOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("job not found: %w", err)
	}

	// Get allocations
	allocs, _, err := m.nomadClient.Jobs().Allocations("penpot", false, &api.QueryOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get allocations: %w", err)
	}

	var services []ServiceHealthInfo
	overallHealthy := true

	for _, alloc := range allocs {
		for taskName, taskState := range alloc.TaskStates {
			healthy := taskState.State == "running"
			if !healthy {
				overallHealthy = false
			}

			service := ServiceHealthInfo{
				Name:          taskName,
				Status:        taskState.State,
				Healthy:       healthy,
				ChecksPassing: 0,
				ChecksTotal:   1,
				LastCheck:     time.Now().Format(time.RFC3339),
			}

			if healthy {
				service.ChecksPassing = 1
			}

			services = append(services, service)
		}
	}

	status := &HealthStatus{
		Namespace:     m.config.Namespace,
		OverallStatus: *job.Status,
		Healthy:       overallHealthy,
		Services:      services,
		LastCheck:     time.Now().Format(time.RFC3339),
		CheckDuration: time.Since(start).String(),
	}

	return status, nil
}

// UpdateDeployment updates an existing deployment
func (m *Manager) UpdateDeployment(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("🔄 Updating Penpot deployment")

	// Re-run deployment steps that support updates
	steps := []DeploymentStep{
		{
			Name:          "vault_secrets",
			Description:   "Update Vault secrets",
			AssessFunc:    m.assessVaultSecrets,
			InterventFunc: m.setupVaultSecrets,
			EvaluateFunc:  m.evaluateVaultSecrets,
		},
		{
			Name:          "nomad_job",
			Description:   "Update Nomad job",
			AssessFunc:    m.assessNomadJob,
			InterventFunc: m.deployNomadJob,
			EvaluateFunc:  m.evaluateNomadJob,
		},
	}

	for _, step := range steps {
		if err := m.executeStep(ctx, step); err != nil {
			return fmt.Errorf("update step %s failed: %w", step.Name, err)
		}
	}

	return nil
}

// DeleteDeployment removes the deployment
func (m *Manager) DeleteDeployment(ctx context.Context, force bool) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("🗑️ Deleting Penpot deployment",
		zap.String("namespace", m.config.Namespace),
		zap.Bool("force", force))

	// Stop the job
	_, _, err := m.nomadClient.Jobs().Deregister("penpot", force, &api.WriteOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return fmt.Errorf("failed to deregister job: %w", err)
	}

	// Clean up Vault secrets if force is enabled
	if force {
		if err := m.cleanupVaultSecrets(ctx); err != nil {
			logger.Warn("Failed to cleanup Vault secrets", zap.Error(err))
		}
	}

	return nil
}

// RestartServices restarts specified services
func (m *Manager) RestartServices(ctx context.Context, services []string) error {
	// Get current job
	job, _, err := m.nomadClient.Jobs().Info("penpot", &api.QueryOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return fmt.Errorf("job not found: %w", err)
	}

	// Force a new deployment by updating the job
	resp, _, err := m.nomadClient.Jobs().Register(job, &api.WriteOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return fmt.Errorf("failed to restart services: %w", err)
	}

	// Monitor the restart
	return m.monitorEvaluation(ctx, resp.EvalID)
}

// ScaleDeployment scales the deployment to the specified count
func (m *Manager) ScaleDeployment(ctx context.Context, count int) error {
	// Get current job
	job, _, err := m.nomadClient.Jobs().Info("penpot", &api.QueryOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return fmt.Errorf("job not found: %w", err)
	}

	// Update the count
	if len(job.TaskGroups) > 0 {
		job.TaskGroups[0].Count = &count
	}

	// Register the updated job
	resp, _, err := m.nomadClient.Jobs().Register(job, &api.WriteOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return fmt.Errorf("failed to scale deployment: %w", err)
	}

	// Monitor the scaling
	return m.monitorEvaluation(ctx, resp.EvalID)
}

// CreateBackup creates a backup of Penpot data
func (m *Manager) CreateBackup(ctx context.Context, backupPath string) error {
	// This would implement backup logic
	// For now, we'll create a placeholder
	return fmt.Errorf("backup functionality not yet implemented")
}

// RestoreBackup restores Penpot data from a backup
func (m *Manager) RestoreBackup(ctx context.Context, backupPath string) error {
	// This would implement restore logic
	// For now, we'll create a placeholder
	return fmt.Errorf("restore functionality not yet implemented")
}

// monitorEvaluation monitors a Nomad evaluation
func (m *Manager) monitorEvaluation(ctx context.Context, evalID string) error {
	logger := otelzap.Ctx(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			eval, _, err := m.nomadClient.Evaluations().Info(evalID, nil)
			if err != nil {
				return fmt.Errorf("failed to get evaluation info: %w", err)
			}

			logger.Debug("Evaluation status",
				zap.String("eval_id", evalID),
				zap.String("status", eval.Status))

			switch eval.Status {
			case "complete":
				return nil
			case "failed", "cancelled":
				return fmt.Errorf("evaluation failed with status: %s", eval.Status)
			}

			time.Sleep(2 * time.Second)
		}
	}
}

// cleanupVaultSecrets removes Vault secrets for the deployment
func (m *Manager) cleanupVaultSecrets(ctx context.Context) error {
	paths := []string{
		"secret/data/penpot",
		"secret/data/postgres",
	}

	for _, path := range paths {
		_, err := m.vaultClient.Logical().Delete(path)
		if err != nil {
			return fmt.Errorf("failed to delete secret %s: %w", path, err)
		}
	}

	return nil
}
