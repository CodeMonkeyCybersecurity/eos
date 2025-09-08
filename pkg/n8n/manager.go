package n8n

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/nomad/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewManager creates a new n8n deployment manager
func NewManager(rc *eos_io.RuntimeContext, config *Config) (*Manager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Initialize Nomad client
	nomadConfig := api.DefaultConfig()
	if config.NomadAddr != "" {
		nomadConfig.Address = config.NomadAddr
	}
	
	nomadClient, err := api.NewClient(nomadConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Initialize Vault client (optional)
	var vaultClient *vault.Client
	if config.VaultAddr != "" {
		vaultConfig := vault.DefaultConfig()
		vaultConfig.Address = config.VaultAddr
		
		vaultClient, err = vault.NewClient(vaultConfig)
		if err != nil {
			logger.Warn("Failed to create Vault client, continuing without Vault", zap.Error(err))
		} else if config.VaultToken != "" {
			vaultClient.SetToken(config.VaultToken)
		}
	}

	return &Manager{
		config:      config,
		nomadClient: nomadClient,
		vaultClient: vaultClient,
		statusChan:  make(chan DeploymentStatus, 100),
	}, nil
}

// Deploy executes the complete n8n deployment process
func (m *Manager) Deploy(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Starting n8n deployment",
		zap.String("environment", m.config.Environment),
		zap.String("datacenter", m.config.Datacenter),
		zap.Int("port", m.config.Port),
		zap.Int("workers", m.config.Workers))

	// Define deployment steps following Assess → Intervene → Evaluate pattern
	steps := []DeploymentStep{
		{
			Name:        "prerequisites",
			Description: "Check system prerequisites and dependencies",
			AssessFunc:  m.assessPrerequisites,
			InterventFunc: m.ensurePrerequisites,
			EvaluateFunc: m.evaluatePrerequisites,
		},
		{
			Name:        "secrets",
			Description: "Generate and store secrets",
			AssessFunc:  m.assessSecrets,
			InterventFunc: m.generateSecrets,
			EvaluateFunc: m.evaluateSecrets,
		},
		{
			Name:        "infrastructure",
			Description: "Deploy supporting infrastructure (PostgreSQL, Redis)",
			AssessFunc:  m.assessInfrastructure,
			InterventFunc: m.deployInfrastructure,
			EvaluateFunc: m.evaluateInfrastructure,
		},
		{
			Name:        "n8n_service",
			Description: "Deploy n8n main service and workers",
			AssessFunc:  m.assessN8nService,
			InterventFunc: m.deployN8nService,
			EvaluateFunc: m.evaluateN8nService,
		},
		{
			Name:        "nginx_proxy",
			Description: "Configure nginx reverse proxy",
			AssessFunc:  m.assessNginxProxy,
			InterventFunc: m.deployNginxProxy,
			EvaluateFunc: m.evaluateNginxProxy,
		},
	}

	// Execute each step
	for _, step := range steps {
		logger.Info("Executing deployment step", zap.String("step", step.Name))
		
		// Assess
		if err := step.AssessFunc(ctx, m); err != nil {
			return fmt.Errorf("assessment failed for step %s: %w", step.Name, err)
		}

		// Intervene
		if err := step.InterventFunc(ctx, m); err != nil {
			return fmt.Errorf("intervention failed for step %s: %w", step.Name, err)
		}

		// Evaluate
		if err := step.EvaluateFunc(ctx, m); err != nil {
			return fmt.Errorf("evaluation failed for step %s: %w", step.Name, err)
		}

		m.statusChan <- DeploymentStatus{
			Step:    step.Name,
			Success: true,
			Message: fmt.Sprintf("Step %s completed successfully", step.Name),
		}
	}

	logger.Info("n8n deployment completed successfully")
	return nil
}

// Assess functions check current state
func (m *Manager) assessPrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Assessing prerequisites")
	
	// Check Nomad connectivity
	_, err := m.nomadClient.Status().Leader()
	if err != nil {
		return fmt.Errorf("cannot connect to Nomad: %w", err)
	}
	
	return nil
}

func (m *Manager) assessSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Assessing secrets")
	
	// Check if required secrets exist
	if m.config.EncryptionKey == "" || m.config.AdminPassword == "" {
		return fmt.Errorf("required secrets not configured")
	}
	
	return nil
}

func (m *Manager) assessInfrastructure(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Assessing infrastructure")
	
	// Check if PostgreSQL and Redis jobs exist
	jobs, _, err := m.nomadClient.Jobs().List(&api.QueryOptions{})
	if err != nil {
		return fmt.Errorf("failed to list jobs: %w", err)
	}
	
	hasPostgres := false
	hasRedis := false
	
	for _, job := range jobs {
		if job.Name == "n8n-postgres" {
			hasPostgres = true
		}
		if job.Name == "n8n-redis" {
			hasRedis = true
		}
	}
	
	if !hasPostgres || !hasRedis {
		logger.Info("Infrastructure services need deployment",
			zap.Bool("postgres_exists", hasPostgres),
			zap.Bool("redis_exists", hasRedis))
	}
	
	return nil
}

func (m *Manager) assessN8nService(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Assessing n8n service")
	
	// Check if n8n job exists and is running
	job, _, err := m.nomadClient.Jobs().Info("n8n", &api.QueryOptions{})
	if err != nil {
		// Job doesn't exist, needs deployment
		return nil
	}
	
	if job.Status == nil || *job.Status != "running" {
		logger.Info("n8n service exists but not running", zap.String("status", *job.Status))
	}
	
	return nil
}

func (m *Manager) assessNginxProxy(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Assessing nginx proxy")
	
	// Check if nginx proxy configuration exists
	// This would typically check the nginx configuration files
	return nil
}

// Intervene functions make necessary changes
func (m *Manager) ensurePrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Ensuring prerequisites")
	
	// Prerequisites are already checked in assess phase
	return nil
}

func (m *Manager) generateSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Generating secrets")
	
	// Secrets are already provided in config
	// In a real implementation, this would generate missing secrets
	return nil
}

func (m *Manager) deployInfrastructure(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Deploying infrastructure services")
	
	// Deploy PostgreSQL job
	postgresJob := m.createPostgresJob()
	_, _, err := m.nomadClient.Jobs().Register(postgresJob, &api.WriteOptions{})
	if err != nil {
		return fmt.Errorf("failed to deploy PostgreSQL: %w", err)
	}
	
	// Deploy Redis job
	redisJob := m.createRedisJob()
	_, _, err = m.nomadClient.Jobs().Register(redisJob, &api.WriteOptions{})
	if err != nil {
		return fmt.Errorf("failed to deploy Redis: %w", err)
	}
	
	return nil
}

func (m *Manager) deployN8nService(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Deploying n8n service")
	
	// Deploy n8n job
	n8nJob := m.createN8nJob()
	_, _, err := m.nomadClient.Jobs().Register(n8nJob, &api.WriteOptions{})
	if err != nil {
		return fmt.Errorf("failed to deploy n8n: %w", err)
	}
	
	return nil
}

func (m *Manager) deployNginxProxy(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Deploying nginx proxy")
	
	// Deploy nginx proxy job
	nginxJob := m.createNginxJob()
	_, _, err := m.nomadClient.Jobs().Register(nginxJob, &api.WriteOptions{})
	if err != nil {
		return fmt.Errorf("failed to deploy nginx proxy: %w", err)
	}
	
	return nil
}

// Evaluate functions verify the changes worked
func (m *Manager) evaluatePrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Evaluating prerequisites")
	
	// Re-check Nomad connectivity
	return m.assessPrerequisites(ctx, mgr)
}

func (m *Manager) evaluateSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Evaluating secrets")
	
	// Verify all required secrets are available
	return m.assessSecrets(ctx, mgr)
}

func (m *Manager) evaluateInfrastructure(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Evaluating infrastructure")
	
	// Check that infrastructure services are running
	jobs := []string{"n8n-postgres", "n8n-redis"}
	
	for _, jobName := range jobs {
		job, _, err := m.nomadClient.Jobs().Info(jobName, &api.QueryOptions{})
		if err != nil {
			return fmt.Errorf("failed to get job info for %s: %w", jobName, err)
		}
		
		if job.Status == nil || *job.Status != "running" {
			return fmt.Errorf("job %s is not running: %s", jobName, *job.Status)
		}
	}
	
	return nil
}

func (m *Manager) evaluateN8nService(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Evaluating n8n service")
	
	// Check that n8n service is running
	job, _, err := m.nomadClient.Jobs().Info("n8n", &api.QueryOptions{})
	if err != nil {
		return fmt.Errorf("failed to get n8n job info: %w", err)
	}
	
	if job.Status == nil || *job.Status != "running" {
		return fmt.Errorf("n8n job is not running: %s", *job.Status)
	}
	
	return nil
}

func (m *Manager) evaluateNginxProxy(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Evaluating nginx proxy")
	
	// Check that nginx proxy is running
	job, _, err := m.nomadClient.Jobs().Info("n8n-nginx", &api.QueryOptions{})
	if err != nil {
		return fmt.Errorf("failed to get nginx job info: %w", err)
	}
	
	if job.Status == nil || *job.Status != "running" {
		return fmt.Errorf("nginx job is not running: %s", *job.Status)
	}
	
	return nil
}
