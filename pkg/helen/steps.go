package helen

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/hashicorp/nomad/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Assessment Phase Functions - Check current state

// assessPrerequisites checks if all required tools are available
func (m *Manager) assessPrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing system prerequisites")

	requiredTools := []string{"nomad", "vault"}

	for _, tool := range requiredTools {
		if err := m.checkCommandExists(tool); err != nil {
			logger.Error("Required tool not found",
				zap.String("tool", tool),
				zap.Error(err))
			return fmt.Errorf("required tool %s not found: %w", tool, err)
		}
		logger.Debug("Tool found", zap.String("tool", tool))
	}

	// Check if public HTML path exists
	if _, err := os.Stat(m.config.PublicHTMLPath); os.IsNotExist(err) {
		logger.Error("Public HTML path does not exist",
			zap.String("path", m.config.PublicHTMLPath))
		return fmt.Errorf("public HTML path does not exist: %s", m.config.PublicHTMLPath)
	}

	return nil
}

// assessVaultSecrets checks if Vault secrets already exist
func (m *Manager) assessVaultSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing Vault secrets")

	// Check if we can connect to Vault
	health, err := m.vaultClient.Sys().Health()
	if err != nil {
		logger.Error("Cannot connect to Vault", zap.Error(err))
		return fmt.Errorf("vault connection failed: %w", err)
	}

	logger.Debug("Vault connection successful",
		zap.Bool("initialized", health.Initialized),
		zap.Bool("sealed", health.Sealed))

	// Check if secrets already exist
	secretPath := fmt.Sprintf("secret/data/helen/%s", m.config.Namespace)
	secret, err := m.vaultClient.Logical().Read(secretPath)
	if err != nil {
		logger.Debug("Helen secrets not found, will create", zap.Error(err))
		return nil // Not an error, we'll create them
	}

	if secret != nil && secret.Data != nil {
		logger.Info("Helen secrets already exist in Vault")
	}

	return nil
}

// assessNomadJob checks if Nomad job is deployed
func (m *Manager) assessNomadJob(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing Nomad job deployment")

	exists, err := m.DeploymentExists(ctx)
	if err != nil {
		logger.Error("Failed to check job existence", zap.Error(err))
		return fmt.Errorf("failed to check job existence: %w", err)
	}

	if exists {
		logger.Info("Helen job already exists in Nomad")
	} else {
		logger.Debug("Helen job does not exist, will deploy")
	}

	return nil
}

// assessDeploymentHealth checks if deployment is healthy
func (m *Manager) assessDeploymentHealth(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing deployment health")

	status, err := m.GetHealthStatus(ctx)
	if err != nil {
		logger.Debug("Cannot get health status, deployment may not exist", zap.Error(err))
		return nil // Not an error during assessment
	}

	if status.Healthy {
		logger.Info("Deployment is healthy")
	} else {
		logger.Debug("Deployment exists but is not healthy")
	}

	return nil
}

// Intervention Phase Functions - Make changes

// ensurePrerequisites ensures all prerequisites are met
func (m *Manager) ensurePrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Ensuring prerequisites are met")

	// Check Nomad connectivity
	if _, err := m.nomadClient.Agent().Self(); err != nil {
		logger.Error("Cannot connect to Nomad", zap.Error(err))
		return fmt.Errorf("nomad connection failed: %w", err)
	}

	// Check Vault connectivity
	if _, err := m.vaultClient.Sys().Health(); err != nil {
		logger.Error("Cannot connect to Vault", zap.Error(err))
		return fmt.Errorf("vault connection failed: %w", err)
	}

	// Ensure work directory exists
	if err := os.MkdirAll(m.config.WorkDir, shared.ServiceDirPerm); err != nil {
		logger.Error("Failed to create work directory", zap.Error(err))
		return fmt.Errorf("failed to create work directory: %w", err)
	}

	logger.Info("All prerequisites verified")
	return nil
}

// setupVaultSecrets creates or updates Vault secrets
func (m *Manager) setupVaultSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Setting up Vault secrets")

	// Create Helen secrets
	helenSecrets := map[string]interface{}{
		"project_name":     m.config.ProjectName,
		"deployment_time":  time.Now().Format(time.RFC3339),
		"container_port":   80,
		"host_port":        m.config.Port,
		"public_html_path": m.config.PublicHTMLPath,
		"namespace":        m.config.Namespace,
		"deployed_by":      "eos-helen-cli",
	}

	// Write secrets to Vault
	secretPath := fmt.Sprintf("secret/data/helen/%s", m.config.Namespace)
	_, err := m.vaultClient.Logical().Write(secretPath, map[string]interface{}{
		"data": helenSecrets,
	})
	if err != nil {
		logger.Error("Failed to write Helen secrets to Vault", zap.Error(err))
		return fmt.Errorf("failed to write helen secrets: %w", err)
	}

	logger.Info("Vault secrets configured successfully")
	return nil
}

// deployNomadJob creates and deploys the Nomad job
func (m *Manager) deployNomadJob(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Deploying Nomad job")

	// Create job specification
	job, err := m.createNomadJobSpec()
	if err != nil {
		return fmt.Errorf("failed to create job spec: %w", err)
	}

	// Register the job
	resp, _, err := m.nomadClient.Jobs().Register(job, nil)
	if err != nil {
		logger.Error("Failed to register Nomad job", zap.Error(err))
		return fmt.Errorf("failed to register job: %w", err)
	}

	logger.Info("Nomad job registered", zap.String("eval_id", resp.EvalID))

	// Monitor deployment
	if err := m.monitorEvaluation(ctx, resp.EvalID); err != nil {
		return fmt.Errorf("deployment monitoring failed: %w", err)
	}

	return nil
}

// waitForHealthy waits for the deployment to become healthy
func (m *Manager) waitForHealthy(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Waiting for deployment to become healthy")

	// Wait a bit for the container to start
	time.Sleep(10 * time.Second)

	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		status, err := m.GetHealthStatus(ctx)
		if err == nil && status.Healthy {
			logger.Info("Deployment is healthy")
			return nil
		}

		logger.Debug("Waiting for deployment to be healthy",
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxAttempts))

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("deployment did not become healthy within timeout")
}

// Evaluation Phase Functions - Verify changes

// evaluatePrerequisites verifies prerequisites are working
func (m *Manager) evaluatePrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating prerequisites")

	// Re-check connectivity
	if _, err := m.nomadClient.Agent().Self(); err != nil {
		return fmt.Errorf("nomad connectivity verification failed: %w", err)
	}

	if _, err := m.vaultClient.Sys().Health(); err != nil {
		return fmt.Errorf("vault connectivity verification failed: %w", err)
	}

	// Verify work directory exists
	if _, err := os.Stat(m.config.WorkDir); os.IsNotExist(err) {
		return fmt.Errorf("work directory does not exist: %s", m.config.WorkDir)
	}

	logger.Info("Prerequisites evaluation successful")
	return nil
}

// evaluateVaultSecrets verifies secrets were created correctly
func (m *Manager) evaluateVaultSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating Vault secrets")

	// Verify Helen secrets exist
	secretPath := fmt.Sprintf("secret/data/helen/%s", m.config.Namespace)
	secret, err := m.vaultClient.Logical().Read(secretPath)
	if err != nil || secret == nil {
		return fmt.Errorf("helen secrets verification failed: %w", err)
	}

	// Verify essential fields exist
	if secret.Data != nil {
		if data, ok := secret.Data["data"].(map[string]interface{}); ok {
			if _, exists := data["project_name"]; !exists {
				return fmt.Errorf("project_name not found in secrets")
			}
			if _, exists := data["deployment_time"]; !exists {
				return fmt.Errorf("deployment_time not found in secrets")
			}
		}
	}

	logger.Info("Vault secrets evaluation successful")
	return nil
}

// evaluateNomadJob verifies the job was deployed successfully
func (m *Manager) evaluateNomadJob(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating Nomad job deployment")

	exists, err := m.DeploymentExists(ctx)
	if err != nil {
		return fmt.Errorf("job existence check failed: %w", err)
	}

	if !exists {
		return fmt.Errorf("job was not deployed successfully")
	}

	// Check job status
	job, _, err := m.nomadClient.Jobs().Info("helen", &api.QueryOptions{
		Namespace: m.config.Namespace,
	})
	if err != nil {
		return fmt.Errorf("failed to get job info: %w", err)
	}

	if *job.Status != "running" {
		return fmt.Errorf("job status is %s, expected running", *job.Status)
	}

	logger.Info("Nomad job evaluation successful")
	return nil
}

// evaluateDeploymentHealth verifies the deployment is healthy
func (m *Manager) evaluateDeploymentHealth(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating deployment health")

	status, err := m.GetHealthStatus(ctx)
	if err != nil {
		return fmt.Errorf("health status check failed: %w", err)
	}

	if !status.Healthy {
		return fmt.Errorf("deployment is not healthy")
	}

	// Test the website endpoint
	websiteURL := fmt.Sprintf("http://localhost:%d", m.config.Port)
	if err := m.checkHTTPEndpoint(ctx, websiteURL); err != nil {
		return fmt.Errorf("website accessibility check failed: %w", err)
	}

	logger.Info("Deployment health evaluation successful")
	return nil
}

// Helper functions

// checkCommandExists checks if a command is available
func (m *Manager) checkCommandExists(command string) error {
	_, err := exec.LookPath(command)
	return err
}

// checkHTTPEndpoint verifies if an HTTP endpoint is accessible
func (m *Manager) checkHTTPEndpoint(ctx context.Context, url string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Checking HTTP endpoint", zap.String("url", url))

	// Give the service time to start
	time.Sleep(5 * time.Second)

	cmd := exec.CommandContext(ctx, "curl", "-f", "-s", "-o", "/dev/null", "-w", "%{http_code}", url)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("HTTP check failed: %w", err)
	}

	statusCode := string(output)
	if statusCode != "200" {
		return fmt.Errorf("unexpected status code: %s", statusCode)
	}

	logger.Debug("HTTP endpoint check successful", zap.String("status_code", statusCode))
	return nil
}
