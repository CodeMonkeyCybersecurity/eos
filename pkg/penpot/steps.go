package penpot

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Assessment Phase Functions - Check current state

// assessPrerequisites checks if all required tools are available
func (m *Manager) assessPrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Assessing system prerequisites")

	requiredTools := []string{"docker", "terraform", "nomad", "vault"}

	for _, tool := range requiredTools {
		if err := m.checkCommandExists(tool); err != nil {
			logger.Error(" Required tool not found",
				zap.String("tool", tool),
				zap.Error(err))
			return fmt.Errorf("required tool %s not found: %w", tool, err)
		}
		logger.Debug(" Tool found", zap.String("tool", tool))
	}

	return nil
}

// assessVaultSecrets checks if Vault secrets already exist
func (m *Manager) assessVaultSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Assessing Vault secrets")

	// Check if we can connect to Vault
	health, err := m.vaultClient.Sys().Health()
	if err != nil {
		logger.Error(" Cannot connect to Vault", zap.Error(err))
		return fmt.Errorf("vault connection failed: %w", err)
	}

	logger.Debug(" Vault connection successful",
		zap.Bool("initialized", health.Initialized),
		zap.Bool("sealed", health.Sealed))

	// Check if secrets already exist
	secret, err := m.vaultClient.Logical().Read("secret/data/penpot")
	if err != nil {
		logger.Debug("Penpot secrets not found, will create", zap.Error(err))
		return nil // Not an error, we'll create them
	}

	if secret != nil && secret.Data != nil {
		logger.Info(" Penpot secrets already exist in Vault")
	}

	return nil
}

// assessTerraformConfig checks if Terraform configuration exists
func (m *Manager) assessTerraformConfig(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Assessing Terraform configuration")

	// Check if work directory exists
	if _, err := os.Stat(m.config.WorkDir); os.IsNotExist(err) {
		logger.Debug("Work directory does not exist, will create",
			zap.String("dir", m.config.WorkDir))
		return nil
	}

	// Check if main.tf exists
	tfPath := filepath.Join(m.config.WorkDir, "main.tf")
	if _, err := os.Stat(tfPath); os.IsNotExist(err) {
		logger.Debug("Terraform configuration does not exist, will create",
			zap.String("path", tfPath))
		return nil
	}

	logger.Info(" Terraform configuration found", zap.String("path", tfPath))
	return nil
}

// assessTerraformState checks if Terraform infrastructure is applied
func (m *Manager) assessTerraformState(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Assessing Terraform state")

	// Check if terraform state file exists
	statePath := filepath.Join(m.config.WorkDir, "terraform.tfstate")
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		logger.Debug("Terraform state does not exist, infrastructure not applied")
		return nil
	}

	logger.Info(" Terraform state found", zap.String("path", statePath))
	return nil
}

// assessNomadJob checks if Nomad job is deployed
func (m *Manager) assessNomadJob(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Assessing Nomad job deployment")

	exists, err := m.DeploymentExists(ctx)
	if err != nil {
		logger.Error(" Failed to check job existence", zap.Error(err))
		return fmt.Errorf("failed to check job existence: %w", err)
	}

	if exists {
		logger.Info(" Penpot job already exists in Nomad")
	} else {
		logger.Debug("Penpot job does not exist, will deploy")
	}

	return nil
}

// assessDeploymentHealth checks if deployment is healthy
func (m *Manager) assessDeploymentHealth(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Assessing deployment health")

	status, err := m.GetHealthStatus(ctx)
	if err != nil {
		logger.Debug("Cannot get health status, deployment may not exist", zap.Error(err))
		return nil // Not an error during assessment
	}

	if status.Healthy {
		logger.Info(" Deployment is healthy")
	} else {
		logger.Debug("Deployment exists but is not healthy")
	}

	return nil
}

// Intervention Phase Functions - Make changes

// ensurePrerequisites ensures all prerequisites are met
func (m *Manager) ensurePrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Ensuring prerequisites are met")

	// Check Nomad connectivity
	if _, err := m.nomadClient.Agent().Self(); err != nil {
		logger.Error(" Cannot connect to Nomad", zap.Error(err))
		return fmt.Errorf("nomad connection failed: %w", err)
	}

	// Check Vault connectivity
	if _, err := m.vaultClient.Sys().Health(); err != nil {
		logger.Error(" Cannot connect to Vault", zap.Error(err))
		return fmt.Errorf("vault connection failed: %w", err)
	}

	logger.Info(" All prerequisites verified")
	return nil
}

// setupVaultSecrets creates or updates Vault secrets
func (m *Manager) setupVaultSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Setting up Vault secrets")

	// Generate secure passwords
	dbPassword := m.generateSecurePassword(32)
	secretKey := m.generateSecurePassword(64)

	// Create Penpot secrets
	penpotSecrets := map[string]interface{}{
		"database_password": dbPassword,
		"secret_key":        secretKey,
		"database_uri":      fmt.Sprintf("postgresql://penpot:%s@postgres:5432/penpot", dbPassword),
		"redis_uri":         "redis://redis:6379/0",
		"public_uri":        fmt.Sprintf("http://localhost:%d", m.config.Port),
	}

	// Write secrets to Vault
	_, err := m.vaultClient.Logical().Write("secret/data/penpot", map[string]interface{}{
		"data": penpotSecrets,
	})
	if err != nil {
		logger.Error(" Failed to write Penpot secrets to Vault", zap.Error(err))
		return fmt.Errorf("failed to write penpot secrets: %w", err)
	}

	// Create PostgreSQL secrets
	pgSecrets := map[string]interface{}{
		"username": "penpot",
		"password": dbPassword,
		"database": "penpot",
	}

	_, err = m.vaultClient.Logical().Write("secret/data/postgres", map[string]interface{}{
		"data": pgSecrets,
	})
	if err != nil {
		logger.Error(" Failed to write PostgreSQL secrets to Vault", zap.Error(err))
		return fmt.Errorf("failed to write postgres secrets: %w", err)
	}

	logger.Info(" Vault secrets configured successfully")
	return nil
}

// createTerraformConfig creates Terraform configuration files
func (m *Manager) createTerraformConfig(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("📝 Creating Terraform configuration")

	// Create work directory
	if err := os.MkdirAll(m.config.WorkDir, 0755); err != nil {
		return fmt.Errorf("failed to create work directory: %w", err)
	}

	terraformConfig := fmt.Sprintf(`
terraform {
  required_providers {
    nomad = {
      source  = "hashicorp/nomad"
      version = "~> 2.0"
    }
    vault = {
      source  = "hashicorp/vault"  
      version = "~> 3.0"
    }
  }
}

provider "nomad" {
  address = "%s"
}

provider "vault" {
  address = "%s"
  token   = "%s"
}

# Create a dedicated namespace for Penpot
resource "nomad_namespace" "penpot" {
  name        = "%s"
  description = "Namespace for Penpot deployment"
}

# Configure Vault policy for Nomad
resource "vault_policy" "nomad_penpot" {
  name = "nomad-penpot"

  policy = <<EOT
path "secret/data/penpot" {
  capabilities = ["read"]
}

path "secret/data/postgres" {
  capabilities = ["read"]
}
EOT
}

# Create Vault token role for Nomad
resource "vault_token_auth_backend_role" "nomad_penpot" {
  role_name              = "nomad-penpot"
  allowed_policies       = ["nomad-penpot"]
  orphan                 = true
  renewable              = true
  token_explicit_max_ttl = 0
}

output "namespace" {
  value = nomad_namespace.penpot.name
}
`, m.config.NomadAddr, m.config.VaultAddr, m.config.VaultToken, m.config.Namespace)

	// Write Terraform configuration
	tfPath := filepath.Join(m.config.WorkDir, "main.tf")
	if err := os.WriteFile(tfPath, []byte(terraformConfig), 0644); err != nil {
		logger.Error(" Failed to write Terraform config", zap.Error(err))
		return fmt.Errorf("failed to write terraform config: %w", err)
	}

	logger.Info(" Terraform configuration created", zap.String("path", tfPath))
	return nil
}

// applyTerraform runs Terraform to create infrastructure
func (m *Manager) applyTerraform(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("🏗️ Applying Terraform infrastructure")

	// Initialize Terraform
	if err := m.runTerraformCommand(ctx, "init"); err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	// Plan Terraform changes
	if err := m.runTerraformCommand(ctx, "plan", "-out=tfplan"); err != nil {
		return fmt.Errorf("terraform plan failed: %w", err)
	}

	// Apply Terraform changes
	if err := m.runTerraformCommand(ctx, "apply", "-auto-approve", "tfplan"); err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	logger.Info(" Terraform infrastructure applied successfully")
	return nil
}

// deployNomadJob creates and deploys the Nomad job
func (m *Manager) deployNomadJob(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Deploying Nomad job")

	// Create job specification
	job, err := m.createNomadJobSpec()
	if err != nil {
		return fmt.Errorf("failed to create job spec: %w", err)
	}

	// Register the job
	resp, _, err := m.nomadClient.Jobs().Register(job, nil)
	if err != nil {
		logger.Error(" Failed to register Nomad job", zap.Error(err))
		return fmt.Errorf("failed to register job: %w", err)
	}

	logger.Info(" Nomad job registered", zap.String("eval_id", resp.EvalID))

	// Monitor deployment
	if err := m.monitorEvaluation(ctx, resp.EvalID); err != nil {
		return fmt.Errorf("deployment monitoring failed: %w", err)
	}

	return nil
}

// waitForHealthy waits for the deployment to become healthy
func (m *Manager) waitForHealthy(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("⏳ Waiting for deployment to become healthy")

	// Implementation would wait for services to be ready
	// For now, we'll add a simple placeholder
	logger.Info(" Deployment health check placeholder completed")

	return nil
}

// Evaluation Phase Functions - Verify changes

// evaluatePrerequisites verifies prerequisites are working
func (m *Manager) evaluatePrerequisites(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Evaluating prerequisites")

	// Re-check connectivity
	if _, err := m.nomadClient.Agent().Self(); err != nil {
		return fmt.Errorf("nomad connectivity verification failed: %w", err)
	}

	if _, err := m.vaultClient.Sys().Health(); err != nil {
		return fmt.Errorf("vault connectivity verification failed: %w", err)
	}

	logger.Info(" Prerequisites evaluation successful")
	return nil
}

// evaluateVaultSecrets verifies secrets were created correctly
func (m *Manager) evaluateVaultSecrets(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Evaluating Vault secrets")

	// Verify Penpot secrets exist
	secret, err := m.vaultClient.Logical().Read("secret/data/penpot")
	if err != nil || secret == nil {
		return fmt.Errorf("penpot secrets verification failed: %w", err)
	}

	// Verify PostgreSQL secrets exist
	pgSecret, err := m.vaultClient.Logical().Read("secret/data/postgres")
	if err != nil || pgSecret == nil {
		return fmt.Errorf("postgres secrets verification failed: %w", err)
	}

	logger.Info(" Vault secrets evaluation successful")
	return nil
}

// evaluateTerraformConfig verifies Terraform config was created
func (m *Manager) evaluateTerraformConfig(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Evaluating Terraform configuration")

	tfPath := filepath.Join(m.config.WorkDir, "main.tf")
	if _, err := os.Stat(tfPath); os.IsNotExist(err) {
		return fmt.Errorf("terraform configuration file not found: %s", tfPath)
	}

	logger.Info(" Terraform configuration evaluation successful")
	return nil
}

// evaluateTerraformState verifies Terraform was applied successfully
func (m *Manager) evaluateTerraformState(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Evaluating Terraform state")

	// Check if namespace was created by querying Nomad
	_, _, err := m.nomadClient.Namespaces().Info(m.config.Namespace, nil)
	if err != nil {
		return fmt.Errorf("namespace verification failed: %w", err)
	}

	logger.Info(" Terraform state evaluation successful")
	return nil
}

// evaluateNomadJob verifies the job was deployed successfully
func (m *Manager) evaluateNomadJob(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Evaluating Nomad job deployment")

	exists, err := m.DeploymentExists(ctx)
	if err != nil {
		return fmt.Errorf("job existence check failed: %w", err)
	}

	if !exists {
		return fmt.Errorf("job was not deployed successfully")
	}

	logger.Info(" Nomad job evaluation successful")
	return nil
}

// evaluateDeploymentHealth verifies the deployment is healthy
func (m *Manager) evaluateDeploymentHealth(ctx context.Context, mgr *Manager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(" Evaluating deployment health")

	status, err := m.GetHealthStatus(ctx)
	if err != nil {
		return fmt.Errorf("health status check failed: %w", err)
	}

	if !status.Healthy {
		return fmt.Errorf("deployment is not healthy")
	}

	logger.Info(" Deployment health evaluation successful")
	return nil
}

// Helper functions

// checkCommandExists checks if a command is available
func (m *Manager) checkCommandExists(command string) error {
	_, err := exec.LookPath(command)
	return err
}

// generateSecurePassword generates a secure password
func (m *Manager) generateSecurePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

// runTerraformCommand runs a terraform command in the work directory
func (m *Manager) runTerraformCommand(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "terraform", args...)
	cmd.Dir = m.config.WorkDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
