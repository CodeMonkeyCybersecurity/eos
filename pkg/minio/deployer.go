package minio

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//go:embed templates/*
var templates embed.FS

// DeploymentOptions contains configuration for MinIO deployment
type DeploymentOptions struct {
	Datacenter    string
	StoragePath   string
	APIPort       int
	ConsolePort   int
	SkipSalt      bool
	SkipTerraform bool
}

// Deployer handles MinIO deployment operations
type Deployer struct{}

// NewDeployer creates a new MinIO deployer instance
func NewDeployer() *Deployer {
	return &Deployer{}
}

// Deploy executes the full MinIO deployment workflow
func (d *Deployer) Deploy(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Step 1: Apply SaltStack states
	if !opts.SkipSalt {
		logger.Info("Applying SaltStack states for MinIO")
		if err := d.applySaltStates(rc); err != nil {
			return eos_err.NewUserErr(fmt.Errorf("failed to apply Salt states: %w", err))
		}
	}

	// Step 2: Generate deployment files
	logger.Info("Generating deployment files")
	deployDir, err := d.generateDeploymentFiles(rc, opts)
	if err != nil {
		return eos_err.NewUserErr(fmt.Errorf("failed to generate deployment files: %w", err))
	}

	// Step 3: Run Terraform deployment
	if !opts.SkipTerraform {
		logger.Info("Running Terraform deployment")
		if err := d.runTerraformDeployment(rc, deployDir); err != nil {
			return eos_err.NewUserErr(fmt.Errorf("failed to run Terraform: %w", err))
		}
	}

	// Step 4: Verify deployment
	logger.Info("Verifying MinIO deployment")
	if err := d.verifyDeployment(rc, opts); err != nil {
		return eos_err.NewUserErr(fmt.Errorf("deployment verification failed: %w", err))
	}

	// Display access information
	d.displayAccessInfo(rc, opts)

	return nil
}

// applySaltStates runs Salt states for MinIO setup
func (d *Deployer) applySaltStates(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Apply MinIO setup states
	logger.Info("Applying MinIO Salt states")
	if _, err := eos_unix.RunCommandWithTimeout(rc.Ctx, 300, "salt", "*", "state.apply", "minio"); err != nil {
		return fmt.Errorf("failed to apply minio state: %w", err)
	}

	// Apply Vault policy states
	logger.Info("Applying Vault policy Salt states")
	if _, err := eos_unix.RunCommandWithTimeout(rc.Ctx, 300, "salt", "salt-master", "state.apply", "minio.vault_policy"); err != nil {
		logger.Warn("Failed to apply vault policy state (this may be expected if not running on salt-master)", zap.Error(err))
	}

	return nil
}

// generateDeploymentFiles creates Terraform and Nomad job files
func (d *Deployer) generateDeploymentFiles(rc *eos_io.RuntimeContext, opts *DeploymentOptions) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create temporary directory for deployment files
	deployDir := filepath.Join("/tmp", "minio-deploy")
	if err := os.MkdirAll(deployDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create deploy directory: %w", err)
	}

	// Create subdirectories
	terraformDir := filepath.Join(deployDir, "terraform", "minio")
	nomadDir := filepath.Join(deployDir, "nomad")
	
	if err := os.MkdirAll(terraformDir, 0755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(nomadDir, 0755); err != nil {
		return "", err
	}

	// Generate files from templates
	files := map[string]string{
		"templates/main.tf.tmpl":           filepath.Join(terraformDir, "main.tf"),
		"templates/variables.tf.tmpl":      filepath.Join(terraformDir, "variables.tf"),
		"templates/outputs.tf.tmpl":        filepath.Join(terraformDir, "outputs.tf"),
		"templates/terraform.tfvars.tmpl":  filepath.Join(terraformDir, "terraform.tfvars"),
		"templates/minio.nomad.hcl.tmpl":   filepath.Join(nomadDir, "minio.nomad.hcl"),
	}

	for tmplPath, outputPath := range files {
		logger.Debug("Generating file", zap.String("template", tmplPath), zap.String("output", outputPath))
		if err := d.renderTemplate(tmplPath, outputPath, opts); err != nil {
			return "", fmt.Errorf("failed to render %s: %w", tmplPath, err)
		}
	}

	return deployDir, nil
}

// renderTemplate renders a template file with the given options
func (d *Deployer) renderTemplate(tmplPath, outputPath string, opts *DeploymentOptions) error {
	tmplContent, err := templates.ReadFile(tmplPath)
	if err != nil {
		return fmt.Errorf("failed to read template: %w", err)
	}

	tmpl, err := template.New(filepath.Base(tmplPath)).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, opts); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// runTerraformDeployment executes Terraform to deploy MinIO
func (d *Deployer) runTerraformDeployment(rc *eos_io.RuntimeContext, deployDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	terraformDir := filepath.Join(deployDir, "terraform", "minio")

	// Initialize Terraform
	logger.Info("Initializing Terraform")
	if _, err := eos_unix.RunCommandInDirWithTimeout(rc.Ctx, terraformDir, 300, "terraform", "init"); err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	// Apply Terraform configuration
	logger.Info("Applying Terraform configuration")
	if _, err := eos_unix.RunCommandInDirWithTimeout(rc.Ctx, terraformDir, 600, "terraform", "apply", "-auto-approve"); err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	return nil
}

// verifyDeployment checks if MinIO is running correctly
func (d *Deployer) verifyDeployment(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check Nomad job status
	logger.Info("Checking Nomad job status")
	output, err := eos_unix.RunCommandWithTimeout(rc.Ctx, 30, "nomad", "job", "status", "minio")
	if err != nil {
		return fmt.Errorf("failed to check Nomad job status: %w", err)
	}
	logger.Debug("Nomad job status", zap.String("output", output))

	// Check MinIO health endpoint
	logger.Info("Checking MinIO health endpoint")
	healthURL := fmt.Sprintf("http://localhost:%d/minio/health/live", opts.APIPort)
	if _, err := eos_unix.RunCommandWithTimeout(rc.Ctx, 30, "curl", "-f", "-s", healthURL); err != nil {
		logger.Warn("MinIO health check failed (service may still be starting)", zap.Error(err))
	}

	return nil
}

// displayAccessInfo shows how to access MinIO
func (d *Deployer) displayAccessInfo(rc *eos_io.RuntimeContext, opts *DeploymentOptions) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("MinIO deployment successful",
		zap.String("api_endpoint", fmt.Sprintf("http://localhost:%d", opts.APIPort)),
		zap.String("console_endpoint", fmt.Sprintf("http://localhost:%d", opts.ConsolePort)),
		zap.String("credentials_path", "kv/minio/root"),
	)

	logger.Info("To retrieve credentials run: vault kv get kv/minio/root")
	logger.Info("To configure mc client: mc alias set local http://localhost:9123 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD")
}