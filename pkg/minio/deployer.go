package minio

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
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
	Skip          bool
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

	// Step 0: Run preflight checks
	logger.Info("Running preflight checks for MinIO deployment")
	if err := CheckPrerequisites(rc); err != nil {
		return err
	}

	// Configure Vault secrets
	config := &Config{
		Region:        DefaultRegion,
		BrowserEnable: true,
	}
	if err := ConfigureVaultSecrets(rc, config); err != nil {
		return err
	}

	// Configure Vault policies
	if err := ConfigureVaultPolicies(rc); err != nil {
		return err
	}

	// Step 2: Generate deployment files
	logger.Info("Generating deployment files")
	deployDir, err := d.generateDeploymentFiles(rc, opts)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to generate deployment files: %w", err))
	}

	// Step 3: Run Terraform deployment
	if !opts.SkipTerraform {
		logger.Info("Running Terraform deployment")
		if err := d.runTerraformDeployment(rc, deployDir); err != nil {
			return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to run Terraform: %w", err))
		}
	}

	// Step 4: Verify deployment
	logger.Info("Verifying MinIO deployment")
	if err := VerifyDeployment(rc, opts); err != nil {
		return err
	}

	// Display access information
	DisplayAccessInfo(rc, opts)

	return nil
}

// applyStates runs  states for MinIO setup
func (d *Deployer) applyStates(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Apply MinIO setup states (using masterless mode with -call)
	logger.Info("Applying MinIO  states")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "-call",
		Args:    []string{"--local", "state.apply", "minio"},
		Timeout: 300 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to apply minio state: %w", err)
	}
	logger.Debug(" state output", zap.String("output", output))

	// Apply Vault policy states (also using masterless mode)
	logger.Info("Applying Vault policy  states")
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "-call",
		Args:    []string{"--local", "state.apply", "minio.vault_policy"},
		Timeout: 300 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to apply vault policy state (this may be expected in masterless mode)", zap.Error(err))
	} else {
		logger.Debug("Vault policy state output", zap.String("output", output))
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
		"templates/main.tf.tmpl":          filepath.Join(terraformDir, "main.tf"),
		"templates/variables.tf.tmpl":     filepath.Join(terraformDir, "variables.tf"),
		"templates/outputs.tf.tmpl":       filepath.Join(terraformDir, "outputs.tf"),
		"templates/terraform.tfvars.tmpl": filepath.Join(terraformDir, "terraform.tfvars"),
		"templates/minio.nomad.hcl.tmpl":  filepath.Join(nomadDir, "minio.nomad.hcl"),
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
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Log using logger if available in context, otherwise silently continue
			// as this is a non-critical error during cleanup
		}
	}()

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
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"init"},
		Dir:     terraformDir,
		Timeout: 300 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}
	logger.Debug("Terraform init output", zap.String("output", output))

	// Apply Terraform configuration
	logger.Info("Applying Terraform configuration")
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"apply", "-auto-approve"},
		Dir:     terraformDir,
		Timeout: 600 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}
	logger.Debug("Terraform apply output", zap.String("output", output))

	return nil
}
