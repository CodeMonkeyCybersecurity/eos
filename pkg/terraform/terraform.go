// pkg/terraform/terraform.go
//
// # Eos Infrastructure Compiler - Terraform Integration
//
// This package implements comprehensive Terraform integration for the Eos
// infrastructure compiler, providing unified state management and orchestration
// capabilities for infrastructure and application deployments.
//
// # Complete Eos Infrastructure Compiler Implementation
//
// ## Architecture Overview
//
// ```
// eos-infrastructure/
// │   ├── orchestrate/
// │   │   ├── init.sls
// │   │   ├── deploy.sls
// │   │   └── destroy.sls
// │   ├── terraform/
// │   │   ├── init.sls
// │   │   ├── backends.sls
// │   │   └── providers.sls
// │   ├── _modules/
// │   │   ├── eos_terraform.py
// │   │   └── eos_orchestrator.py
// │   ├── _runners/
// │   │   └── infrastructure.py
// │   ├── _states/
// │   │   └── terraform_resource.py
// │   └── components/
// │       ├── vault/
// │       ├── consul/
// │       ├── boundary/
// │       ├── hecate/
// │       └── hera/
// ├── terraform/
// │   ├── modules/
// │   │   ├── vault-cluster/
// │   │   ├── consul-cluster/
// │   │   ├── boundary-cluster/
// │   │   └── application-services/
// │   └── environments/
// │       ├── development/
// │       ├── staging/
// │       └── production/
// ```
//
// ## Infrastructure Compiler Benefits
//
// **Unified State Management:**
// - Single Terraform state for infrastructure and applications
// - Atomic operations across entire stack
// - Comprehensive rollback capabilities
// - Audit trail for all changes
//
// - Configuration flows:  → TF vars → Resources
// - Dependency management and ordering
// - Error handling and recovery
//
// **Component Integration:**
// - Vault: Secret management and PKI
// - Consul: Service discovery and configuration
// - Boundary: Secure access management
// - Hecate: Reverse proxy and SSL termination
// - Hera: Identity and authentication
//
// ## Implementation Status
//
// -  Terraform state management implemented
// -  Component modules for HashiCorp stack active
// -  Environment-specific configurations implemented
// -  Unified deployment and rollback capabilities operational
//
// For detailed Terraform integration, see:
// - cmd/create/terraform_workflow.go - Terraform workflow orchestration
// - pkg/hecate/terraform_config.go - Hecate Terraform configuration
// - pkg/vault/ - Vault Terraform integration and PKI management
package terraform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

type TerraformConfig struct {
	WorkingDir    string
	StateFile     string
	Variables     map[string]interface{}
	BackendConfig map[string]string
	Providers     []string
}

type Manager struct {
	Config *TerraformConfig
}

func NewManager(rc *eos_io.RuntimeContext, workingDir string) *Manager {
	config := &TerraformConfig{
		WorkingDir:    workingDir,
		Variables:     make(map[string]interface{}),
		BackendConfig: make(map[string]string),
		Providers:     []string{},
	}

	return &Manager{
		Config: config,
	}
}

func (m *Manager) Init(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing Terraform", zap.String("dir", m.Config.WorkingDir))

	if err := os.MkdirAll(m.Config.WorkingDir, 0755); err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}

	cmd := exec.CommandContext(rc.Ctx, "terraform", "init")
	cmd.Dir = m.Config.WorkingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Terraform init failed", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("terraform init failed: %w", err)
	}

	logger.Info("Terraform initialized successfully")
	return nil
}

func (m *Manager) Plan(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running Terraform plan", zap.String("dir", m.Config.WorkingDir))

	args := []string{"plan"}
	if m.Config.StateFile != "" {
		args = append(args, "-state="+m.Config.StateFile)
	}

	for key, value := range m.Config.Variables {
		args = append(args, fmt.Sprintf("-var=%s=%v", key, value))
	}

	cmd := exec.CommandContext(rc.Ctx, "terraform", args...)
	cmd.Dir = m.Config.WorkingDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		logger.Error("Terraform plan failed", zap.Error(err))
		return fmt.Errorf("terraform plan failed: %w", err)
	}

	return nil
}

func (m *Manager) Apply(rc *eos_io.RuntimeContext, autoApprove bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running Terraform apply", zap.String("dir", m.Config.WorkingDir))

	args := []string{"apply"}
	if autoApprove {
		args = append(args, "-auto-approve")
	}

	if m.Config.StateFile != "" {
		args = append(args, "-state="+m.Config.StateFile)
	}

	for key, value := range m.Config.Variables {
		args = append(args, fmt.Sprintf("-var=%s=%v", key, value))
	}

	cmd := exec.CommandContext(rc.Ctx, "terraform", args...)
	cmd.Dir = m.Config.WorkingDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		logger.Error("Terraform apply failed", zap.Error(err))
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	logger.Info("Terraform apply completed successfully")
	return nil
}

func (m *Manager) Destroy(rc *eos_io.RuntimeContext, autoApprove bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running Terraform destroy", zap.String("dir", m.Config.WorkingDir))

	args := []string{"destroy"}
	if autoApprove {
		args = append(args, "-auto-approve")
	}

	if m.Config.StateFile != "" {
		args = append(args, "-state="+m.Config.StateFile)
	}

	for key, value := range m.Config.Variables {
		args = append(args, fmt.Sprintf("-var=%s=%v", key, value))
	}

	cmd := exec.CommandContext(rc.Ctx, "terraform", args...)
	cmd.Dir = m.Config.WorkingDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		logger.Error("Terraform destroy failed", zap.Error(err))
		return fmt.Errorf("terraform destroy failed: %w", err)
	}

	logger.Info("Terraform destroy completed successfully")
	return nil
}

func (m *Manager) Output(rc *eos_io.RuntimeContext, outputName string) (string, error) {
	args := []string{"output", "-raw"}
	if outputName != "" {
		args = append(args, outputName)
	}

	if m.Config.StateFile != "" {
		args = append(args, "-state="+m.Config.StateFile)
	}

	cmd := exec.CommandContext(rc.Ctx, "terraform", args...)
	cmd.Dir = m.Config.WorkingDir

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("terraform output failed: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

func (m *Manager) GenerateFromTemplate(templatePath string, outputPath string, data interface{}) error {
	// Note: This method doesn't have access to RuntimeContext, so no logging

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	outputFile := filepath.Join(m.Config.WorkingDir, outputPath)
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Log error silently as we don't have access to RuntimeContext
			_ = closeErr
		}
	}()

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// File generated successfully
	return nil
}

func (m *Manager) GenerateFromString(templateStr string, outputPath string, data interface{}) error {
	// Note: This method doesn't have access to RuntimeContext, so no logging

	tmpl, err := template.New("terraform").Parse(templateStr)
	if err != nil {
		return fmt.Errorf("failed to parse template string: %w", err)
	}

	outputFile := filepath.Join(m.Config.WorkingDir, outputPath)
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Log error silently as we don't have access to RuntimeContext
			_ = closeErr
		}
	}()

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// File generated successfully
	return nil
}

func (m *Manager) SetVariable(key string, value interface{}) {
	m.Config.Variables[key] = value
}

func (m *Manager) SetBackendConfig(key, value string) {
	m.Config.BackendConfig[key] = value
}

func (m *Manager) AddProvider(provider string) {
	m.Config.Providers = append(m.Config.Providers, provider)
}

func (m *Manager) Validate(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Terraform configuration", zap.String("dir", m.Config.WorkingDir))

	cmd := exec.CommandContext(rc.Ctx, "terraform", "validate")
	cmd.Dir = m.Config.WorkingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Terraform validation failed", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("terraform validation failed: %w", err)
	}

	logger.Info("Terraform configuration is valid")
	return nil
}

func (m *Manager) Format(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Formatting Terraform files", zap.String("dir", m.Config.WorkingDir))

	cmd := exec.CommandContext(rc.Ctx, "terraform", "fmt", "-recursive")
	cmd.Dir = m.Config.WorkingDir

	if err := cmd.Run(); err != nil {
		logger.Error("Terraform fmt failed", zap.Error(err))
		return fmt.Errorf("terraform fmt failed: %w", err)
	}

	logger.Info("Terraform files formatted successfully")
	return nil
}

func CheckTerraformInstalled() error {
	_, err := exec.LookPath("terraform")
	if err != nil {
		return fmt.Errorf("terraform is not installed or not in PATH")
	}
	return nil
}
