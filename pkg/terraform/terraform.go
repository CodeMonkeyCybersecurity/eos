// pkg/terraform/terraform.go

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
