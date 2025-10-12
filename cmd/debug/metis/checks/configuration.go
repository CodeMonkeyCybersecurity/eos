package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/debug/metis"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// CheckConfigurationWithResult validates the Metis configuration file.
func CheckConfigurationWithResult(rc *eos_io.RuntimeContext, projectDir string, verbose bool) (*metis.MetisConfig, metis.CheckResult) {
	config, err := checkConfiguration(rc, projectDir, verbose)
	result := metis.CheckResult{
		Name:     "Configuration File",
		Category: "Configuration",
		Passed:   err == nil,
		Error:    err,
	}

	if err != nil {
		configPath := filepath.Join(projectDir, "config.yaml")
		result.Remediation = []string{
			fmt.Sprintf("Edit configuration file: sudo nano %s", configPath),
			"Verify YAML syntax is valid",
			"Ensure all required fields are set:",
			"  - temporal.host_port (e.g., localhost:7233)",
			"  - azure_openai.endpoint (Azure OpenAI endpoint URL)",
			"  - email.smtp_host (SMTP server address)",
			"Example config: https://github.com/.../config.example.yaml",
		}
	} else {
		result.Details = "Configuration valid with all required fields"
	}

	return config, result
}

func checkConfiguration(rc *eos_io.RuntimeContext, projectDir string, verbose bool) (*metis.MetisConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	configPath := filepath.Join(projectDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config metis.MetisConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate required fields
	if config.Temporal.HostPort == "" {
		return nil, fmt.Errorf("temporal.host_port not configured")
	}
	if config.AzureOpenAI.Endpoint == "" || strings.Contains(config.AzureOpenAI.Endpoint, "YOUR-") {
		return nil, fmt.Errorf("azure_openai.endpoint not configured")
	}
	if config.Email.SMTPHost == "" {
		return nil, fmt.Errorf("email.smtp_host not configured")
	}

	if verbose {
		logger.Debug("Configuration loaded",
			zap.String("temporal_host", config.Temporal.HostPort),
			zap.String("openai_endpoint", config.AzureOpenAI.Endpoint),
			zap.String("smtp_host", config.Email.SMTPHost))
	}

	return &config, nil
}

// CheckAzureOpenAIWithResult validates Azure OpenAI configuration.
func CheckAzureOpenAIWithResult(rc *eos_io.RuntimeContext, config *metis.MetisConfig) metis.CheckResult {
	err := checkAzureOpenAI(rc, config)
	result := metis.CheckResult{
		Name:     "Azure OpenAI Configuration",
		Category: "Configuration",
		Passed:   err == nil,
		Error:    err,
	}

	if err != nil {
		result.Remediation = []string{
			"Get Azure OpenAI credentials from Azure Portal",
			"Edit config.yaml and set azure_openai section:",
			"  endpoint: https://<resource>.openai.azure.com/",
			"  api_key: <your-api-key>",
			"  deployment_name: <your-deployment>",
			"  api_version: 2024-02-15-preview",
			"Docs: https://learn.microsoft.com/azure/ai-services/openai/",
		}
	} else {
		result.Details = "Azure OpenAI credentials configured"
	}

	return result
}

func checkAzureOpenAI(rc *eos_io.RuntimeContext, config *metis.MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Basic validation
	if strings.Contains(config.AzureOpenAI.APIKey, "YOUR-") {
		return fmt.Errorf("azure_openai.api_key contains placeholder text")
	}
	if config.AzureOpenAI.DeploymentName == "" {
		return fmt.Errorf("azure_openai.deployment_name not set")
	}
	if !strings.HasPrefix(config.AzureOpenAI.Endpoint, "https://") {
		return fmt.Errorf("azure_openai.endpoint must start with https://")
	}

	return nil
}

// CheckSMTPConfigWithResult validates SMTP configuration.
func CheckSMTPConfigWithResult(rc *eos_io.RuntimeContext, config *metis.MetisConfig) metis.CheckResult {
	err := checkSMTPConfig(rc, config)
	result := metis.CheckResult{
		Name:     "SMTP Configuration",
		Category: "Configuration",
		Passed:   err == nil,
		Error:    err,
	}

	if err != nil {
		result.Remediation = []string{
			"Configure SMTP settings in config.yaml email section:",
			"  smtp_host: smtp.gmail.com (or your SMTP server)",
			"  smtp_port: 587 (or 465 for SSL)",
			"  username: your-email@example.com",
			"  password: <app-password>",
			"  from: metis@example.com",
			"  to: security-team@example.com",
			"For Gmail: use App Password, not account password",
		}
	} else {
		result.Details = "SMTP configuration complete"
	}

	return result
}

func checkSMTPConfig(rc *eos_io.RuntimeContext, config *metis.MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	if config.Email.SMTPHost == "" {
		return fmt.Errorf("email.smtp_host not set")
	}
	if config.Email.SMTPPort == 0 {
		return fmt.Errorf("email.smtp_port not set")
	}
	if config.Email.From == "" {
		return fmt.Errorf("email.from not set")
	}
	if config.Email.To == "" {
		return fmt.Errorf("email.to not set")
	}

	return nil
}
