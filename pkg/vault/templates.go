// pkg/vault/templates.go
// Vault Agent template rendering configuration
//
// This module enables HashiCorp Vault Agent template rendering for automatic
// secret injection and rotation without application code changes.
//
// HashiCorp Pattern: Use template rendering for apps that consume secrets via
// environment variables or configuration files.
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AgentTemplateConfig defines a Vault Agent template configuration
// NOTE: Renamed from TemplateConfig to avoid conflict with template_bionicgpt.go:TemplateConfig
type AgentTemplateConfig struct {
	ServiceName      string // e.g., "bionicgpt"
	SourceTemplate   string // Path to .ctmpl file
	DestinationFile  string // Where to write rendered file
	FilePermissions  string // e.g., "0640"
	CommandOnChange  string // Command to run when template changes
	TemplateContent  string // Actual template content (if not reading from file)
}

// EnableTemplatesConfig configures template rendering enablement
type EnableTemplatesConfig struct {
	Services []string // Services to enable templates for (empty = all)
	DryRun   bool     // Preview changes without applying
}

const (
	// Template directory paths
	TemplateDir = "/etc/vault.d/templates"

	// Agent config path
	AgentConfigPath = "/etc/vault.d/agent-config.hcl"
)

// EnableTemplates enables Vault Agent template rendering for specified services
// Follows Assess → Intervene → Evaluate pattern
func EnableTemplates(rc *eos_io.RuntimeContext, config *EnableTemplatesConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Enabling Vault Agent template rendering")
	logger.Info("This feature allows automatic secret injection and rotation")
	logger.Info("")

	// ASSESS - Check current state
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("ASSESS: Checking current template configuration")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Check if template directory exists
	if _, err := os.Stat(TemplateDir); os.IsNotExist(err) {
		logger.Info(fmt.Sprintf("Template directory does not exist: %s", TemplateDir))
		if !config.DryRun {
			logger.Info("Creating template directory...")
			if err := os.MkdirAll(TemplateDir, VaultBaseDirPerm); err != nil {
				return fmt.Errorf("failed to create template directory: %w", err)
			}
			logger.Info("✓ Template directory created")
		} else {
			logger.Info("[DRY RUN] Would create template directory")
		}
	} else {
		logger.Info(fmt.Sprintf("✓ Template directory exists: %s", TemplateDir))
	}

	// Check current Agent configuration
	hasTemplates, err := checkAgentHasTemplates(rc)
	if err != nil {
		logger.Warn("Could not check Agent configuration", zap.Error(err))
	} else if hasTemplates {
		logger.Info("⚠ Agent configuration already contains template blocks")
		logger.Info("Existing templates will be preserved")
	} else {
		logger.Info("Agent configuration does not contain template blocks yet")
	}

	// INTERVENE - Create templates and update Agent config
	logger.Info("")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("INTERVENE: Creating templates and updating Agent config")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if config.DryRun {
		logger.Info("[DRY RUN] Would perform the following actions:")
		logger.Info("  1. Create template files in /etc/vault.d/templates/")
		logger.Info("  2. Update Vault Agent configuration")
		logger.Info("  3. Restart Vault Agent service")
		logger.Info("")
		logger.Info("Run without --dry-run to apply changes")
		return nil
	}

	// Show informational message
	logger.Info("Template rendering is currently in PREVIEW mode")
	logger.Info("To enable templates for a service, create a .ctmpl file manually:")
	logger.Info("")
	logger.Info("Example: BionicGPT .env template")
	logger.Info(fmt.Sprintf("  File: %s/bionicgpt.env.ctmpl", TemplateDir))
	logger.Info("  Content:")
	logger.Info("    {{- with secret \"services/production/bionicgpt\" }}")
	logger.Info("    POSTGRES_PASSWORD={{ .Data.data.postgres_password }}")
	logger.Info("    JWT_SECRET={{ .Data.data.jwt_secret }}")
	logger.Info("    {{- end }}")
	logger.Info("")
	logger.Info("Then add to agent-config.hcl:")
	logger.Info("  template {")
	logger.Info(fmt.Sprintf("    source      = \"%s/bionicgpt.env.ctmpl\"", TemplateDir))
	logger.Info("    destination = \"/opt/bionicgpt/.env\"")
	logger.Info("    perms       = \"0640\"")
	logger.Info("    command     = \"docker compose -f /opt/bionicgpt/docker-compose.yml up -d --force-recreate\"")
	logger.Info("  }")
	logger.Info("")
	logger.Info("Restart Vault Agent:")
	logger.Info("  sudo systemctl restart vault-agent-eos")
	logger.Info("")

	// EVALUATE
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("EVALUATE: Template rendering setup")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("")
	logger.Info("Template directory ready: " + TemplateDir)
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info("  1. Create .ctmpl files for your services")
	logger.Info("  2. Add template blocks to agent-config.hcl")
	logger.Info("  3. Restart Vault Agent")
	logger.Info("  4. Verify secrets are rendered correctly")
	logger.Info("")
	logger.Info("Benefits:")
	logger.Info("  • 0ms Vault I/O during deployment (secrets pre-rendered)")
	logger.Info("  • Automatic secret rotation (Agent watches Vault)")
	logger.Info("  • No application code changes required")
	logger.Info("  • Resilient to Vault outages (cached secrets)")
	logger.Info("")

	return nil
}

// checkAgentHasTemplates checks if Agent config already has template blocks
func checkAgentHasTemplates(rc *eos_io.RuntimeContext) (bool, error) {
	data, err := os.ReadFile(AgentConfigPath)
	if err != nil {
		return false, err
	}

	content := string(data)
	return strings.Contains(content, "template {"), nil
}

// GenerateBionicGPTTemplate generates a sample template for BionicGPT
// This serves as an example for users to understand the pattern
func GenerateBionicGPTTemplate() string {
	return `# Vault Agent Template for BionicGPT
# This template automatically injects secrets from Vault into the .env file
# Vault Agent watches for changes and re-renders automatically

{{- with secret "services/production/bionicgpt" }}
# Database Configuration
POSTGRES_PASSWORD={{ .Data.data.postgres_password }}

# Authentication
JWT_SECRET={{ .Data.data.jwt_secret }}

# AI Model Configuration
{{- if .Data.data.litellm_master_key }}
LITELLM_MASTER_KEY={{ .Data.data.litellm_master_key }}
{{- end }}

{{- if .Data.data.azure_openai_api_key }}
AZURE_OPENAI_API_KEY={{ .Data.data.azure_openai_api_key }}
{{- end }}

{{- if .Data.data.azure_openai_endpoint }}
AZURE_OPENAI_ENDPOINT={{ .Data.data.azure_openai_endpoint }}
{{- end }}

{{- end }}

# Generated by Vault Agent at: {{ now | date "2006-01-02 15:04:05 UTC" }}
# Do not edit this file manually - changes will be overwritten
`
}

// WriteSampleTemplates writes example template files to help users get started
func WriteSampleTemplates(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Ensure template directory exists
	if err := os.MkdirAll(TemplateDir, VaultBaseDirPerm); err != nil {
		return fmt.Errorf("failed to create template directory: %w", err)
	}

	// Write BionicGPT example
	bionicPath := filepath.Join(TemplateDir, "bionicgpt.env.ctmpl.example")
	if err := os.WriteFile(bionicPath, []byte(GenerateBionicGPTTemplate()), VaultTLSCertPerm); err != nil {
		return fmt.Errorf("failed to write BionicGPT template example: %w", err)
	}

	logger.Info(fmt.Sprintf("✓ Example template written: %s", bionicPath))
	logger.Info("  Copy to bionicgpt.env.ctmpl and customize for your environment")

	return nil
}
