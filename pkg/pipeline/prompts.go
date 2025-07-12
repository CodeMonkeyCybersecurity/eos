package pipeline

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	stringutils "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/strings"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreatePromptTemplate creates a basic template for a new prompt
// Migrated from cmd/create/pipeline_prompts.go createPromptTemplate
func CreatePromptTemplate(rc *eos_io.RuntimeContext, name, description string) string {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check inputs
	logger.Debug("Assessing prompt template requirements",
		zap.String("name", name),
		zap.String("description", description))

	if description == "" {
		description = "Custom system prompt for Delphi AI processing"
	}

	// INTERVENE - Create template
	logger.Debug("Creating prompt template")

	// Convert name to title case
	titleName := stringutils.TitleCase(rc, strings.ReplaceAll(name, "-", " "))

	template := fmt.Sprintf(`# %s

## Description
%s

## Instructions
You are an AI assistant analyzing security alerts and incidents. Your role is to:

1. Analyze the provided security data
2. Identify potential threats and risks
3. Provide clear, actionable recommendations
4. Communicate findings in a user-friendly manner

## Response Format
- Be concise but comprehensive
- Use clear, non-technical language when possible
- Highlight critical information
- Provide specific next steps

## Context
This prompt is used by the Delphi alerting pipeline to process security events and generate user-friendly notifications.

---
Please provide your analysis based on the security data provided.
`, titleName, description)

	// EVALUATE - Return template
	logger.Debug("Prompt template created",
		zap.String("title", titleName),
		zap.Int("template_length", len(template)))

	return template
}

// IsPromptsDirectoryMounted checks if the prompts directory is mounted to Delphi containers
// This is a placeholder for future implementation
func IsPromptsDirectoryMounted(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Log the check
	logger.Debug("Checking if prompts directory is mounted")

	// TODO: Implement actual check
	// This would involve:
	// 1. Checking Docker/Podman container mounts
	// 2. Verifying the /srv/eos/system-prompts directory is mounted
	// 3. Checking if Delphi services can access the prompts

	// EVALUATE - Return placeholder
	logger.Warn("Prompts directory mount check not yet implemented")
	return false, fmt.Errorf("prompts directory mount check not yet implemented")
}
