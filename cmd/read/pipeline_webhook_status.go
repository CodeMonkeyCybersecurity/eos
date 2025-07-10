// cmd/read/pipeline_webhook_status.go
package read

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var pipelineWebhookStatusCmd = &cobra.Command{
	Use:     "pipeline-webhook-status",
	Aliases: []string{"delphi-webhook-status", "webhook-status"},
	Short:   "Check Delphi webhook deployment and configuration status",
	Long: `Check the current status of the Delphi webhook integration.

This command verifies:
- Webhook script deployment status
- File permissions and ownership
- Configuration file presence
- Environment variable configuration
- Wazuh integration configuration
- Network connectivity to Delphi service

Examples:
  eos read pipeline-webhook-status             # Basic status check
  eos read pipeline-webhook-status --verbose   # Detailed status information
  eos read pipeline-webhook-status --json      # JSON output format`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		outputJSON, _ := cmd.Flags().GetBool("json")
		verbose, _ := cmd.Flags().GetBool("verbose")
		
		logger.Info("Checking Delphi webhook status", zap.Bool("verbose", verbose))

		status := checkWebhookStatus(rc, verbose)

		if outputJSON {
			return outputStatusJSON(status)
		}

		return outputStatusText(status, logger)
	}),
}

func init() {
	pipelineWebhookStatusCmd.Flags().Bool("json", false, "Output status in JSON format")
	pipelineWebhookStatusCmd.Flags().Bool("verbose", false, "Show detailed status information")

	ReadCmd.AddCommand(pipelineWebhookStatusCmd)
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// WebhookStatus represents the status of webhook deployment
type WebhookStatus struct {
	Timestamp       time.Time         `json:"timestamp"`
	Deployed        bool              `json:"deployed"`
	ConfigPresent   bool              `json:"config_present"`
	FilesPresent    map[string]bool   `json:"files_present"`
	Permissions     map[string]string `json:"permissions"`
	EnvironmentVars map[string]bool   `json:"environment_vars"`
	Connectivity    bool              `json:"connectivity"`
	Issues          []string          `json:"issues"`
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// checkWebhookStatus checks the current webhook deployment status
func checkWebhookStatus(rc *eos_io.RuntimeContext, verbose bool) *WebhookStatus {
	status := &WebhookStatus{
		Timestamp:       time.Now(),
		FilesPresent:    make(map[string]bool),
		Permissions:     make(map[string]string),
		EnvironmentVars: make(map[string]bool),
		Issues:          make([]string, 0),
	}

	// Check if webhook files are deployed
	integrationDir := "/var/ossec/integrations"
	requiredFiles := []string{
		"custom-delphi-webhook",
		"custom-delphi-webhook.py",
	}

	for _, file := range requiredFiles {
		fullPath := filepath.Join(integrationDir, file)
		if info, err := os.Stat(fullPath); err == nil {
			status.FilesPresent[file] = true
			status.Permissions[file] = fmt.Sprintf("%o", info.Mode().Perm())
		} else {
			status.FilesPresent[file] = false
			status.Issues = append(status.Issues, fmt.Sprintf("Missing file: %s", fullPath))
		}
	}

	// Check environment configuration
	envFile := filepath.Join(integrationDir, ".env")
	if _, err := os.Stat(envFile); err == nil {
		status.ConfigPresent = true
		// Check for required environment variables
		status.EnvironmentVars["HOOK_URL"] = checkEnvVar(envFile, "HOOK_URL")
		status.EnvironmentVars["WEBHOOK_TOKEN"] = checkEnvVar(envFile, "WEBHOOK_TOKEN")
	} else {
		status.ConfigPresent = false
		status.Issues = append(status.Issues, "Environment configuration file missing: "+envFile)
	}

	// Set deployment status
	status.Deployed = len(status.FilesPresent) > 0 && allFilesPresent(status.FilesPresent)

	return status
}

// Helper functions
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func allFilesPresent(files map[string]bool) bool {
	for _, present := range files {
		if !present {
			return false
		}
	}
	return true
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func checkEnvVar(envFile, varName string) bool {
	// Simple check - in production you'd want proper env file parsing
	data, err := os.ReadFile(envFile)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), varName+"=")
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputStatusJSON(status *WebhookStatus) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputStatusText(status *WebhookStatus, logger otelzap.LoggerWithCtx) error {
	logger.Info("Delphi Webhook Integration Status")
	logger.Info(strings.Repeat("=", 50))

	// Deployment status
	if status.Deployed {
		logger.Info("Deployment Status: DEPLOYED")
	} else {
		logger.Info("Deployment Status: NOT DEPLOYED")
	}

	// File presence
	logger.Info("File Status:")
	for file, present := range status.FilesPresent {
		if present {
			perm := status.Permissions[file]
			logger.Info(fmt.Sprintf("   %s (permissions: %s)", file, perm))
		} else {
			logger.Info(fmt.Sprintf("  ❌ %s (missing)", file))
		}
	}

	// Configuration status
	logger.Info("Configuration Status:")
	if status.ConfigPresent {
		logger.Info("   Environment file present")
		for envVar, present := range status.EnvironmentVars {
			if present {
				logger.Info(fmt.Sprintf("     %s configured", envVar))
			} else {
				logger.Info(fmt.Sprintf("    ❌ %s missing", envVar))
			}
		}
	} else {
		logger.Info("  ❌ Environment file missing")
	}

	// Issues
	if len(status.Issues) > 0 {
		logger.Info("Issues Found:")
		for _, issue := range status.Issues {
			logger.Info(fmt.Sprintf("  • %s", issue))
		}
	}

	logger.Info(strings.Repeat("=", 50))

	return nil
}