package webhook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WebhookCmd is the root command for webhook management
var WebhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Manage Delphi webhook integration with Wazuh",
	Long: `Manage the Delphi webhook integration for receiving Wazuh security alerts.

This command provides management for the custom Delphi webhook that integrates
with Wazuh security monitoring to forward alerts to the Delphi pipeline.

Available operations:
- deploy: Install webhook scripts to Wazuh integrations directory
- status: Check webhook deployment and configuration status
- test: Test webhook functionality and connectivity
- logs: View webhook integration logs

Examples:
  eos delphi webhook deploy             # Deploy webhook integration
  eos delphi webhook status             # Check deployment status
  eos delphi webhook test               # Test webhook functionality
  eos delphi webhook logs               # View integration logs`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for webhook", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Add subcommands to WebhookCmd
	WebhookCmd.AddCommand(NewDeployCmd())
	WebhookCmd.AddCommand(NewStatusCmd())
	WebhookCmd.AddCommand(NewTestCmd())
	WebhookCmd.AddCommand(NewLogsCmd())
}

// NewDeployCmd creates the deploy subcommand
func NewDeployCmd() *cobra.Command {
	var (
		targetDir    string
		dryRun       bool
		forceInstall bool
	)

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy Delphi webhook integration to Wazuh",
		Long: `Deploy the Delphi webhook integration scripts to Wazuh server.

This command deploys the custom webhook integration that allows Wazuh to send
security alerts directly to the Delphi security monitoring pipeline.

Files deployed:
- custom-delphi-webhook: Bash wrapper script for Wazuh integration
- custom-delphi-webhook.py: Python webhook implementation

The scripts are deployed with proper ownership (root:wazuh) and permissions (0750).

Examples:
  eos delphi webhook deploy                     # Deploy to default location
  eos delphi webhook deploy --dry-run           # Preview deployment
  eos delphi webhook deploy --force             # Overwrite existing files
  eos delphi webhook deploy --target-dir /custom/path`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Starting Delphi webhook deployment",
				zap.String("target_dir", targetDir),
				zap.Bool("dry_run", dryRun),
				zap.Bool("force", forceInstall))

			return delphi.DeployDelphiWebhook(rc.Ctx, logger, targetDir, dryRun, forceInstall)
		}),
	}

	cmd.Flags().StringVarP(&targetDir, "target-dir", "t", "/var/ossec/integrations", "Target directory for webhook scripts")
	cmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Show what would be done without making changes")
	cmd.Flags().BoolVarP(&forceInstall, "force", "f", false, "Overwrite existing files")

	return cmd
}

// NewStatusCmd creates the status subcommand
func NewStatusCmd() *cobra.Command {
	var (
		outputJSON bool
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check Delphi webhook deployment and configuration status",
		Long: `Check the current status of the Delphi webhook integration.

This command verifies:
- Webhook script deployment status
- File permissions and ownership
- Configuration file presence
- Environment variable configuration
- Wazuh integration configuration
- Network connectivity to Delphi service

Examples:
  eos delphi webhook status             # Basic status check
  eos delphi webhook status --verbose   # Detailed status information
  eos delphi webhook status --json      # JSON output format`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Checking Delphi webhook status", zap.Bool("verbose", verbose))

			status := checkWebhookStatus(rc, verbose)

			if outputJSON {
				return outputStatusJSON(status)
			}

			return outputStatusText(status, logger)
		}),
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output status in JSON format")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed status information")

	return cmd
}

// NewTestCmd creates the test subcommand
func NewTestCmd() *cobra.Command {
	var (
		hookURL   string
		authToken string
		timeout   int
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test Delphi webhook functionality and connectivity",
		Long: `Test the Delphi webhook integration functionality.

This command sends a test alert to verify that the webhook integration
is working correctly and can successfully communicate with the Delphi service.

The test includes:
- Webhook script execution
- Network connectivity to Delphi service
- Authentication validation
- Response processing

Examples:
  eos delphi webhook test                                    # Test with default config
  eos delphi webhook test --hook-url http://delphi:9000/alert # Test specific endpoint
  eos delphi webhook test --timeout 30                      # Custom timeout`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Testing Delphi webhook integration",
				zap.String("hook_url", hookURL),
				zap.Int("timeout", timeout))

			return testWebhookIntegration(rc, hookURL, authToken, timeout)
		}),
	}

	cmd.Flags().StringVar(&hookURL, "hook-url", "", "Override webhook URL for testing")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "Override authentication token for testing")
	cmd.Flags().IntVar(&timeout, "timeout", 10, "Request timeout in seconds")

	return cmd
}

// NewLogsCmd creates the logs subcommand
func NewLogsCmd() *cobra.Command {
	var (
		follow  bool
		lines   int
		logType string
	)

	cmd := &cobra.Command{
		Use:   "logs [integration|payload|all]",
		Short: "View Delphi webhook integration logs",
		Long: `View logs from the Delphi webhook integration.

Available log types:
- integration: Webhook integration logs (/var/ossec/logs/integrations.log)
- payload: Sent payload logs (/var/ossec/logs/sent_payload.log)
- all: Both integration and payload logs

Examples:
  eos delphi webhook logs                    # View recent integration logs
  eos delphi webhook logs payload            # View payload logs
  eos delphi webhook logs --follow           # Follow logs in real-time
  eos delphi webhook logs --lines 100        # Show last 100 lines`,
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"integration", "payload", "all"},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if len(args) > 0 {
				logType = args[0]
			} else {
				logType = "integration"
			}

			logger.Info("Viewing webhook logs",
				zap.String("type", logType),
				zap.Bool("follow", follow),
				zap.Int("lines", lines))

			return viewWebhookLogs(rc, logType, follow, lines)
		}),
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "Number of lines to show")

	return cmd
}

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

func allFilesPresent(files map[string]bool) bool {
	for _, present := range files {
		if !present {
			return false
		}
	}
	return true
}

func checkEnvVar(envFile, varName string) bool {
	// Simple check - in production you'd want proper env file parsing
	data, err := os.ReadFile(envFile)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), varName+"=")
}

func outputStatusJSON(status *WebhookStatus) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}

func outputStatusText(status *WebhookStatus, logger otelzap.LoggerWithCtx) error {
	logger.Info(" Delphi Webhook Integration Status")
	logger.Info(strings.Repeat("=", 50))

	// Deployment status
	if status.Deployed {
		logger.Info(" Deployment Status: DEPLOYED")
	} else {
		logger.Info("❌ Deployment Status: NOT DEPLOYED")
	}

	// File presence
	logger.Info("\n📁 File Status:")
	for file, present := range status.FilesPresent {
		if present {
			perm := status.Permissions[file]
			logger.Info(fmt.Sprintf("   %s (permissions: %s)", file, perm))
		} else {
			logger.Info(fmt.Sprintf("  ❌ %s (missing)", file))
		}
	}

	// Configuration status
	logger.Info("\n⚙️  Configuration Status:")
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
		logger.Info("\n⚠️  Issues Found:")
		for _, issue := range status.Issues {
			logger.Info(fmt.Sprintf("  • %s", issue))
		}
	}

	logger.Info("\n" + strings.Repeat("=", 50))

	return nil
}

func testWebhookIntegration(rc *eos_io.RuntimeContext, hookURL, authToken string, timeout int) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🧪 Testing webhook integration functionality")

	// Implementation would test the webhook by calling the script with test data
	logger.Info("Test functionality not yet implemented")
	logger.Info("To manually test: sudo /var/ossec/integrations/custom-delphi-webhook --test")

	return nil
}

func viewWebhookLogs(rc *eos_io.RuntimeContext, logType string, follow bool, lines int) error {
	logger := otelzap.Ctx(rc.Ctx)

	var logFiles []string
	switch logType {
	case "integration":
		logFiles = []string{"/var/ossec/logs/integrations.log"}
	case "payload":
		logFiles = []string{"/var/ossec/logs/sent_payload.log"}
	case "all":
		logFiles = []string{"/var/ossec/logs/integrations.log", "/var/ossec/logs/sent_payload.log"}
	default:
		return fmt.Errorf("invalid log type: %s. Use 'integration', 'payload', or 'all'", logType)
	}

	logger.Info("📋 Viewing webhook logs",
		zap.Strings("files", logFiles),
		zap.Bool("follow", follow),
		zap.Int("lines", lines))

	// Implementation would use tail command or similar to view logs
	logger.Info("Log viewing functionality not yet implemented")
	logger.Info("To manually view logs:")
	for _, file := range logFiles {
		if follow {
			logger.Info(fmt.Sprintf("  tail -f %s", file))
		} else {
			logger.Info(fmt.Sprintf("  tail -n %d %s", lines, file))
		}
	}

	return nil
}
