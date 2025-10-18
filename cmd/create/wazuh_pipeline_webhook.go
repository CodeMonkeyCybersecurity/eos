// cmd/create/wazuh_webhook.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// wazuhWebhookCmd deploys Wazuh webhook integration scripts to Wazuh
var wazuhWebhookCmd = &cobra.Command{
	Use:   "wazuh-webhook",
	Short: "Deploy Wazuh webhook integration scripts to Wazuh",
	Long: `Deploy the custom Wazuh webhook integration scripts to Wazuh server.

This command deploys two files to /var/ossec/integrations/:
- custom-wazuh-webhook (bash wrapper script)
- custom-wazuh-webhook.py (Python webhook implementation)

The scripts are deployed with proper ownership (root:wazuh) and permissions (0750).

After deployment, you need to:
1. Configure /var/ossec/etc/ossec.conf with the webhook integration
2. Restart Wazuh manager to activate the integration

Examples:
  eos create wazuh-webhook                       # Deploy to default location
  eos create wazuh-webhook --target-dir /custom/path # Deploy to custom location
  eos create wazuh-webhook --dry-run             # Preview deployment`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		targetDir, _ := cmd.Flags().GetString("target-dir")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		forceInstall, _ := cmd.Flags().GetBool("force")

		logger.Info("Starting Wazuh webhook deployment",
			zap.String("target_dir", targetDir),
			zap.Bool("dry_run", dryRun),
			zap.Bool("force", forceInstall))

		return wazuh.DeployWazuhWebhook(rc.Ctx, logger, targetDir, dryRun, forceInstall)
	}),
}

var pipelineWebhookCmd = &cobra.Command{
	Use:     "pipeline-webhook",
	Aliases: []string{"wazuh-webhook", "wazuh-webhook"},
	Short:   "Create and deploy Wazuh webhook integration with Wazuh",
	Long: `Create and deploy the Wazuh webhook integration for receiving Wazuh security alerts.

This command creates and installs the custom Wazuh webhook that integrates
with Wazuh security monitoring to forward alerts to the Wazuh pipeline.

Files deployed:
- custom-wazuh-webhook: Bash wrapper script for Wazuh integration
- custom-wazuh-webhook.py: Python webhook implementation

The scripts are deployed with proper ownership (root:wazuh) and permissions (0750).

Examples:
  eos create pipeline-webhook                     # Deploy to default location
  eos create pipeline-webhook --dry-run           # Preview deployment
  eos create pipeline-webhook --force             # Overwrite existing files
  eos create pipeline-webhook --target-dir /custom/path`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		targetDir, _ := cmd.Flags().GetString("target-dir")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		forceInstall, _ := cmd.Flags().GetBool("force")

		logger.Info("Creating Wazuh webhook integration",
			zap.String("target_dir", targetDir),
			zap.Bool("dry_run", dryRun),
			zap.Bool("force", forceInstall))

		return wazuh.DeployWazuhWebhook(rc.Ctx, logger, targetDir, dryRun, forceInstall)
	}),
}

func init() {
	// Register webhook commands with CreateCmd
	CreateCmd.AddCommand(wazuhWebhookCmd)
	CreateCmd.AddCommand(pipelineWebhookCmd)

	// Set up flags for wazuhWebhookCmd
	wazuhWebhookCmd.Flags().StringP("target-dir", "t", "/var/ossec/integrations", "Target directory for webhook scripts")
	wazuhWebhookCmd.Flags().BoolP("dry-run", "n", false, "Show what would be done without making changes")
	wazuhWebhookCmd.Flags().BoolP("force", "f", false, "Overwrite existing files")

	// Set up flags for pipelineWebhookCmd
	pipelineWebhookCmd.Flags().String("target-dir", "/var/ossec/integrations", "Target directory for webhook scripts")
	pipelineWebhookCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	pipelineWebhookCmd.Flags().Bool("force", false, "Overwrite existing files")
}
