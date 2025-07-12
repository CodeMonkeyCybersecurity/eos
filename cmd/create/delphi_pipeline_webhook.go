// cmd/create/delphi_webhook.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// delphiWebhookCmd deploys Delphi webhook integration scripts to Wazuh
var delphiWebhookCmd = &cobra.Command{
	Use:   "delphi-webhook",
	Short: "Deploy Delphi webhook integration scripts to Wazuh",
	Long: `Deploy the custom Delphi webhook integration scripts to Wazuh server.

This command deploys two files to /var/ossec/integrations/:
- custom-delphi-webhook (bash wrapper script)
- custom-delphi-webhook.py (Python webhook implementation)

The scripts are deployed with proper ownership (root:wazuh) and permissions (0750).

After deployment, you need to:
1. Configure /var/ossec/etc/ossec.conf with the webhook integration
2. Restart Wazuh manager to activate the integration

Examples:
  eos create delphi-webhook                       # Deploy to default location
  eos create delphi-webhook --target-dir /custom/path # Deploy to custom location
  eos create delphi-webhook --dry-run             # Preview deployment`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		targetDir, _ := cmd.Flags().GetString("target-dir")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		forceInstall, _ := cmd.Flags().GetBool("force")

		logger.Info("Starting Delphi webhook deployment",
			zap.String("target_dir", targetDir),
			zap.Bool("dry_run", dryRun),
			zap.Bool("force", forceInstall))

		return delphi.DeployDelphiWebhook(rc.Ctx, logger, targetDir, dryRun, forceInstall)
	}),
}

var pipelineWebhookCmd = &cobra.Command{
	Use:     "pipeline-webhook",
	Aliases: []string{"delphi-webhook", "wazuh-webhook"},
	Short:   "Create and deploy Delphi webhook integration with Wazuh",
	Long: `Create and deploy the Delphi webhook integration for receiving Wazuh security alerts.

This command creates and installs the custom Delphi webhook that integrates
with Wazuh security monitoring to forward alerts to the Delphi pipeline.

Files deployed:
- custom-delphi-webhook: Bash wrapper script for Wazuh integration
- custom-delphi-webhook.py: Python webhook implementation

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

		logger.Info("Creating Delphi webhook integration",
			zap.String("target_dir", targetDir),
			zap.Bool("dry_run", dryRun),
			zap.Bool("force", forceInstall))

		return delphi.DeployDelphiWebhook(rc.Ctx, logger, targetDir, dryRun, forceInstall)
	}),
}

func init() {
	// Register webhook commands with CreateCmd
	CreateCmd.AddCommand(delphiWebhookCmd)
	CreateCmd.AddCommand(pipelineWebhookCmd)

	// Set up flags for delphiWebhookCmd
	delphiWebhookCmd.Flags().StringP("target-dir", "t", "/var/ossec/integrations", "Target directory for webhook scripts")
	delphiWebhookCmd.Flags().BoolP("dry-run", "n", false, "Show what would be done without making changes")
	delphiWebhookCmd.Flags().BoolP("force", "f", false, "Overwrite existing files")

	// Set up flags for pipelineWebhookCmd
	pipelineWebhookCmd.Flags().String("target-dir", "/var/ossec/integrations", "Target directory for webhook scripts")
	pipelineWebhookCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	pipelineWebhookCmd.Flags().Bool("force", false, "Overwrite existing files")
}
