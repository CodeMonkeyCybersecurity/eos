// cmd/read/pipeline_webhook_status.go
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline/webhook"
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

		status := webhook.CheckWebhookStatus(rc, verbose)

		if outputJSON {
			return webhook.OutputStatusJSON(rc, status)
		}

		return webhook.OutputStatusText(rc, status)
	}),
}

func init() {
	pipelineWebhookStatusCmd.Flags().Bool("json", false, "Output status in JSON format")
	pipelineWebhookStatusCmd.Flags().Bool("verbose", false, "Show detailed status information")

	ReadCmd.AddCommand(pipelineWebhookStatusCmd)
}
// All helper functions have been migrated to pkg/pipeline/webhook/