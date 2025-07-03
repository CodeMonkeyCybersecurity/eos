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

func init() {
	CreateCmd.AddCommand(NewDelphiWebhookCmd())
}

// NewDelphiWebhookCmd creates the delphi-webhook command
func NewDelphiWebhookCmd() *cobra.Command {
	var (
		targetDir    string
		dryRun       bool
		forceInstall bool
	)

	cmd := &cobra.Command{
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

Example:
  eos create delphi-webhook
  eos create delphi-webhook --target-dir /custom/path --dry-run`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Starting Delphi webhook deployment",
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
