// cmd/update/delphi_notification_channels.go
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi_channels"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var delphiNotificationChannelsCmd = &cobra.Command{
	Use:     "delphi-notification-channels",
	Aliases: []string{"fix-delphi-channels", "delphi-channels"},
	Short:   "Standardize PostgreSQL notification channels for Delphi workers",
	Long: `Standardizes PostgreSQL notification channels across all Delphi workers to ensure
consistent communication in the pipeline.

This command:
- Updates LISTEN_CHANNEL and NOTIFY_CHANNEL variable definitions
- Fixes pg_notify() function calls to use correct channels
- Updates LISTEN statements in SQL code
- Creates backups of modified files (unless disabled)
- Validates the entire notification flow

Standard notification flow:
  new_alert       → delphi-listener → delphi-agent-enricher
  agent_enriched  → delphi-agent-enricher → llm-worker  
  new_response    → llm-worker → email-structurer
  alert_structured → email-structurer → email-formatter
  alert_formatted → email-formatter → email-sender
  alert_sent      → email-sender → final (archive/metrics)

Examples:
  eos update delphi-notification-channels
  eos update delphi-notification-channels --analyze
  eos update delphi-notification-channels --workers-dir /custom/path
  eos update delphi-notification-channels --dry-run
  eos update delphi-notification-channels --json
  eos update delphi-notification-channels --no-backups`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		workersDir, _ := cmd.Flags().GetString("workers-dir")
		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		createBackups, _ := cmd.Flags().GetBool("backups")
		analyze, _ := cmd.Flags().GetBool("analyze")

		logger.Info("Starting notification channel standardization",
			zap.String("workers_dir", workersDir),
			zap.Bool("dry_run", dryRun),
			zap.Bool("analyze_only", analyze),
			zap.Bool("create_backups", createBackups))

		// Create configuration
		config := &delphi_channels.ChannelStandardizerConfig{
			WorkersDir:      workersDir,
			CreateBackups:   createBackups,
			DryRun:          dryRun,
			ExcludePatterns: []string{"*.bak", "*.old", "__pycache__", ".git"},
		}

		// Create standardizer
		standardizer := delphi_channels.NewChannelStandardizer(config)

		if analyze {
			return pipeline.RunAnalysis(standardizer, outputJSON, logger)
		} else {
			return pipeline.RunStandardization(standardizer, outputJSON, dryRun, logger)
		}
	}),
}

func init() {
	delphiNotificationChannelsCmd.Flags().String("workers-dir", "/opt/stackstorm/packs/delphi/actions/python_workers",
		"Directory containing Delphi worker Python files")
	delphiNotificationChannelsCmd.Flags().Bool("json", false, "Output results in JSON format")
	delphiNotificationChannelsCmd.Flags().Bool("dry-run", false, "Show what would be changed without making modifications")
	delphiNotificationChannelsCmd.Flags().Bool("backups", true, "Create backup files before modification")
	delphiNotificationChannelsCmd.Flags().Bool("analyze", false, "Analyze current configuration without making changes")

	UpdateCmd.AddCommand(delphiNotificationChannelsCmd)
}
