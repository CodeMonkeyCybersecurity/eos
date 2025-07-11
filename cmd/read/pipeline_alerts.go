// cmd/delphi/watch/alerts.go
package read

import (
	"database/sql"
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline/alerts"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	pipelineAlertsLimit   int
	pipelineAlertsRefresh int
	pipelineAlertsDsn     string
)

// pipelineAlertsCmd watches alerts table for real-time changes
var pipelineAlertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Watch alerts table for real-time changes",
	Long: `Watch the alerts table for real-time security alert updates.

This command displays alerts in a spreadsheet-like format and updates automatically
when new alerts arrive or existing alerts change state.

The display shows:
- Alert ID, Agent ID, Rule ID/Level
- Rule description
- Processing state (new → summarized → sent)
- Timestamps for each processing stage

Example:
  eos read pipeline alerts --limit 20 --refresh 2`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting alerts watch",
			zap.Int("limit", pipelineAlertsLimit),
			zap.Int("refresh_seconds", pipelineAlertsRefresh))

		// Get database DSN
		if pipelineAlertsDsn == "" {
			pipelineAlertsDsn = os.Getenv("AGENTS_PG_DSN")
			if pipelineAlertsDsn == "" {
				return fmt.Errorf("database DSN not provided. Set AGENTS_PG_DSN environment variable or use --dsn flag")
			}
		}

		// Connect to database
		db, err := sql.Open("postgres", pipelineAlertsDsn)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer func() {
			if err := db.Close(); err != nil {
				logger.Error(" Failed to close database connection", zap.Error(err))
			}
		}()

		// Test connection
		if err := db.Ping(); err != nil {
			return fmt.Errorf("failed to ping database: %w", err)
		}

		logger.Info(" Connected to PostgreSQL database")

		// Start watching
		return alerts.WatchAlerts(rc.Ctx, logger, db, pipelineAlertsLimit, pipelineAlertsRefresh)
	}),
}

func init() {
	pipelineAlertsCmd.Flags().IntVarP(&pipelineAlertsLimit, "limit", "l", 10, "Number of recent alerts to display")
	pipelineAlertsCmd.Flags().IntVarP(&pipelineAlertsRefresh, "refresh", "r", 5, "Refresh interval in seconds")
	pipelineAlertsCmd.Flags().StringVarP(&pipelineAlertsDsn, "dsn", "d", "", "PostgreSQL connection string (defaults to AGENTS_PG_DSN env var)")
}
// All helper functions have been migrated to pkg/pipeline/alerts/
