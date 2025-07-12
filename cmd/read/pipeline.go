// cmd/delphi/watch/all.go
package read

import (
	"database/sql"
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline/monitor"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	pipelineAllAlertLimit int
	pipelineAllAgentLimit int
	pipelineAllRefresh    int
	pipelineAllDsn        string
)

// pipelineAllCmd watches both alerts and agents tables simultaneously
var pipelineAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Watch both alerts and agents tables simultaneously",
	Long: `Watch both alerts and agents tables for real-time changes in a combined view.

This command displays both alerts and agents in separate sections that update
automatically when changes occur in either table.

The combined view shows:
- Recent alerts with their processing status
- Active agents with their current status
- Real-time updates via PostgreSQL LISTEN/NOTIFY

Example:
  eos read pipeline all --alert-limit 5 --agent-limit 10 --refresh 3`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting combined alerts & agents watch",
			zap.Int("alert_limit", pipelineAllAlertLimit),
			zap.Int("agent_limit", pipelineAllAgentLimit),
			zap.Int("refresh_seconds", pipelineAllRefresh))

		// Get database DSN
		if pipelineAllDsn == "" {
			pipelineAllDsn = os.Getenv("AGENTS_PG_DSN")
			if pipelineAllDsn == "" {
				return fmt.Errorf("database DSN not provided. Set AGENTS_PG_DSN environment variable or use --dsn flag")
			}
		}

		// Connect to database
		db, err := sql.Open("postgres", pipelineAllDsn)
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
		return monitor.WatchAll(rc.Ctx, logger, db, pipelineAllAlertLimit, pipelineAllAgentLimit, pipelineAllRefresh)
	}),
}

func init() {
	pipelineAllCmd.Flags().IntVar(&pipelineAllAlertLimit, "alert-limit", 5, "Number of recent alerts to display")
	pipelineAllCmd.Flags().IntVar(&pipelineAllAgentLimit, "agent-limit", 8, "Number of agents to display")
	pipelineAllCmd.Flags().IntVarP(&pipelineAllRefresh, "refresh", "r", 5, "Refresh interval in seconds")
	pipelineAllCmd.Flags().StringVarP(&pipelineAllDsn, "dsn", "d", "", "PostgreSQL connection string (defaults to AGENTS_PG_DSN env var)")
}

// All helper functions have been migrated to pkg/pipeline/monitor/
