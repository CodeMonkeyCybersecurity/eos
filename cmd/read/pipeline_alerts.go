// cmd/delphi/watch/alerts.go
package read

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/lib/pq"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Alert represents an alert record for display
type Alert struct {
	ID                 int64      `json:"id"`
	AgentID            string     `json:"agent_id"`
	RuleID             int        `json:"rule_id"`
	RuleLevel          int        `json:"rule_level"`
	RuleDesc           string     `json:"rule_desc"`
	IngestTimestamp    time.Time  `json:"ingest_timestamp"`
	State              string     `json:"state"`
	PromptSentAt       *time.Time `json:"prompt_sent_at"`
	ResponseReceivedAt *time.Time `json:"response_received_at"`
	AlertSentAt        *time.Time `json:"alert_sent_at"`
}

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
		return watchAlerts(rc.Ctx, logger, db, pipelineAlertsLimit, pipelineAlertsRefresh)
	}),
}

func init() {
	pipelineAlertsCmd.Flags().IntVarP(&pipelineAlertsLimit, "limit", "l", 10, "Number of recent alerts to display")
	pipelineAlertsCmd.Flags().IntVarP(&pipelineAlertsRefresh, "refresh", "r", 5, "Refresh interval in seconds")
	pipelineAlertsCmd.Flags().StringVarP(&pipelineAlertsDsn, "dsn", "d", "", "PostgreSQL connection string (defaults to AGENTS_PG_DSN env var)")
}

func watchAlerts(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit, refresh int) error {
	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Get database connection string from environment for listener
	connStr := os.Getenv("AGENTS_PG_DSN")
	if connStr == "" {
		return fmt.Errorf("AGENTS_PG_DSN environment variable required for notifications")
	}

	// Create a listener for PostgreSQL notifications
	listener := pq.NewListener(connStr, 10*time.Second, time.Minute, func(ev pq.ListenerEventType, err error) {
		if err != nil {
			logger.Error("PostgreSQL listener error", zap.Error(err))
		}
	})
	defer func() {
		if err := listener.Close(); err != nil {
			logger.Error(" Failed to close PostgreSQL listener", zap.Error(err))
		}
	}()

	// Listen for new alert notifications
	err := listener.Listen("new_alert")
	if err != nil {
		return fmt.Errorf("failed to listen for new_alert notifications: %w", err)
	}

	// Listen for alert response notifications
	err = listener.Listen("new_response")
	if err != nil {
		return fmt.Errorf("failed to listen for new_response notifications: %w", err)
	}

	// Listen for alert sent notifications
	err = listener.Listen("alert_sent")
	if err != nil {
		return fmt.Errorf("failed to listen for alert_sent notifications: %w", err)
	}

	logger.Info(" Listening for database notifications...")

	// Initial display
	displayAlerts(ctx, logger, db, limit)

	// Create ticker for periodic refresh
	ticker := time.NewTicker(time.Duration(refresh) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info(" Context cancelled, stopping alerts watch")
			return nil

		case sig := <-sigChan:
			logger.Info(" Received signal, stopping alerts watch", zap.String("signal", sig.String()))
			return nil

		case notification := <-listener.Notify:
			if notification != nil {
				logger.Debug("📬 Received database notification",
					zap.String("channel", notification.Channel),
					zap.String("payload", notification.Extra))

				// Refresh display on notification
				displayAlerts(ctx, logger, db, limit)
			}

		case <-ticker.C:
			// Periodic refresh
			displayAlerts(ctx, logger, db, limit)
		}
	}
}

func displayAlerts(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	fmt.Printf(" Delphi Alerts Monitor - Last %d alerts (Updated: %s)\n", limit, time.Now().Format("15:04:05"))
	fmt.Println(strings.Repeat("=", 120))

	// Query recent alerts
	query := `
		SELECT 
			id, agent_id, rule_id, rule_level, rule_desc,
			ingest_timestamp, state,
			prompt_sent_at, response_received_at, alert_sent_at
		FROM alerts 
		ORDER BY ingest_timestamp DESC 
		LIMIT $1`

	rows, err := db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Error("Failed to query alerts", zap.Error(err))
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logger.Error(" Failed to close rows", zap.Error(err))
		}
	}()

	// Print header
	fmt.Printf("%-6s %-12s %-8s %-6s %-10s %-20s %-12s %-10s %-10s %-10s\n",
		"ID", "Agent", "Rule ID", "Level", "State", "Ingested", "Prompted", "Response", "Sent", "Description")
	fmt.Println(strings.Repeat("-", 120))

	alerts := make([]Alert, 0, limit)
	for rows.Next() {
		var alert Alert
		var ruleDesc sql.NullString

		err := rows.Scan(
			&alert.ID, &alert.AgentID, &alert.RuleID, &alert.RuleLevel, &ruleDesc,
			&alert.IngestTimestamp, &alert.State,
			&alert.PromptSentAt, &alert.ResponseReceivedAt, &alert.AlertSentAt,
		)
		if err != nil {
			logger.Error("Failed to scan alert row", zap.Error(err))
			continue
		}

		if ruleDesc.Valid {
			alert.RuleDesc = ruleDesc.String
		}

		alerts = append(alerts, alert)
	}

	// Display alerts
	for _, alert := range alerts {
		// Format timestamps
		ingestedTime := alert.IngestTimestamp.Format("15:04:05")
		promptedTime := formatOptionalTime(alert.PromptSentAt)
		responseTime := formatOptionalTime(alert.ResponseReceivedAt)
		sentTime := formatOptionalTime(alert.AlertSentAt)

		// Truncate description if too long
		desc := alert.RuleDesc
		if len(desc) > 25 {
			desc = desc[:22] + "..."
		}

		// Color-code state
		stateColor := getStateColor(alert.State)

		fmt.Printf("%-6d %-12s %-8d %-6d %s%-10s\033[0m %-20s %-10s %-10s %-10s %s\n",
			alert.ID, alert.AgentID, alert.RuleID, alert.RuleLevel,
			stateColor, alert.State, ingestedTime, promptedTime, responseTime, sentTime, desc)
	}

	if len(alerts) == 0 {
		fmt.Println("No alerts found.")
	}

	fmt.Printf("\n Total alerts shown: %d | Press Ctrl+C to exit\n", len(alerts))
}

func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("15:04:05")
}

func getStateColor(state string) string {
	switch state {
	case "new":
		return "\033[33m" // Yellow
	case "summarized":
		return "\033[34m" // Blue
	case "sent":
		return "\033[32m" // Green
	case "failed":
		return "\033[31m" // Red
	case "archived":
		return "\033[90m" // Gray
	default:
		return ""
	}
}
