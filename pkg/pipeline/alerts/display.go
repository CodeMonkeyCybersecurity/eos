package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DisplayAlerts displays alerts in a formatted table
// Migrated from cmd/read/pipeline_alerts.go displayAlerts
func DisplayAlerts(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
	// ASSESS - Prepare alerts display
	logger.Debug("🎨 Assessing alerts display",
		zap.Int("limit", limit))

	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	fmt.Printf("🔔 Delphi Alerts Monitor - Last %d alerts (Updated: %s)\n", limit, time.Now().Format("15:04:05"))
	fmt.Println(strings.Repeat("=", 120))

	// INTERVENE - Query and display recent alerts
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
			logger.Error("🔌 Failed to close rows", zap.Error(err))
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
		promptedTime := FormatOptionalTime(alert.PromptSentAt)
		responseTime := FormatOptionalTime(alert.ResponseReceivedAt)
		sentTime := FormatOptionalTime(alert.AlertSentAt)

		// Truncate description if too long
		desc := alert.RuleDesc
		if len(desc) > 25 {
			desc = desc[:22] + "..."
		}

		// Color-code state
		stateColor := GetStateColor(alert.State)

		fmt.Printf("%-6d %-12s %-8d %-6d %s%-10s\033[0m %-20s %-10s %-10s %-10s %s\n",
			alert.ID, alert.AgentID, alert.RuleID, alert.RuleLevel,
			stateColor, alert.State, ingestedTime, promptedTime, responseTime, sentTime, desc)
	}

	if len(alerts) == 0 {
		fmt.Println("No alerts found.")
	}

	// EVALUATE - Display summary
	fmt.Printf("\n📊 Total alerts shown: %d | Press Ctrl+C to exit\n", len(alerts))

	logger.Debug("Alerts display completed successfully",
		zap.Int("alerts_shown", len(alerts)))
}
