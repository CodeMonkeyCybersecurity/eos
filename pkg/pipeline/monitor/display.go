package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DisplayAll shows both alerts and agents in a combined view
// Migrated from cmd/read/pipeline.go displayAll
func DisplayAll(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, alertLimit, agentLimit int) {
	// ASSESS - Prepare display update
	logger.Debug("Assessing display update",
		zap.Int("alert_limit", alertLimit),
		zap.Int("agent_limit", agentLimit))

	// INTERVENE - Clear screen and display data
	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	currentTime := time.Now().Format("15:04:05")
	fmt.Printf("🔍 Delphi Real-Time Monitor (Updated: %s)\n", currentTime)
	fmt.Println(strings.Repeat("=", 120))

	// Display recent alerts section
	fmt.Printf("\n🚨 Recent Alerts (Last %d)\n", alertLimit)
	fmt.Println(strings.Repeat("-", 80))

	DisplayRecentAlerts(ctx, logger, db, alertLimit)

	// Display agents section
	fmt.Printf("\n🤖 Active Agents (Top %d)\n", agentLimit)
	fmt.Println(strings.Repeat("-", 80))

	DisplayRecentAgents(ctx, logger, db, agentLimit)

	// Display summary statistics
	fmt.Println(strings.Repeat("=", 120))
	DisplaySummaryStats(ctx, db)
	fmt.Println("\n⏹️  Press Ctrl+C to exit")

	// EVALUATE - Log successful display update
	logger.Debug("Display updated successfully")
}

// DisplayRecentAlerts shows recent alerts from the database
// Migrated from cmd/read/pipeline.go displayRecentAlerts
func DisplayRecentAlerts(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
	// ASSESS - Prepare alerts query
	logger.Debug("Assessing recent alerts display",
		zap.Int("limit", limit))

	query := `
		SELECT 
			id, agent_id, rule_level, rule_desc, state,
			ingest_timestamp
		FROM alerts 
		ORDER BY ingest_timestamp DESC 
		LIMIT $1`

	// INTERVENE - Execute query and display results
	rows, err := db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Error("Failed to query recent alerts", zap.Error(err))
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logger.Error("Failed to close rows", zap.Error(err))
		}
	}()

	fmt.Printf("%-6s %-12s %-5s %-10s %-8s %s\n",
		"ID", "Agent", "Level", "State", "Time", "Description")

	count := 0
	for rows.Next() {
		var id int64
		var agentID, ruleDesc, state string
		var ruleLevel int
		var ingestTime time.Time

		err := rows.Scan(&id, &agentID, &ruleLevel, &ruleDesc, &state, &ingestTime)
		if err != nil {
			logger.Error("Failed to scan alert row", zap.Error(err))
			continue
		}

		// Truncate description
		desc := ruleDesc
		if len(desc) > 35 {
			desc = desc[:32] + "..."
		}

		// Format time as relative
		timeStr := FormatRelativeTime(ingestTime)
		stateColor := GetStateColor(state)

		fmt.Printf("%-6d %-12s %-5d %s%-10s\033[0m %-8s %s\n",
			id, agentID, ruleLevel, stateColor, state, timeStr, desc)
		count++
	}

	// EVALUATE - Log results
	if count == 0 {
		fmt.Println("No recent alerts")
		logger.Debug("No recent alerts found")
	} else {
		logger.Debug("Recent alerts displayed successfully",
			zap.Int("count", count))
	}
}

// DisplayRecentAgents shows recent agent activity
// Migrated from cmd/read/pipeline.go displayRecentAgents
func DisplayRecentAgents(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
	// ASSESS - Prepare agents query
	logger.Debug("Assessing recent agents display",
		zap.Int("limit", limit))

	query := `
		SELECT 
			id, name, ip, status_text, last_seen
		FROM agents 
		WHERE status_text = 'active' OR last_seen > NOW() - INTERVAL '1 hour'
		ORDER BY 
			CASE 
				WHEN last_seen IS NOT NULL THEN last_seen 
				ELSE NOW() - INTERVAL '1 year'
			END DESC
		LIMIT $1`

	// INTERVENE - Execute query and display results
	rows, err := db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Error("Failed to query recent agents", zap.Error(err))
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logger.Error("Failed to close rows", zap.Error(err))
		}
	}()

	fmt.Printf("%-8s %-15s %-15s %-12s %s\n",
		"ID", "Name", "IP", "Status", "Last Seen")

	count := 0
	for rows.Next() {
		var id string
		var name, ip, status sql.NullString
		var lastSeen sql.NullTime

		err := rows.Scan(&id, &name, &ip, &status, &lastSeen)
		if err != nil {
			logger.Error("Failed to scan agent row", zap.Error(err))
			continue
		}

		nameStr := "-"
		if name.Valid {
			nameStr = name.String
			if len(nameStr) > 15 {
				nameStr = nameStr[:12] + "..."
			}
		}

		ipStr := "-"
		if ip.Valid {
			ipStr = ip.String
		}

		statusStr := "-"
		statusColor := "\033[90m"
		if status.Valid {
			statusStr = status.String
			statusColor = GetAgentStatusColor(&statusStr)
		}

		lastSeenStr := "-"
		if lastSeen.Valid {
			lastSeenStr = FormatRelativeTime(lastSeen.Time)
		}

		fmt.Printf("%-8s %-15s %-15s %s%-12s\033[0m %s\n",
			id, nameStr, ipStr, statusColor, statusStr, lastSeenStr)
		count++
	}

	// EVALUATE - Log results
	if count == 0 {
		fmt.Println("No active agents")
		logger.Debug("No active agents found")
	} else {
		logger.Debug("Recent agents displayed successfully",
			zap.Int("count", count))
	}
}