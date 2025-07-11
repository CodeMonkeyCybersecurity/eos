package monitor

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DisplaySummaryStats shows summary statistics for alerts and agents
// Migrated from cmd/read/pipeline.go displaySummaryStats
func DisplaySummaryStats(ctx context.Context, db *sql.DB) {
	logger := otelzap.Ctx(ctx)

	// ASSESS - Prepare statistics collection
	logger.Debug("Assessing summary statistics collection")

	// Get alert stats
	var alertStats struct {
		total   int
		new     int
		sent    int
		failed  int
		last24h int
	}

	// INTERVENE - Collect alert statistics
	logger.Debug("Collecting alert statistics")

	// Total alerts
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts").Scan(&alertStats.total); err != nil {
		logger.Error("Failed to get total alerts count", zap.Error(err))
		alertStats.total = 0
	}

	// Alerts by state
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE state = 'new'").Scan(&alertStats.new); err != nil {
		logger.Error("Failed to get new alerts count", zap.Error(err))
		alertStats.new = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE state = 'sent'").Scan(&alertStats.sent); err != nil {
		logger.Error("Failed to get sent alerts count", zap.Error(err))
		alertStats.sent = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE state = 'failed'").Scan(&alertStats.failed); err != nil {
		logger.Error("Failed to get failed alerts count", zap.Error(err))
		alertStats.failed = 0
	}

	// Alerts in last 24h
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE ingest_timestamp > NOW() - INTERVAL '24 hours'").Scan(&alertStats.last24h); err != nil {
		logger.Error("Failed to get 24h alerts count", zap.Error(err))
		alertStats.last24h = 0
	}

	// Get agent stats
	var agentStats struct {
		total        int
		active       int
		disconnected int
		lastHour     int
	}

	logger.Debug("Collecting agent statistics")

	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents").Scan(&agentStats.total); err != nil {
		logger.Error("Failed to get total agents count", zap.Error(err))
		agentStats.total = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE status_text = 'active'").Scan(&agentStats.active); err != nil {
		logger.Error("Failed to get active agents count", zap.Error(err))
		agentStats.active = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE status_text = 'disconnected'").Scan(&agentStats.disconnected); err != nil {
		logger.Error("Failed to get disconnected agents count", zap.Error(err))
		agentStats.disconnected = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE last_seen > NOW() - INTERVAL '1 hour'").Scan(&agentStats.lastHour); err != nil {
		logger.Error("Failed to get recent agents count", zap.Error(err))
		agentStats.lastHour = 0
	}

	// EVALUATE - Display statistics
	fmt.Printf("📊 Alerts: %d total | %d new | %d sent | %d failed | %d (24h) | "+
		"Agents: %d total | %d active | %d disconnected | %d (1h)",
		alertStats.total, alertStats.new, alertStats.sent, alertStats.failed, alertStats.last24h,
		agentStats.total, agentStats.active, agentStats.disconnected, agentStats.lastHour)

	logger.Debug("Summary statistics displayed successfully",
		zap.Int("alert_total", alertStats.total),
		zap.Int("alert_new", alertStats.new),
		zap.Int("agent_total", agentStats.total),
		zap.Int("agent_active", agentStats.active))
}