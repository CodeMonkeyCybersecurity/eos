package agents

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared/format"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared/terminal"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WatchAgents monitors the agents table and displays real-time updates.
// It connects to the PostgreSQL database and periodically queries for agent status,
// displaying results in a terminal-friendly format.
func WatchAgents(rc *eos_io.RuntimeContext, config WatchConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting agents watch",
		zap.Int("limit", config.Limit),
		zap.Int("refresh_seconds", config.Refresh))

	// Get database DSN from config or environment
	dsn := config.DSN
	if dsn == "" {
		dsn = os.Getenv("AGENTS_PG_DSN")
		if dsn == "" {
			return fmt.Errorf("database DSN not provided. Set AGENTS_PG_DSN environment variable or use --dsn flag")
		}
	}

	// Connect to database
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database connection", zap.Error(err))
		}
	}()

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info("Connected to PostgreSQL database")

	// Start watching
	return watchAgentsLoop(rc.Ctx, logger, db, config.Limit, config.Refresh)
}

// watchAgentsLoop runs the main monitoring loop with periodic refresh.
func watchAgentsLoop(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit, refresh int) error {
	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Starting agents monitoring...")

	// Initial display
	displayAgents(ctx, logger, db, limit)

	// Create ticker for periodic refresh
	ticker := time.NewTicker(time.Duration(refresh) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled, stopping agents watch")
			return nil

		case sig := <-sigChan:
			logger.Info("Received signal, stopping agents watch", zap.String("signal", sig.String()))
			return nil

		case <-ticker.C:
			// Periodic refresh
			displayAgents(ctx, logger, db, limit)
		}
	}
}

// displayAgents queries and displays the current agent status.
func displayAgents(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
	// Clear screen and move cursor to top
	logger.Info("terminal prompt: \033[2J\033[H")

	logger.Info("terminal prompt: Wazuh Agents Monitor", zap.Int("limit", limit), zap.String("updated", time.Now().Format("15:04:05")))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("=", 140))))

	// Query recent agents
	query := `
		SELECT
			id, name, ip, os, registered, last_seen,
			agent_version, status_text, node_name,
			disconnection_time, api_fetch_timestamp
		FROM agents
		ORDER BY
			CASE
				WHEN last_seen IS NOT NULL THEN last_seen
				ELSE registered
			END DESC NULLS LAST
		LIMIT $1`

	rows, err := db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Error("Failed to query agents", zap.Error(err))
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logger.Error("Failed to close rows", zap.Error(err))
		}
	}()

	// Log header
	logger.Info("terminal prompt: Headers", zap.Strings("columns", []string{"ID", "Name", "IP", "OS", "Status", "Last Seen", "Version", "Node", "Registered", "API Fetch"}))

	agents := make([]AgentMonitor, 0, limit)
	for rows.Next() {
		var agent AgentMonitor

		err := rows.Scan(
			&agent.ID, &agent.Name, &agent.IP, &agent.OS,
			&agent.Registered, &agent.LastSeen, &agent.AgentVersion,
			&agent.StatusText, &agent.NodeName, &agent.DisconnectionTime,
			&agent.APIFetchTimestamp,
		)
		if err != nil {
			logger.Error("Failed to scan agent row", zap.Error(err))
			continue
		}

		agents = append(agents, agent)
	}

	// Display agents
	for _, agent := range agents {
		// Format optional fields
		name := format.OptionalString(agent.Name, 15)
		ip := format.OptionalString(agent.IP, 15)
		os := format.OptionalString(agent.OS, 20)
		status := format.OptionalString(agent.StatusText, 12)
		version := format.OptionalString(agent.AgentVersion, 15)
		node := format.OptionalString(agent.NodeName, 15)

		// Format timestamps
		lastSeenTime := format.OptionalTimeShort(agent.LastSeen)
		registeredTime := format.OptionalTimeShort(agent.Registered)
		apiFetchTime := format.OptionalTimeShort(agent.APIFetchTimestamp)

		// Color-code status (not used in structured logging)
		_ = terminal.GetAgentStatusColor(agent.StatusText)

		logger.Info("terminal prompt: Agent",
			zap.String("id", agent.ID),
			zap.String("name", name),
			zap.String("ip", ip),
			zap.String("os", os),
			zap.String("status", status),
			zap.String("last_seen", lastSeenTime),
			zap.String("version", version),
			zap.String("node", node),
			zap.String("registered", registeredTime),
			zap.String("api_fetch", apiFetchTime))
	}

	if len(agents) == 0 {
		logger.Info("terminal prompt: No agents found.")
	}

	// Count active/inactive agents
	stats := CountAgentsByStatus(ctx, db, len(agents))
	logger.Info("terminal prompt: Agent Summary",
		zap.Int("active", stats.Active),
		zap.Int("total", stats.Total),
		zap.Int("showing", stats.Showing))
}

// CountAgentsByStatus returns summary statistics about agent status.
func CountAgentsByStatus(ctx context.Context, db *sql.DB, showing int) AgentStats {
	stats := AgentStats{Showing: showing}

	// Count active agents
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE status_text = 'active'").Scan(&stats.Active)
	if err != nil {
		stats.Active = 0
	}

	// Count total agents
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents").Scan(&stats.Total)
	if err != nil {
		stats.Total = 0
	}

	return stats
}
