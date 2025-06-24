// cmd/delphi/watch/all.go
package watch

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

// NewAllCmd creates the combined watch command
func NewAllCmd() *cobra.Command {
	var (
		alertLimit int
		agentLimit int
		refresh    int
		dsn        string
	)

	cmd := &cobra.Command{
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
  eos delphi watch all --alert-limit 5 --agent-limit 10 --refresh 3`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Starting combined alerts & agents watch",
				zap.Int("alert_limit", alertLimit),
				zap.Int("agent_limit", agentLimit),
				zap.Int("refresh_seconds", refresh))

			// Get database DSN
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
					logger.Error(" Failed to close database connection", zap.Error(err))
				}
			}()

			// Test connection
			if err := db.Ping(); err != nil {
				return fmt.Errorf("failed to ping database: %w", err)
			}

			logger.Info(" Connected to PostgreSQL database")

			// Start watching
			return watchAll(rc.Ctx, logger, db, alertLimit, agentLimit, refresh)
		}),
	}

	cmd.Flags().IntVar(&alertLimit, "alert-limit", 5, "Number of recent alerts to display")
	cmd.Flags().IntVar(&agentLimit, "agent-limit", 8, "Number of agents to display")
	cmd.Flags().IntVarP(&refresh, "refresh", "r", 5, "Refresh interval in seconds")
	cmd.Flags().StringVarP(&dsn, "dsn", "d", "", "PostgreSQL connection string (defaults to AGENTS_PG_DSN env var)")

	return cmd
}

func watchAll(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, alertLimit, agentLimit, refresh int) error {
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

	// Listen for alert-related notifications
	channels := []string{"new_alert", "new_response", "alert_sent"}
	for _, channel := range channels {
		err := listener.Listen(channel)
		if err != nil {
			return fmt.Errorf("failed to listen for %s notifications: %w", channel, err)
		}
	}

	logger.Info(" Listening for database notifications...")

	// Initial display
	displayAll(ctx, logger, db, alertLimit, agentLimit)

	// Create ticker for periodic refresh
	ticker := time.NewTicker(time.Duration(refresh) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("🛑 Context cancelled, stopping combined watch")
			return nil

		case sig := <-sigChan:
			logger.Info("🛑 Received signal, stopping combined watch", zap.String("signal", sig.String()))
			return nil

		case notification := <-listener.Notify:
			if notification != nil {
				logger.Debug("📬 Received database notification",
					zap.String("channel", notification.Channel),
					zap.String("payload", notification.Extra))

				// Refresh display on notification
				displayAll(ctx, logger, db, alertLimit, agentLimit)
			}

		case <-ticker.C:
			// Periodic refresh
			displayAll(ctx, logger, db, alertLimit, agentLimit)
		}
	}
}

func displayAll(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, alertLimit, agentLimit int) {
	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	currentTime := time.Now().Format("15:04:05")
	fmt.Printf(" Delphi Real-Time Monitor (Updated: %s)\n", currentTime)
	fmt.Println(strings.Repeat("=", 120))

	// Display recent alerts section
	fmt.Printf("\n Recent Alerts (Last %d)\n", alertLimit)
	fmt.Println(strings.Repeat("-", 80))

	displayRecentAlerts(ctx, logger, db, alertLimit)

	// Display agents section
	fmt.Printf("\n🖥️  Active Agents (Top %d)\n", agentLimit)
	fmt.Println(strings.Repeat("-", 80))

	displayRecentAgents(ctx, logger, db, agentLimit)

	// Display summary statistics
	fmt.Println(strings.Repeat("=", 120))
	displaySummaryStats(ctx, db)
	fmt.Println("\n Press Ctrl+C to exit")
}

func displayRecentAlerts(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
	query := `
		SELECT 
			id, agent_id, rule_level, rule_desc, state,
			ingest_timestamp
		FROM alerts 
		ORDER BY ingest_timestamp DESC 
		LIMIT $1`

	rows, err := db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Error("Failed to query recent alerts", zap.Error(err))
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logger.Error(" Failed to close rows", zap.Error(err))
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
		timeStr := formatRelativeTime(ingestTime)
		stateColor := getStateColor(state)

		fmt.Printf("%-6d %-12s %-5d %s%-10s\033[0m %-8s %s\n",
			id, agentID, ruleLevel, stateColor, state, timeStr, desc)
		count++
	}

	if count == 0 {
		fmt.Println("No recent alerts")
	}
}

func displayRecentAgents(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
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

	rows, err := db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Error("Failed to query recent agents", zap.Error(err))
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logger.Error(" Failed to close rows", zap.Error(err))
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
			statusColor = getAgentStatusColor(&statusStr)
		}

		lastSeenStr := "-"
		if lastSeen.Valid {
			lastSeenStr = formatRelativeTime(lastSeen.Time)
		}

		fmt.Printf("%-8s %-15s %-15s %s%-12s\033[0m %s\n",
			id, nameStr, ipStr, statusColor, statusStr, lastSeenStr)
		count++
	}

	if count == 0 {
		fmt.Println("No active agents")
	}
}

func displaySummaryStats(ctx context.Context, db *sql.DB) {
	logger := otelzap.Ctx(ctx)

	// Get alert stats
	var alertStats struct {
		total   int
		new     int
		sent    int
		failed  int
		last24h int
	}

	// Total alerts
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts").Scan(&alertStats.total); err != nil {
		logger.Error(" Failed to get total alerts count", zap.Error(err))
		alertStats.total = 0
	}

	// Alerts by state
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE state = 'new'").Scan(&alertStats.new); err != nil {
		logger.Error(" Failed to get new alerts count", zap.Error(err))
		alertStats.new = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE state = 'sent'").Scan(&alertStats.sent); err != nil {
		logger.Error(" Failed to get sent alerts count", zap.Error(err))
		alertStats.sent = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE state = 'failed'").Scan(&alertStats.failed); err != nil {
		logger.Error(" Failed to get failed alerts count", zap.Error(err))
		alertStats.failed = 0
	}

	// Alerts in last 24h
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE ingest_timestamp > NOW() - INTERVAL '24 hours'").Scan(&alertStats.last24h); err != nil {
		logger.Error(" Failed to get 24h alerts count", zap.Error(err))
		alertStats.last24h = 0
	}

	// Get agent stats
	var agentStats struct {
		total        int
		active       int
		disconnected int
		lastHour     int
	}

	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents").Scan(&agentStats.total); err != nil {
		logger.Error(" Failed to get total agents count", zap.Error(err))
		agentStats.total = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE status_text = 'active'").Scan(&agentStats.active); err != nil {
		logger.Error(" Failed to get active agents count", zap.Error(err))
		agentStats.active = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE status_text = 'disconnected'").Scan(&agentStats.disconnected); err != nil {
		logger.Error(" Failed to get disconnected agents count", zap.Error(err))
		agentStats.disconnected = 0
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE last_seen > NOW() - INTERVAL '1 hour'").Scan(&agentStats.lastHour); err != nil {
		logger.Error(" Failed to get recent agents count", zap.Error(err))
		agentStats.lastHour = 0
	}

	fmt.Printf("📈 Alerts: %d total | %d new | %d sent | %d failed | %d (24h) | "+
		"Agents: %d total | %d active | %d disconnected | %d (1h)",
		alertStats.total, alertStats.new, alertStats.sent, alertStats.failed, alertStats.last24h,
		agentStats.total, agentStats.active, agentStats.disconnected, agentStats.lastHour)
}

func formatRelativeTime(t time.Time) string {
	diff := time.Since(t)

	if diff < time.Minute {
		return "now"
	} else if diff < time.Hour {
		return fmt.Sprintf("%dm", int(diff.Minutes()))
	} else if diff < 24*time.Hour {
		return fmt.Sprintf("%dh", int(diff.Hours()))
	} else {
		return fmt.Sprintf("%dd", int(diff.Hours()/24))
	}
}
