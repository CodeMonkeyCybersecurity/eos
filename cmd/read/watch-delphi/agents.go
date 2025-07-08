// cmd/delphi/watch/agents.go
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
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Agent represents an agent record for display
type Agent struct {
	ID                string     `json:"id"`
	Name              *string    `json:"name"`
	IP                *string    `json:"ip"`
	OS                *string    `json:"os"`
	Registered        *time.Time `json:"registered"`
	LastSeen          *time.Time `json:"last_seen"`
	AgentVersion      *string    `json:"agent_version"`
	StatusText        *string    `json:"status_text"`
	NodeName          *string    `json:"node_name"`
	DisconnectionTime *time.Time `json:"disconnection_time"`
	APIFetchTimestamp *time.Time `json:"api_fetch_timestamp"`
}

// NewAgentsCmd creates the agents watch command
func NewAgentsCmd() *cobra.Command {
	var (
		limit   int
		refresh int
		dsn     string
	)

	cmd := &cobra.Command{
		Use:   "agents",
		Short: "Watch agents table for real-time changes",
		Long: `Watch the agents table for real-time agent status updates.

This command displays agents in a spreadsheet-like format and updates automatically
when agent information changes or new agents are registered.

The display shows:
- Agent ID, Name, IP address
- Operating system and Wazuh agent version
- Registration and last seen timestamps
- Current status and node assignment

Example:
  eos delphi watch agents --limit 25 --refresh 3`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Starting agents watch",
				zap.Int("limit", limit),
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
			return watchAgents(rc.Ctx, logger, db, limit, refresh)
		}),
	}

	cmd.Flags().IntVarP(&limit, "limit", "l", 15, "Number of agents to display")
	cmd.Flags().IntVarP(&refresh, "refresh", "r", 10, "Refresh interval in seconds")
	cmd.Flags().StringVarP(&dsn, "dsn", "d", "", "PostgreSQL connection string (defaults to AGENTS_PG_DSN env var)")

	return cmd
}

func watchAgents(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit, refresh int) error {
	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info(" Starting agents monitoring...")

	// Initial display
	displayAgents(ctx, logger, db, limit)

	// Create ticker for periodic refresh
	ticker := time.NewTicker(time.Duration(refresh) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info(" Context cancelled, stopping agents watch")
			return nil

		case sig := <-sigChan:
			logger.Info(" Received signal, stopping agents watch", zap.String("signal", sig.String()))
			return nil

		case <-ticker.C:
			// Periodic refresh
			displayAgents(ctx, logger, db, limit)
		}
	}
}

func displayAgents(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	fmt.Printf("  Delphi Agents Monitor - Last %d agents (Updated: %s)\n", limit, time.Now().Format("15:04:05"))
	fmt.Println(strings.Repeat("=", 140))

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
			logger.Error(" Failed to close rows", zap.Error(err))
		}
	}()

	// Print header
	fmt.Printf("%-8s %-15s %-15s %-20s %-12s %-12s %-15s %-12s %-15s %-12s\n",
		"ID", "Name", "IP", "OS", "Status", "Last Seen", "Version", "Node", "Registered", "API Fetch")
	fmt.Println(strings.Repeat("-", 140))

	agents := make([]Agent, 0, limit)
	for rows.Next() {
		var agent Agent

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
		name := formatOptionalString(agent.Name, 15)
		ip := formatOptionalString(agent.IP, 15)
		os := formatOptionalString(agent.OS, 20)
		status := formatOptionalString(agent.StatusText, 12)
		version := formatOptionalString(agent.AgentVersion, 15)
		node := formatOptionalString(agent.NodeName, 15)

		// Format timestamps
		lastSeenTime := formatOptionalTimeShort(agent.LastSeen)
		registeredTime := formatOptionalTimeShort(agent.Registered)
		apiFetchTime := formatOptionalTimeShort(agent.APIFetchTimestamp)

		// Color-code status
		statusColor := getAgentStatusColor(agent.StatusText)

		fmt.Printf("%-8s %-15s %-15s %-20s %s%-12s\033[0m %-12s %-15s %-15s %-12s %-12s\n",
			agent.ID, name, ip, os, statusColor, status, lastSeenTime,
			version, node, registeredTime, apiFetchTime)
	}

	if len(agents) == 0 {
		fmt.Println("No agents found.")
	}

	// Count active/inactive agents
	activeCount, totalCount := countAgentsByStatus(ctx, db)
	fmt.Printf("\n Active: %d | Total: %d | Showing: %d | Press Ctrl+C to exit\n",
		activeCount, totalCount, len(agents))
}

func formatOptionalString(s *string, maxLen int) string {
	if s == nil {
		return "-"
	}
	str := *s
	if len(str) > maxLen {
		return str[:maxLen-3] + "..."
	}
	return str
}

func formatOptionalTimeShort(t *time.Time) string {
	if t == nil {
		return "-"
	}

	now := time.Now()
	diff := now.Sub(*t)

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

func getAgentStatusColor(status *string) string {
	if status == nil {
		return "\033[90m" // Gray
	}

	switch strings.ToLower(*status) {
	case "active":
		return "\033[32m" // Green
	case "disconnected":
		return "\033[31m" // Red
	case "pending":
		return "\033[33m" // Yellow
	case "never_connected":
		return "\033[35m" // Magenta
	default:
		return "\033[90m" // Gray
	}
}

func countAgentsByStatus(ctx context.Context, db *sql.DB) (active, total int) {
	// Count active agents
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE status_text = 'active'").Scan(&active)
	if err != nil {
		active = 0
	}

	// Count total agents
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents").Scan(&total)
	if err != nil {
		total = 0
	}

	return active, total
}
