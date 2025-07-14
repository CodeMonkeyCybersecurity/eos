// cmd/delphi/watch/agents.go
package read

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
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

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	delphiAgentsLimit   int
	delphiAgentsRefresh int
	delphiAgentsDsn     string
)

// delphiAgentsCmd watches agents table for real-time changes
var delphiAgentsCmd = &cobra.Command{
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
  eos read delphi agents --limit 25 --refresh 3`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting agents watch",
			zap.Int("limit", delphiAgentsLimit),
			zap.Int("refresh_seconds", delphiAgentsRefresh))

		// Get database DSN
		if delphiAgentsDsn == "" {
			delphiAgentsDsn = os.Getenv("AGENTS_PG_DSN")
			if delphiAgentsDsn == "" {
				return fmt.Errorf("database DSN not provided. Set AGENTS_PG_DSN environment variable or use --dsn flag")
			}
		}

		// Connect to database
		db, err := sql.Open("postgres", delphiAgentsDsn)
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
		return watchAgents(rc.Ctx, logger, db, delphiAgentsLimit, delphiAgentsRefresh)
	}),
}

func init() {
	delphiAgentsCmd.Flags().IntVarP(&delphiAgentsLimit, "limit", "l", 15, "Number of agents to display")
	delphiAgentsCmd.Flags().IntVarP(&delphiAgentsRefresh, "refresh", "r", 10, "Refresh interval in seconds")
	delphiAgentsCmd.Flags().StringVarP(&delphiAgentsDsn, "dsn", "d", "", "PostgreSQL connection string (defaults to AGENTS_PG_DSN env var)")
}

// TODO: Move to pkg/delphi/monitoring or pkg/delphi/agents
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

// TODO: Move to pkg/delphi/display or pkg/delphi/output
func displayAgents(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit int) {
	// Clear screen and move cursor to top
	logger.Info("terminal prompt: \033[2J\033[H")

	logger.Info("terminal prompt: Delphi Agents Monitor", zap.Int("limit", limit), zap.String("updated", time.Now().Format("15:04:05")))
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
			logger.Error(" Failed to close rows", zap.Error(err))
		}
	}()

	// Log header
	logger.Info("terminal prompt: Headers", zap.Strings("columns", []string{"ID", "Name", "IP", "OS", "Status", "Last Seen", "Version", "Node", "Registered", "API Fetch"}))

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

		// Color-code status (not used in structured logging)
		_ = getAgentStatusColor(agent.StatusText)

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
	activeCount, totalCount := countAgentsByStatus(ctx, db)
	logger.Info("terminal prompt: Agent Summary", 
		zap.Int("active", activeCount),
		zap.Int("total", totalCount),
		zap.Int("showing", len(agents)))
}

// TODO: Move to pkg/shared/format or pkg/eos_io
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

// TODO: Move to pkg/shared/format or pkg/shared/time
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

// TODO: Move to pkg/delphi/display or pkg/shared/terminal
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

// TODO: Move to pkg/delphi/agents or pkg/delphi/stats
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

var ReadKeepAliveCmd = &cobra.Command{
	Use:   "keepalive",
	Short: "Check disconnected agents from Wazuh API",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := delphi.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Delphi config", zap.Error(err))
		}
		if cfg.Protocol == "" {
			cfg.Protocol = "https"
		}
		if cfg.Port == "" {
			cfg.Port = "55000"
		}
		if cfg.Endpoint == "" {
			cfg.Endpoint = "/agents?select=lastKeepAlive&select=id&status=disconnected"
		}
		baseURL := fmt.Sprintf("%s://%s:%s%s", cfg.Protocol, cfg.FQDN, cfg.Port, cfg.Endpoint)

		otelzap.Ctx(rc.Ctx).Info("Sending GET request to Wazuh", zap.String("url", baseURL))

		headers := map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", cfg.Token),
			"Content-Type":  "application/json",
		}

		response, err := delphi.GetJSON(rc, baseURL, headers)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to fetch keepalive data", zap.Error(err))
		}

		pretty, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to format JSON", zap.Error(err))
		}
		otelzap.Ctx(rc.Ctx).Info("terminal prompt: Disconnected agents")
		otelzap.Ctx(rc.Ctx).Info("terminal prompt: JSON output", zap.String("data", string(pretty)))
		return nil
	}),
}

func init() {
	readDelphiCmd.AddCommand(ReadKeepAliveCmd)
}
