// cmd/read/wazuh_agents.go
package read

import (
	"encoding/json"
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/agents"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	wazuhAgentsLimit   int
	wazuhAgentsRefresh int
	wazuhAgentsDsn     string
)

// wazuhAgentsCmd watches agents table for real-time changes
var wazuhAgentsCmd = &cobra.Command{
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
  eos read wazuh agents --limit 25 --refresh 3`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Delegate to pkg/wazuh/agents
		return agents.WatchAgents(rc, agents.WatchConfig{
			DSN:     wazuhAgentsDsn,
			Limit:   wazuhAgentsLimit,
			Refresh: wazuhAgentsRefresh,
		})
	}),
}

func init() {
	wazuhAgentsCmd.Flags().IntVarP(&wazuhAgentsLimit, "limit", "l", 15, "Number of agents to display")
	wazuhAgentsCmd.Flags().IntVarP(&wazuhAgentsRefresh, "refresh", "r", 10, "Refresh interval in seconds")
	wazuhAgentsCmd.Flags().StringVarP(&wazuhAgentsDsn, "dsn", "d", "", "PostgreSQL connection string (defaults to AGENTS_PG_DSN env var)")
}

var ReadKeepAliveCmd = &cobra.Command{
	Use:   "keepalive",
	Short: "Check disconnected agents from Wazuh API",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := wazuh.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Wazuh config", zap.Error(err))
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

		response, err := wazuh.GetJSON(rc, baseURL, headers)
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
	readWazuhCmd.AddCommand(ReadKeepAliveCmd)
}
