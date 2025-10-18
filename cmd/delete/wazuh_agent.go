// cmd/wazuh/delete/agent.go
package delete

import (
	"encoding/json"
	"os"
	"runtime"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/agents"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var agentID string

var DeleteAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Delete a Wazuh agent using its agent ID and uninstall it from the local machine",
	Long: `This command deletes a Wazuh agent from the server via API and uninstalls the agent locally.

Supported OS uninstallers:
- macOS: /Library/Ossec/uninstall.sh
- Linux: apt-get, yum, or dnf depending on distribution
- Windows: wmic + msiexec`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		if agentID == "" {
			otelzap.Ctx(rc.Ctx).Error("Agent ID is required")
			otelzap.Ctx(rc.Ctx).Info("terminal prompt:  Please provide an agent ID using --agent-id")
			return nil
		}

		otelzap.Ctx(rc.Ctx).Info(" Authenticating and loading Wazuh config...")
		config, err := wazuh.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to load config", zap.Error(err))
			os.Exit(1)
		}

		token, err := wazuh.Authenticate(rc, config)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Authentication failed", zap.Error(err))
			os.Exit(1)
		}

		otelzap.Ctx(rc.Ctx).Info("  Deleting Wazuh agent via API", zap.String("agentID", agentID))

		// Convert wazuh.Config to agents.Config
		agentConfig := &agents.Config{
			Protocol: config.Protocol,
			FQDN:     config.FQDN,
			Port:     config.Port,
		}
		resp, err := agents.DeleteAgent(rc, agentID, token, agentConfig)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to delete agent via API", zap.Error(err))
			os.Exit(1)
		}

		prettyJSON, _ := json.MarshalIndent(resp, "", "  ")
		otelzap.Ctx(rc.Ctx).Info("terminal prompt: Agent deleted successfully from Wazuh", zap.String("response", string(prettyJSON)))

		otelzap.Ctx(rc.Ctx).Info(" Attempting local Wazuh agent uninstall...")
		switch runtime.GOOS {
		case "darwin":
			agents.UninstallMacOS(rc)
		case "linux":
			agents.UninstallLinux(rc)
		case "windows":
			agents.UninstallWindows(rc)
		default:
			otelzap.Ctx(rc.Ctx).Warn("Unsupported OS for local uninstall", zap.String("os", runtime.GOOS))
		}
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	DeleteAgentCmd.Flags().StringVar(&agentID, "agent-id", "", "ID of the agent to delete")
}
