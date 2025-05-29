// cmd/delphi/update/agents.go

package update

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

var UpdateAgentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Upgrade Wazuh agents via the Wazuh API",
	Long:  "Upgrades one or more Wazuh agents using a remote package (WPK) via the API.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := delphi.ReadConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to load Delphi config", zap.Error(err))
			return err
		}

		token, err := delphi.Authenticate(rc, cfg)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Authentication failed", zap.Error(err))
			return fmt.Errorf("authentication failed: %w", err)
		}

		agentRaw := interaction.PromptInput(rc.Ctx, "Enter agent IDs (comma-separated)", "")
		agentIDs := strings.Split(agentRaw, ",")

		version := interaction.PromptInput(rc.Ctx, "Enter version (e.g., v4.6.0)", "")
		repo := interaction.PromptInput(rc.Ctx, "Enter WPK repo", "packages.wazuh.com/wpk/")
		packageType := interaction.PromptInput(rc.Ctx, "Enter package type (rpm/deb)", "rpm")
		force, _ := interaction.Resolve("Force upgrade?")
		useHTTP, _ := interaction.Resolve("Use HTTP (instead of HTTPS)?")

		payload := map[string]interface{}{
			"origin":  map[string]string{"module": "api"},
			"command": "upgrade",
			"parameters": map[string]interface{}{
				"agents":        agentIDs,
				"wpk_repo":      repo,
				"version":       version,
				"use_http":      useHTTP,
				"force_upgrade": force,
				"package_type":  packageType,
			},
		}

		if err := delphi.UpgradeAgents(rc, cfg, token, agentIDs, payload); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Upgrade failed", zap.Error(err))
			return fmt.Errorf("upgrade failed: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info("✅ Agent upgrade request sent successfully.")
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateAgentsCmd)
}
