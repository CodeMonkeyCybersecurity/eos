// cmd/delphi/services/services.go
package services

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServicesCmd represents the 'services' command for managing Delphi pipeline services
var ServicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Manage Delphi pipeline systemd services",
	Long: `The 'services' command provides functionality to manage the Delphi data pipeline systemd services.

This includes:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- delphi-emailer: Email notification service
- llm-worker: LLM processing service

Available operations:
- check: Verify Python dependencies are installed
- install: Install required Python dependencies
- start/stop/restart: Control service lifecycle
- enable/disable: Configure service autostart
- status: View service status and health
- logs: View service logs and troubleshooting info`,
	Aliases: []string{"svc"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Services command called without subcommand",
			zap.String("command", "eos delphi services"),
		)
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	// Add subcommands for service management
	ServicesCmd.AddCommand(NewStartCmd())
	ServicesCmd.AddCommand(NewStopCmd())
	ServicesCmd.AddCommand(NewRestartCmd())
	ServicesCmd.AddCommand(NewStatusCmd())
	ServicesCmd.AddCommand(NewEnableCmd())
	ServicesCmd.AddCommand(NewDisableCmd())
	ServicesCmd.AddCommand(NewLogsCmd())
}