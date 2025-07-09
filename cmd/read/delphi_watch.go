// cmd/delphi/watch/watch.go
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WatchCmd represents the 'watch' command for monitoring database changes
var WatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch Delphi database for real-time changes",
	Long: `The 'watch' command provides real-time monitoring of the Delphi PostgreSQL database.

You can watch:
- alerts: Monitor new security alerts as they arrive
- agents: Monitor agent status changes and new registrations

The display updates in real-time showing the latest entries in a spreadsheet-like format.`,
	Aliases: []string{"monitor", "tail"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Watch command called without subcommand",
			zap.String("command", "eos delphi watch"),
		)
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	// Add subcommands for watching different tables
	WatchCmd.AddCommand(pipelineAlertsCmd)
	WatchCmd.AddCommand(delphiAgentsCmd)
	WatchCmd.AddCommand(pipelineAllCmd)
}
