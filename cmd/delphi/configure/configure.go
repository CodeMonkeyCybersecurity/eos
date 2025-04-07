// cmd/delphi/configure/configure.go
package configure

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var ConfigureCmd = &cobra.Command{
	Use:     "configure",
	Aliases: []string{"config"},
	Short:   "Configure Delphi (Wazuh) related services",
	Long:    "Run configuration commands such as setting up firewall rules, tuning agent settings, and more.",

	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()
	ConfigureCmd.AddCommand(ConfigureFirewallCmd)
}
