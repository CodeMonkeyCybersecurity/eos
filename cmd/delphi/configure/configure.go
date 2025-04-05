// cmd/delphi/configure/configure.go
package configure

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var ConfigureCmd = &cobra.Command{
	Use:     "configure",
	Aliases: []string{"config"},
	Short:   "Configure Delphi (Wazuh) related services",
	Long:    "Run configuration commands such as setting up firewall rules, tuning agent settings, and more.",

	Run: func(cmd *cobra.Command, args []string) {
		log := logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}

var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()
}
