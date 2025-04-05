// cmd/delphi/sync/sync.go

package sync

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var SyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync Delphi components (e.g., LDAP backend)",
	Long:  "Synchronize data or configuration from fallback or external sources.",

	Run: func(cmd *cobra.Command, args []string) {
		log = logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire install package
	log = logger.L()
}
