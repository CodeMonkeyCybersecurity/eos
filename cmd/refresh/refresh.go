// cmd/refresh/refresh.go
package refresh

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// RefreshCmd represents the refresh parent command.
var RefreshCmd = &cobra.Command{
	Use:     "refresh",
	Short:   "Refresh commands",
	Long:    "Commands to refresh or reload components.",
	Aliases: []string{"reload", "restart"},
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
