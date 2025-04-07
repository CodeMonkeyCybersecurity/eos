// cmd/refresh/refresh.go
package refresh

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"go.uber.org/zap"
)

// RefreshCmd represents the refresh parent command.
var RefreshCmd = &cobra.Command{
	Use:     "refresh",
	Short:   "Refresh commands",
	Long:    "Commands to refresh or reload components.",
	Aliases: []string{"reload", "restart"},
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log = logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil 
	}),
}

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire install package
	log = logger.L()
}
