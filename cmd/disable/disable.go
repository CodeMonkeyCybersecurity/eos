// cmd/disable/disable.go

package disable

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable system features (e.g., suspension, hibernation)",

	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.L()

		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()
}
