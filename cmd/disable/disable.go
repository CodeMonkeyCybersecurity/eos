// cmd/disable/disable.go

package disable

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable system features (e.g., suspension, hibernation)",

	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.L()

		if flags.IsDryRun() {
			log.Info("Dry-run mode: no subcommand executed", zap.String("command", cmd.Use))
			fmt.Printf("💡 [dry-run] No subcommand was executed for '%s'\n", cmd.Use)
			return nil
		}

		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}
