// cmd/disable/disable.go

package disable

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable system features (e.g., suspension, hibernation)",

	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}

func init() {
	// Initialize the shared logger for the entire deploy package
}
