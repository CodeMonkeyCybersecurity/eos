// cmd/refresh/refresh.go
package refresh

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// RefreshCmd represents the refresh parent command.
var RefreshCmd = &cobra.Command{
	Use:     "refresh",
	Short:   "Refresh EOS system components (e.g., passwords, tokens)",
	Long:    "Commands to refresh or reload EOS components safely and securely.",
	Aliases: []string{"reload", "restart", "rescue"},
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("No subcommand provided for refresh command", zap.String("command", cmd.Use))
		_ = cmd.Help() // fallback to displaying help if no subcommand
		return nil
	}),
}

// logger instance shared for refresh package

func init() {

}
