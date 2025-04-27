// cmd/refresh/refresh.go
package refresh

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// RefreshCmd represents the refresh parent command.
var RefreshCmd = &cobra.Command{
	Use:     "refresh",
	Short:   "Refresh EOS system components (e.g., passwords, tokens)",
	Long:    "Commands to refresh or reload EOS components safely and securely.",
	Aliases: []string{"reload", "restart"},
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log = logger.L()
		log.Info("No subcommand provided for refresh command", zap.String("command", cmd.Use))
		_ = cmd.Help() // fallback to displaying help if no subcommand
		return nil
	}),
}

// logger instance shared for refresh package
var log *zap.Logger

func init() {
	log = logger.L()
}
