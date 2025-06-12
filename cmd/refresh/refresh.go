// cmd/refresh/refresh.go
package refresh

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RefreshCmd represents the refresh parent command.
var RefreshCmd = &cobra.Command{
	Use:     "refresh",
	Short:   "Refresh Eos system components (e.g., passwords, tokens)",
	Long:    "Commands to refresh or reload Eos components safely and securely.",
	Aliases: []string{"reload", "restart", "rescue"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for refresh command", zap.String("command", cmd.Use))
		_ = cmd.Help() // fallback to displaying help if no subcommand
		return nil
	}),
}

// logger instance shared for refresh package

func init() {

}
