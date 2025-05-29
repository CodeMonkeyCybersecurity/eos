// cmd/disable/disable.go

package disable

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable system features (e.g., suspension, hibernation)",

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}

func init() {
	// Initialize the shared logger for the entire deploy package
}
