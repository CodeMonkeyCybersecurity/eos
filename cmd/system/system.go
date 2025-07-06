package system

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemCmd represents the parent "system" command.
var SystemCmd = &cobra.Command{
	Use:     "system",
	Short:   "System management and diagnostic commands",
	Long:    "Commands for system diagnostics, cleanup, configuration, and management tasks.",
	Aliases: []string{"sys"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for system command.", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}