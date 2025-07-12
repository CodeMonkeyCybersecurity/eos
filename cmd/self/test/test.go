package test

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TestCmd represents the parent "test" command.
var TestCmd = &cobra.Command{
	Use:     "test",
	Short:   "Commands for testing and validation",
	Long:    "Commands for running tests, fuzz tests, and validation across the EOS codebase.",
	Aliases: []string{"t"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for test command.", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}
