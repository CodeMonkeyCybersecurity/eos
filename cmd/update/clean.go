// cmd/update/clean.go

package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CleanCmd is the root command for clean operations
var CleanCmd = &cobra.Command{
	Use:     "clean",
	Aliases: []string{"sanitise", "sanitize"},
	Short:   "Clean and sanitize system resources and components",
	Long: `Clean and sanitize system resources including temporary files, caches, logs, and unused data.

This command provides various cleaning operations to maintain system health and free up disk space.
The clean command serves as a parent for various cleaning subcommands.

Examples:
  eos update clean system          # Clean system temporary files
  eos update clean cache           # Clean application caches
  eos update clean logs            # Clean old log files
  eos update clean docker          # Clean Docker images and containers`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}
