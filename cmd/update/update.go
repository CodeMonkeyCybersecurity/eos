// cmd/update/update.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateCmd is the root command for update operations
var UpdateCmd = &cobra.Command{
	Use:     "update",
	Aliases: []string{"upgrade", "modify", "change"},
	Short:   "Update resources (e.g., processes, users, storage)",
	Long:    `The update command allows you to modify existing resources such as processes, users, or storage.`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}
