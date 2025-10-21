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

// AddSubcommands adds all update subcommands to the update command
func AddSubcommands() {
	// Add HashiCorp update commands
	UpdateCmd.AddCommand(VaultCmd)
	UpdateCmd.AddCommand(ConsulCmd)
}

// UpdateCmd is the root command for update operations
var UpdateCmd = &cobra.Command{
	Use:     "update",
	Aliases: []string{"modify", "change", "restart", "set", "edit"},
	Short:   "Update resources (e.g., processes, users, storage)",
	Long:    `The update command allows you to modify existing resources such as processes, users, or storage.`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for update command", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}
