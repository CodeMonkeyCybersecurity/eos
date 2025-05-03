// cmd/update/update.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/
package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// UpdateCmd is the root command for update operations
var UpdateCmd = &cobra.Command{
	Use:     "update",
	Aliases: []string{"upgrade", "modify", "change", "sync"},
	Short:   "Update resources (e.g., processes, users, storage)",
	Long:    `The update command allows you to modify existing resources such as processes, users, or storage.`,

	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

// Add any subcommands to the UpdateCmd here, if needed
// For example, you can add a subcommand like this:
