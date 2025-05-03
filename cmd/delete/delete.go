/*
cmd/delete/delete.go

Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au
*/

package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"

	"github.com/spf13/cobra"

	"go.uber.org/zap"
)

// DeleteCmd is the root command for delete operations
var DeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"remove", "uninstall", "rm"},
	Short:   "Delete resources (e.g., processes, users, storage)",
	Long: `The delete command allows you to remove various resources such as processes, users, or storage.
For example:
	eos delete trivy 
	eos delete vault
	eos delete umami`,

	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

// log is a package-level variable for the Zap logger.

func init() {
	// Initialize the shared logger for the entire deploy package

}
