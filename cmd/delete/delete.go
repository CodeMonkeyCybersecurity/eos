/*
cmd/delete/delete.go

Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au
*/

package delete

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"

	"go.uber.org/zap"
)

// DeleteCmd is the root command for delete operations
var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete resources (e.g., processes, users, storage)",
	Long: `The delete command allows you to remove various resources such as processes, users, or storage.
For example:
	eos delete trivy 
	eos delete vault
	eos delete umami`,

	Aliases: []string{"remove", "uninstall", "rm"},

	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()
}
