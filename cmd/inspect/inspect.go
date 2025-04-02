// cmd/inspect.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/
package inspect

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ReadCmd is the root command for read operations
var InspectCmd = &cobra.Command{
	Use:     "inspect",
	Short:   "Inspect resources (e.g., processes, users, storage)",
	Long:    `The inspect command retrieves information about various resources such as processes, users, or storage.`,
	Aliases: []string{"read", "get", "list", "ls"},
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("No subcommand provided for read.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}

// init registers subcommands for the read command
func init() {
	InspectCmd.AddCommand(InspectProcessCmd)
	InspectCmd.AddCommand(InspectUsersCmd)
	InspectCmd.AddCommand(InspectStorageCmd)
}
