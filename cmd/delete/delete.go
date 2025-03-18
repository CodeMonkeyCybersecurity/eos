/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
//cmd/delete.go
package delete

import (
	"eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// DeleteCmd is the root command for delete operations
var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete resources (e.g., processes, users, storage)",
	Long:  `The delete command allows you to remove various resources such as processes, users, or storage.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("No subcommand provided for delete.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}

// init registers subcommands for the delete command
func init() {
	DeleteCmd.AddCommand(deleteProcessCmd)
	DeleteCmd.AddCommand(deleteUsersCmd)
	DeleteCmd.AddCommand(deleteStorageCmd)
	DeleteCmd.AddCommand(deleteUmamiCmd)
}
