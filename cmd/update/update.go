// cmd/update/update.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/
package update

import (
	"eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// UpdateCmd is the root command for update operations
var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update resources (e.g., processes, users, storage)",
	Long:  `The update command allows you to modify existing resources such as processes, users, or storage.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("No subcommand provided for update.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}

// init registers subcommands for the update command
func init() {
	UpdateCmd.AddCommand(updateProcessCmd)
	UpdateCmd.AddCommand(updateUsersCmd)
	UpdateCmd.AddCommand(updateStorageCmd)
	UpdateCmd.AddCommand(hostnameCmd)
}
