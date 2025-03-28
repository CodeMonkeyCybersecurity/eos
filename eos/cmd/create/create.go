/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/
// cmd/create/create.go
package create

import (
	"eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CreateCmd is the root command for create operations
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create resources (e.g., processes, users, storage)",
	Long:  `The create command allows you to create various resources such as processes, users, or storage.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}

// init registers subcommands for the create command
func init() {
	CreateCmd.AddCommand(createProcessCmd)
	CreateCmd.AddCommand(createUserCmd)
	CreateCmd.AddCommand(createStorageCmd)
	CreateCmd.AddCommand(createBackupCmd)
}
