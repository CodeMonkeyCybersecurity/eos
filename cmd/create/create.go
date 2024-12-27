/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
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
		// Log the default behavior
		log := logger.GetLogger()
		if len(args) == 0 {
			log.Warn("No subcommand specified for 'create'. Use a subcommand like 'process' or 'user'.")
			return
		}
		log.Info("Create command invoked without a specific subcommand", zap.Strings("args", args))
	},
}

// init registers subcommands for the create command
func init() {
	CreateCmd.AddCommand(createProcessCmd)
	CreateCmd.AddCommand(createUserCmd)
	CreateCmd.AddCommand(createStorageCmd)
	CreateCmd.AddCommand(createBackupCmd)
}
