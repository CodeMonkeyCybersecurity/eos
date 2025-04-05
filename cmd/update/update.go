// cmd/update/update.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// UpdateCmd is the root command for update operations
var UpdateCmd = &cobra.Command{
	Use:   "update",
	Aliases: []string{"upgrade", "modify", "change"},
	Short: "Update resources (e.g., processes, users, storage)",
	Long:  `The update command allows you to modify existing resources such as processes, users, or storage.`,

	Run: func(cmd *cobra.Command, args []string) {
		log = logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	}	,
}	

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire install package
	log = logger.L()
}

// Add any subcommands to the UpdateCmd here, if needed
// For example, you can add a subcommand like this:	
