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

// log is a package-level variable for the Zap logger.
var log *zap.Logger


// ReadCmd is the root command for read operations
var InspectCmd = &cobra.Command{
	Use:     "inspect",
	Short:   "Inspect resources (e.g., processes, users, storage)",
	Long:    `The inspect command retrieves information about various resources such as processes, users, or storage.`,
	Aliases: []string{"read", "get", "list", "ls"},
	Run: func(cmd *cobra.Command, args []string) {
		log = logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	}	,
}	


func init() {
	// Initialize the shared logger for the entire install package
	log = logger.L()
}


