/*
// cmd/logs/logs.go

Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/

// cmd//logs/logs.go
package logs

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"

	"go.uber.org/zap"
)

// log is a package-level variable for the Zap logger.
var log *zap.Logger


// LogsCmd represents the parent "logs" command.
var LogsCmd = &cobra.Command{
	Use:     "logs",
	Aliases: []string{"log", "tail", "view", "debug"},
	Short:   "Log related commands",
	Long:    "Commands for viewing and tailing logs for various components.",
	Run: func(cmd *cobra.Command, args []string) {
		log = logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}


func init() {
	// Initialize the shared logger for the entire install package
	log = logger.L()
}
