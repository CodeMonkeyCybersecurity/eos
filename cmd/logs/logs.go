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

// LogsCmd represents the parent "logs" command.
var LogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Log related commands",
	Long:  "Commands for viewing and tailing logs for various components.",
}

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire install package
	log = logger.L()

	LogsCmd.AddCommand(vaultLogsCmd)
}
