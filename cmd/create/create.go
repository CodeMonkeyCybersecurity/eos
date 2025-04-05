/*
cmd/create/create.go

Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au
*/
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"

	"go.uber.org/zap"
)

// CreateCmd is the root command for create operations
var CreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"deploy", "install", "setup", "add", "bootstrap"},
	Short:   "Create, deploy, install resources programmes and components (e.g., processes, users, storage, application containers)",
	Long: `The create command allows you to create various resources such as processes, users, or storage, components or dependencies.
For example:
	eos deploy trivy 
	eos deploy vault
	eos deploy umami`,

	Run: func(cmd *cobra.Command, args []string) {
		log := logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	},
}

var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()
}
