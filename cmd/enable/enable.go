package enable

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"

	"go.uber.org/zap"
)

// log is a package-level variable for the Zap logger.
var log *zap.Logger

// EnableCmd represents the parent "enable" command.
var EnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Commands to enable or start services",
	Long:  "Commands to enable or start services, such as initializing and unsealing Vault.",
	Aliases: []string{"start", "init", "unseal"},
	Run: func(cmd *cobra.Command, args []string) {
		log = logger.L()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
	}	,
}	



func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()
}