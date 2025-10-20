// cmd/read.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// log is a package-level variable for the Zap logger.

// ReadCmd is the root command for read operations
var ReadCmd = &cobra.Command{
	Use:     "read",
	Short:   "Inspect resources (e.g., processes, users, storage)",
	Long:    `The read command retrieves information about various resources such as processes, users, or storage.`,
	Aliases: []string{"inspect", "get", "query", "verify", "enumerate", "enum"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Initialize the shared logger for the entire install package

	// Add the major sub-commands
	ReadCmd.AddCommand(InspectCmd)
	ReadCmd.AddCommand(ReadDiskCmd)
	ReadCmd.AddCommand(readWazuhCmd)
	ReadCmd.AddCommand(readHecateCmd)
	ReadCmd.AddCommand(readSecretsCmd)
	ReadCmd.AddCommand(readCephCmd)
}
