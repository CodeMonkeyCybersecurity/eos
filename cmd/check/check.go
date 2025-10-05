// cmd/check/check.go
package check

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// CheckCmd represents the 'eos check' command
var CheckCmd = &cobra.Command{
	Use:   "check [command]",
	Short: "Check the status of various Eos components",
	Long:  `Check the status and health of various Eos components and services.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}

// AddSubcommands adds all check subcommands to the root command
func AddSubcommands() {
	// Authentik subcommand is added in authentik.go
}

// RegisterCommands registers all check commands with the root command
func RegisterCommands(rootCmd *cobra.Command) {
	rootCmd.AddCommand(CheckCmd)
}
