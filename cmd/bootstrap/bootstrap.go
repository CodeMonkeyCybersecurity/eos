// cmd/bootstrap/bootstrap.go
// Top-level bootstrap command that provides direct access to bootstrap functionality

package bootstrap

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
)

// BootstrapCmd is the top-level bootstrap command
var BootstrapCmd *cobra.Command

func init() {
	// Find the bootstrap command from create and use it directly
	for _, cmd := range create.CreateCmd.Commands() {
		if cmd.Name() == "bootstrap" {
			// Create a copy of the bootstrap command for top-level use
			BootstrapCmd = &cobra.Command{
				Use:     cmd.Use,
				Short:   cmd.Short + " (alias)",
				Long:    cmd.Long,
				Aliases: cmd.Aliases,
				RunE:    cmd.RunE,
			}
			
			// Copy all subcommands
			for _, subCmd := range cmd.Commands() {
				BootstrapCmd.AddCommand(subCmd)
			}
			
			// Copy all flags
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				BootstrapCmd.Flags().AddFlag(flag)
			})
			
			break
		}
	}
	
	// Fallback if bootstrap command not found
	if BootstrapCmd == nil {
		BootstrapCmd = &cobra.Command{
			Use:   "bootstrap",
			Short: "Bootstrap infrastructure components",
			Long:  "Bootstrap infrastructure components (create bootstrap must be available)",
			RunE: func(cmd *cobra.Command, args []string) error {
				return cmd.Help()
			},
		}
	}
}