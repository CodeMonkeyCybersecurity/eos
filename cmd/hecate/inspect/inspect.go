// cmd/inspect/inspect.go

package inspect

import (
	"fmt"

	"github.com/spf13/cobra"
)

// InspectCmd is the top-level `inspect` command
var InspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect the current state of Hecate-managed services",
	Long: `Use this command to inspect the status, configuration, and health of 
reverse proxy applications deployed via Hecate.

Examples:
  hecate inspect config
  hecate inspect`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔍 Please use a subcommand (e.g. 'inspect config') to inspect a resource.")
	},
}

// Register subcommands when the package is loaded
func init() {
	InspectCmd.AddCommand(inspectConfigCmd)
}
