// cmd/inspect/inspect.go

package inspect

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
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
	Aliases: []string{"read", "get"},
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		fmt.Println("🔍 Please use a subcommand (e.g. 'inspect config') to inspect a resource.")
		return nil
	}),
}

// Register subcommands when the package is loaded
func init() {
	InspectCmd.AddCommand(inspectConfigCmd)
}
