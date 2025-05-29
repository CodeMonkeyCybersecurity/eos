// cmd/read/read.go

package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// ReadCmd is the top-level `inspect` command
var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Inspect the current state of Hecate-managed services",
	Long: `Use this command to inspect the status, configuration, and health of 
reverse proxy applications deployed via Hecate.

Examples:
	hecate inspect config
	hecate inspect`,
	Aliases: []string{"read", "get"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		fmt.Println("🔍 Please use a subcommand (e.g. 'inspect config') to inspect a resource.")
		return nil
	}),
}

// Register subcommands when the package is loaded
func init() {
	ReadCmd.AddCommand(inspectConfigCmd)
}
