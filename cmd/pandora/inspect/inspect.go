// cmd/pandora/inspect/inspect.go
package inspect

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

// InspectCmd is the top-level 'eos pandora inspect' command.
var InspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect secrets and data in Pandora (Vault)",
	Long:  "Inspect and view stored secrets or test data in Pandora (Vault).",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}
