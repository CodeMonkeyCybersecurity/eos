// cmd/pandora/delete/delete.go
package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

// DeleteCmd is the top-level 'eos pandora delete' command.
var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete resources from Pandora (Vault)",
	Long:  "Delete secrets and test data from Pandora (Vault).",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}
