// cmd/pandora/update/update.go
package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
)

// UpdateCmd is the top-level 'eos pandora update' command.
var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update existing data in Pandora (Vault)",
	Long:  "Update or modify secrets and test data stored in Pandora (Vault).",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}
