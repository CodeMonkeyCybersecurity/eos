// cmd/pandora/read/read.go
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
)

// ReadCmd is the top-level 'eos pandora inspect' command.
var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Inspect secrets and data in Pandora (Vault)",
	Long:  "Inspect and view stored secrets or test data in Pandora (Vault).",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}
