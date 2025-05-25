// cmd/pandora/read/read.go
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// ReadCmd is the top-level 'eos pandora inspect' command.
var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Inspect secrets and data in Pandora (Vault)",
	Long:  "Inspect and view stored secrets or test data in Pandora (Vault).",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}
