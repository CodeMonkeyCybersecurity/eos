// cmd/pandora/create/create.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// CreateCmd is the top-level 'eos pandora create' command.
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create resources in Pandora (Vault)",
	Long:  "Create secrets and test data in Pandora (Vault) for testing and validation.",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}
