// cmd/pandora/pandora.go

package pandora

import (
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora/delete"
	read "github.com/CodeMonkeyCybersecurity/eos/cmd/pandora/read"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora/update"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
)

// PandoraCmd groups commands related to managing pandora (Wazuh) components.
var PandoraCmd = &cobra.Command{
	Use:     "pandora",
	Short:   "Manage pandora (Vault) components",
	Long:    "Commands related to pandora and integrations such as install, remove, and inspect.",
	Aliases: []string{"p"},
	// Optionally, you can define a Run function to display help if no subcommand is provided.
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	PandoraCmd.AddCommand(create.CreateCmd)
	PandoraCmd.AddCommand(delete.DeleteCmd)
	PandoraCmd.AddCommand(read.ReadCmd)
	PandoraCmd.AddCommand(update.UpdateCmd)
}

// log is a package-level variable for the Zap logger.

func init() {
	// Initialize the shared logger for the entire deploy package

}
