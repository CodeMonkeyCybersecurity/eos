// cmd/pandora/pandora.go

package pandora

import (
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora/inspect"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora/update"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// PandoraCmd groups commands related to managing pandora (Wazuh) components.
var PandoraCmd = &cobra.Command{
	Use:   "pandora",
	Short: "Manage pandora (Vault) components",
	Long:  "Commands related to pandora and integrations such as install, remove, and inspect.",
	// Optionally, you can define a Run function to display help if no subcommand is provided.
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		shared.SafeHelp(cmd, log)
		return nil
	}),
}

func init() {
	PandoraCmd.AddCommand(create.CreateCmd)
	PandoraCmd.AddCommand(delete.DeleteCmd)
	PandoraCmd.AddCommand(inspect.InspectCmd)
	PandoraCmd.AddCommand(update.UpdateCmd)
}

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()
}
