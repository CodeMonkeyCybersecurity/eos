// cmd/delphi/delphi.go

package delphi

import (
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/read"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/sync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/update"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
)

// DelphiCmd groups commands related to managing Delphi (Wazuh) components.
var DelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Manage Delphi (Wazuh) components",
	Long:  "Commands related to Wazuh and Delphi integrations such as install, remove, and inspect.",
	// Optionally, you can define a Run function to display help if no subcommand is provided.
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	// Register subcommands
	DelphiCmd.AddCommand(create.CreateCmd)
	DelphiCmd.AddCommand(read.ReadCmd)
	DelphiCmd.AddCommand(delete.DeleteCmd)
	DelphiCmd.AddCommand(update.UpdateCmd)
	DelphiCmd.AddCommand(sync.SyncCmd)

	// TODO: Example persistent flags: DelphiCmd.PersistentFlags().String("config", "", "Path to the Delphi configuration file")
}

// log is a package-level variable for the Zap logger.

func init() {
	// Initialize the shared logger for the entire deploy package

}
