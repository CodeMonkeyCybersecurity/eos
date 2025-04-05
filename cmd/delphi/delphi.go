// cmd/delphi/delphi.go

package delphi

import (
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/configure"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/deploy"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/inspect"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/update"

	"github.com/spf13/cobra"
)

// DelphiCmd groups commands related to managing Delphi (Wazuh) components.
var DelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Manage Delphi (Wazuh) components",
	Long:  "Commands related to Wazuh and Delphi integrations such as install, remove, and inspect.",
	// Optionally, you can define a Run function to display help if no subcommand is provided.
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	// Register subcommands
	DelphiCmd.AddCommand(create.CreateCmd)
	DelphiCmd.AddCommand(deploy.DeployCmd)
	DelphiCmd.AddCommand(inspect.InspectCmd)
	DelphiCmd.AddCommand(delete.DeleteCmd)
	DelphiCmd.AddCommand(update.UpdateCmd)
	DelphiCmd.AddCommand(configure.ConfigureCmd)

	// TODO: Example persistent flags: DelphiCmd.PersistentFlags().String("config", "", "Path to the Delphi configuration file")
}
