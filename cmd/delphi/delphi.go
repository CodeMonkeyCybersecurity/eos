// cmd/delphi/delphi.go
package delphi

import (
	"github.com/spf13/cobra"
	"eos/cmd/delphi/install"
)

// DelphiCmd is the root command for Delphi-related actions
var DelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Manage Delphi (Wazuh) components",
	Long:  "Commands related to Wazuh and Delphi integrations such as install, remove, inspect.",
}

func init() {
	// Register subcommands
	DelphiCmd.AddCommand(install.InstallCmd)
}
