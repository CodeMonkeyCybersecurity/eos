// cmd/delphi/inspect/inspect.go

package inspect

import (
	"github.com/spf13/cobra"
)

var InspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect Delphi (Wazuh) data",
	Long:  "Run inspection commands against Wazuh to retrieve agent status, config, upgrades, and more.",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("'eos delphi inspect' was called without a subcommand")
	},
}

func init() {
	InspectCmd.AddCommand(KeepAliveCmd)
}
