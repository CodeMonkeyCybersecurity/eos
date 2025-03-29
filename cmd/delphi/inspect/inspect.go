// cmd/delphi/inspect/inspect.go

package inspect

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

var log = logger.L()

var InspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect Delphi (Wazuh) data",
	Long: `The 'inspect' command provides diagnostic and introspection tools 
for your Delphi (Wazuh) instance.

Use this command to view configuration details, authentication info, 
user permissions, versioning data, keepalive status, and other useful insights.

Subcommands are required to specify which type of information to inspect.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("'eos delphi inspect' was called without a subcommand")

		fmt.Println("❌ Missing subcommand.")
		fmt.Println("ℹ️  Run `eos delphi inspect --help` to see available options.")
	},
}

func init() {
	InspectCmd.AddCommand(KeepAliveCmd)
	InspectCmd.AddCommand(InspectAPICmd)
	InspectCmd.AddCommand(InspectCredentialsCmd)
}
