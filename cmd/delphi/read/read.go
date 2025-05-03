// cmd/delphi/read/read.go

package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	showSecrets bool
)

var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Inspect Delphi (Wazuh) data",
	Long: `The 'inspect' command provides diagnostic and introspection tools for your Delphi (Wazuh) instance.

Use this command to view configuration details, authentication info, 
user permissions, versioning data, keepalive status, and other useful insights.

Subcommands are required to specify which type of information to inspect.`,
	Aliases: []string{"read", "get"},
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		zap.L().Info("'eos delphi inspect' was called without a subcommand")

		fmt.Println("❌ Missing subcommand.")
		fmt.Println("ℹ️  Run `eos delphi inspect --help` to see available options.")
		_ = cmd.Help() // Print built-in help with formatting
		return nil
	}),
}
