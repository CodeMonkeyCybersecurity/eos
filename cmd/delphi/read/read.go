// cmd/delphi/read/read.go

package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("'eos delphi inspect' was called without a subcommand")

		fmt.Println("❌ Missing subcommand.")
		fmt.Println("ℹ️  Run `eos delphi inspect --help` to see available options.")
		_ = cmd.Help() // Print built-in help with formatting
		return nil
	}),
}
